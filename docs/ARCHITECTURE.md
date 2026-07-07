# Architecture

How `symbolon` works.

See also:

- [`PROTOCOLS.md`](PROTOCOLS.md): wire formats, file schemas,
  log event catalog.
- [`PROVIDER_CONTRACT.md`](PROVIDER_CONTRACT.md): RFC-2119
  contract for providers.
- [`INSTALL.md`](INSTALL.md): deploy the daemon.
- [`OPERATIONS.md`](OPERATIONS.md): operate the daemon.
- [`providers/`](providers/): per-provider setup and guarantees.
- [`../AGENTS.md`](../AGENTS.md): design and style notes for
  contributors and LLM agents.

## At a glance

```
┌──────────────────────────┐                ┌───────────────────────────┐
│   client                 │                │       broker host         │
│ (VM or container)        │                │                           │
│                          │                │  symbolon :9418           │
│  git → git-credential-   │  Noise NKpsk2  │  (TCP listen,             │
│        symbolon          ├──────────────► │   PSK identity →          │
│           │              │                │   per-client lookup)      │
│           │              │ ◄── git creds ─┤                           │
└──────────────────────────┘                │       │ HTTPS             │
                                            │       ▼                   │
                                            │  provider API             │
                                            │  mints per-repo token     │
                                            └───────────────────────────┘
```

Per request: `git` invokes the bundled `git-credential-symbolon`
helper on the client. The helper opens a TCP connection to the
broker and runs the initiator side of a Noise NKpsk2 handshake:
its identity travels encrypted inside the first handshake message
(encrypted to the broker's pinned static public key), and the
per-client PSK both sides hold is mixed into message 2. Handshake
completion proves the client's identity. The
daemon then dispatches the credential request to the configured
provider, mints a single-repository token, and writes it back
through the authenticated Noise transport. The token's lifetime
and exact scope are provider-determined (see
[`providers/`](providers/)). Nothing is persisted on either side.

## Trust boundary

The broker host is the trust boundary. It holds the
**provider private key** (e.g. a GitHub App's PEM), the
**per-client PSKs**, and the **broker static X25519 key**. Clients
hold a single PSK, the broker's static *public* key, and a stable
identity name; nothing else.

A client compromise is bounded by:

- Per-mint scope: tokens are scoped to one repository, with the
  minimum permission set the provider accepts for `git push` /
  `git clone`. Never broader.
- Per-provider token TTL: the lifetime of an issued token (e.g.
  ≤1 hour on GitHub). Outstanding tokens are not revocable from
  the broker. See [`providers/<name>.md`](providers/) for the
  provider-specific hard-cutoff procedure.
- Per-client PSK isolation: a compromised PSK lets the attacker
  use *that* client's identity. Other clients are unaffected.

A client compromise does NOT buy:

- Access to repos the provider identity hasn't been granted.
- Anything outside the per-mint permission set the broker
  requests from the provider (provider-specific; see
  [`providers/<name>.md`](providers/) for the exact set).
- Other clients' traffic. Per-client unique PSKs isolate them.
- Persistent access. No long-lived tokens, and the provider's
  private key never leaves the broker host.

## Identity model

Identity is the **PSK identity surfaced by the Noise handshake**,
not the TCP source address. The flow:

1. Client opens the `Noise_NKpsk2_25519_ChaChaPoly_BLAKE2s`
   handshake, carrying an identity TLV (4-byte magic `SBLN` plus
   version, length, and identity bytes) as the *encrypted* payload
   of message 1 — encrypted to the broker's static public key,
   which the client pins in its key file. The identity is a stable
   name (e.g. `dev-vm-1`); the wire format is in
   [`PROTOCOLS.md` § Identity TLV](PROTOCOLS.md).
2. Broker decrypts message 1 with its static private key and looks
   up the PSK for the identity in its in-memory store. Unknown
   identities get a random substitute PSK rather than an early
   drop, so enrollment status is not observable from the wire
   (anti-enumeration; see PROTOCOLS.md).
3. The PSK is mixed into handshake message 2 (`psk2`); the
   handshake only completes if both sides hold the same PSK.
4. Handshake completion **is** the identity proof. The `evt=accept`
   log field `psk_identity` reflects the authenticated value, not
   the client-claimed string.

The TCP source address is logged as `peer` for audit only, never
used for identity decisions. This makes the daemon DHCP-friendly:
client IPs may change freely.

The identity travels only inside the encrypted message-1 payload,
so a passive observer (or any active attacker without the broker's
static private key) learns neither **which** identity connects nor
whether it is enrolled. Source IP and timing still identify
clients to an on-path observer; the protocol-level guarantees and
accepted residuals are enumerated in
[`PROTOCOLS.md` § Identity confidentiality](PROTOCOLS.md#identity-confidentiality-protocol-level-guarantees).

## Permission model and per-mint scoping

Two architectural invariants:

- **Per-mint scoping is mandatory.** Every mint requests exactly
  one repository plus the minimum permission set the provider
  accepts for `git push` / `git clone`. Never broader. The
  on-the-wire encoding (`repository_ids: [<one>]` on GitHub, or
  the equivalent for other providers) is in
  [`providers/<name>.md`](providers/).
- **Provider permissions are immutable per provider.** The broker
  requests one fixed permission set per provider, hard-coded in
  `src/providers/<name>.rs`. Operators do not configure it.
  Widening the set requires a code change plus an explicit
  AGENTS.md instruction.

This keeps the per-mint blast radius small and structurally
non-configurable.

## Provider dispatch

The `host=` field in a git-credential request is matched
**byte-exact** (case-sensitive, no normalisation, no suffix
matching, no default) against the `host` values in configured
`[provider.X]` sections of `config.toml`. Unknown host returns
`evt=mint_denied reason=unknown_host`. See
[`PROTOCOLS.md` § Host dispatch](PROTOCOLS.md#host-dispatch-byte-exact).

## Supervisor handoff

The daemon does **not** bind its listening sockets — both the
inbound TCP wire socket and the admin Unix socket are obtained
from a supervisor via the systemd-defined `LISTEN_FDS` env
protocol. Two supported deployments:

- **systemd:** a `.socket` unit with `Sockets=symbolon.socket` on
  the `.service`. systemd binds the sockets, sets `SocketMode=0600`
  for the UDS, and hands the fds to the daemon at start.
- **non-systemd (OpenRC, runit, s6, …):** the
  [`systemfd`](https://github.com/mitsuhiko/systemfd) wrapper:
  `systemfd --no-pid -s tcp::… -s unix::… -- symbolon daemon`.
  systemfd binds, sets `LISTEN_FDS`/`LISTEN_PID`, and execs.

Slot ordering is fixed: slot 0 = TCP wire, slot 1 = admin UDS.
A plain `symbolon daemon` invocation with no supervisor exits
immediately with `DaemonError::EnvFdTake`. The supervisor owns
the socket inode lifecycle (perms, unlink); the daemon never
binds, chmods, or unlinks. See [`INSTALL.md`](INSTALL.md) §§ 3.9–3.11
for the unit / init-script recipes.

## State and atomic writes

State lives in two files on the broker:

- `/var/lib/symbolon/clients.json`: the enrolled-clients table.
- `/var/lib/symbolon/psks`: the per-client PSKs
  (`identity:hex` per line).

Both are owned and atomically rewritten by the daemon (tempfile +
fsync + rename + fsync-parent). The daemon is the **sole writer**.
CLI commands talk to the daemon via the admin Unix socket; the
daemon serialises them. No file locks; no other process is
expected to touch these files at runtime.

Wire and file schemas in
[`PROTOCOLS.md` § File formats](PROTOCOLS.md#file-formats).

## Sandbox model

At startup, after sockets are inherited via `LISTEN_FDS` (the daemon
does not bind — see [Supervisor handoff](#supervisor-handoff)) and the
provider private key is loaded, the broker applies Landlock at ABI 6
to itself:

- **FS allowlist.** Only the state directory
  (`/var/lib/symbolon/`, read-write), `/dev/urandom`, the CA
  bundle, and the nameservice files libc's `getaddrinfo` reads
  are reachable. The provider-key directory stays out of the
  allowlist, so a post-compromise process inside the daemon
  cannot re-open the key (the daemon already loaded it).
- **Outbound TCP-connect** restricted to port 443.
- **Abstract Unix socket scope.** Denies attaching to or creating
  abstract namespace sockets.
- **`Scope::Signal` (Linux 6.12+).** Denies sending signals to
  processes outside the broker's Landlock domain.

Levels: `[security] sandbox = required | best_effort (default) | off`.
On `best_effort`, missing kernel features degrade with a `warn`
log; on `required`, missing features abort startup. The full
ruleset (paths, scopes, edge cases) lives in
[`src/sandbox.rs`](../src/sandbox.rs).

A complementary anti-swap defence is `mlockall(MCL_CURRENT |
MCL_FUTURE)` at startup (see `src/mlock.rs`). The primary
anti-swap defence is operator-side: disable swap on the broker
host. Both contribute to AGENTS.md invariant #14 ("Secrets stay
off disk").

## Transport layer

The Noise NKpsk2 protocol lifecycle (msg1 with encrypted identity
TLV → PSK selection → msg2 → encrypted request/response) is a
sans-IO state machine:
`transport::Responder` for the daemon side, `transport::Initiator`
for the client. Each emits `Step` values telling the I/O driver
what to do next — read N bytes, write these bytes, look up a PSK
for this identity, process this plaintext request. The driver
does only I/O; the machine owns all state.

Same machine drives the async compio daemon (`src/daemon.rs`) and
the sync std::net client binary (`src/bin/git_credential_symbolon.rs`).
Protocol changes happen in one place.

## Concurrency model

Single-threaded [compio](https://docs.rs/compio) runtime.
CPU-bound work (today: JWT signing) runs on a dedicated OS
thread via `crate::cpu_worker::CpuWorker`.

Rationale and developer-facing detail (`CpuWorker` vs
`spawn_blocking`, why no Tokio) lives in
[`../AGENTS.md` § Concurrency notes](../AGENTS.md).
