# Architecture

How `symbolon` works as a system. This is the explanation doc —
read it once to build a mental model. For lookup-while-working
material, see the references below.

| Doc | Mode |
|---|---|
| [`PROTOCOLS.md`](PROTOCOLS.md) | Reference — wire formats, file schemas, logging schema |
| [`PROVIDER_CONTRACT.md`](PROVIDER_CONTRACT.md) | Reference — RFC-2119 contract for providers |
| [`INSTALL.md`](INSTALL.md) | How-to — deploy the daemon |
| [`OPERATIONS.md`](OPERATIONS.md) | How-to — operate the daemon |
| [`providers/`](providers/) | Per-provider setup, guarantees, contracts |
| [`../AGENTS.md`](../AGENTS.md) | Agent-facing source-of-truth for design + style |

## At a glance

```
┌──────────────────────────┐                ┌───────────────────────────┐
│   client                 │                │       broker host         │
│ (VM or container)        │                │                           │
│                          │                │  symbolon :9418           │
│  git → git-credential-   │  Noise NNpsk0  │  (TCP listen,             │
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
broker, sends a small cleartext identity prelude, and runs the
initiator side of a Noise NNpsk0 handshake against the PSK both
sides hold. Handshake completion proves the client's identity. The
daemon then dispatches the credential request to the configured
provider, mints a single-repository token, and writes it back
through the authenticated Noise transport. The token's lifetime
and exact scope are provider-determined (see
[`providers/`](providers/)). Nothing is persisted on either side.

## Trust boundary

The broker host is the trust boundary. It holds the
**provider private key** (e.g. a GitHub App's PEM) and the
**per-client PSKs**. Clients hold a single PSK and a stable
identity name; nothing else.

A client compromise is bounded by:

- Per-mint scope: tokens are scoped to one repository, with the
  minimum permission set the provider accepts for `git push` /
  `git clone`. Never broader.
- Per-provider token TTL: the lifetime of an issued token (e.g.
  ≤1 hour on GitHub). Outstanding tokens are not revocable from
  the broker — see [`providers/<name>.md`](providers/) for the
  provider-specific hard-cutoff procedure.
- Per-client PSK isolation: a compromised PSK lets the attacker
  use *that* client's identity. Other clients are unaffected.

A client compromise does NOT buy:

- Access to repos the provider identity hasn't been granted.
- Anything outside the per-mint permission set the broker
  requests from the provider (provider-specific; see
  [`providers/<name>.md`](providers/) for the exact set).
- Other clients' traffic — per-client unique PSKs.
- Persistent access — no long-lived tokens; the provider's
  private key never leaves the broker host.

## Identity model

Identity is the **PSK identity surfaced by the Noise handshake**,
not the TCP source address. The flow:

1. Client sends a cleartext identity prelude (4-byte magic `SBLN`
   + version + length + identity bytes). The identity is a stable
   name (e.g. `dev-vm-1`); the wire format is in
   [`PROTOCOLS.md` § Identity prelude](PROTOCOLS.md).
2. Broker looks up the PSK for that identity in its in-memory
   store.
3. Both sides run `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`. The
   handshake only completes if both sides hold the same PSK.
4. Handshake completion **is** the identity proof. The `evt=accept`
   log field `psk_identity` reflects the authenticated value, not
   the client-claimed string.

The TCP source address is logged as `peer` for audit only, never
used for identity decisions. This makes the daemon DHCP-friendly:
client IPs may change freely.

The cleartext prelude leaks **which** identity is being used to
a passive observer, but not whether they hold the PSK. Identity
names are not secrets.

## Permission model and per-mint scoping

Two architectural invariants:

- **Per-mint scoping is mandatory.** Every mint requests exactly
  one repository plus the minimum permission set the provider
  accepts for `git push` / `git clone`. Never broader. The exact
  on-the-wire encoding (`repository_ids: [<one>]` on GitHub, or
  the equivalent for other providers) is in
  [`providers/<name>.md`](providers/).
- **Provider permissions are immutable per provider.** The broker
  requests one fixed permission set per provider, hard-coded in
  `src/providers/<name>.rs`. Operators do not configure it.
  Widening the set requires a code change plus an explicit
  AGENTS.md instruction.

This makes the per-mint blast radius small and structurally
non-configurable.

## Provider dispatch

The `host=` field in a git-credential request is matched
**byte-exact** (case-sensitive, no normalisation, no suffix
matching, no default) against the `host` values in configured
`[provider.X]` sections of `config.toml`. Unknown host →
`evt=mint_denied reason=unknown_host`. See
[`PROTOCOLS.md` § Host dispatch](PROTOCOLS.md#host-dispatch-byte-exact).

## State and atomic writes

State lives in two files on the broker:

- `/var/lib/symbolon/clients.json` — the enrolled-clients table.
- `/var/lib/symbolon/psks` — the per-client PSKs (`identity:hex` per line).

Both are owned and atomically rewritten by the daemon (tempfile +
fsync + rename + fsync-parent). The daemon is the **sole writer** —
CLI commands talk to the daemon via the admin Unix socket; the
daemon serialises them. No file locks; no other process is
expected to touch these files at runtime.

Wire / file schemas in
[`PROTOCOLS.md` § File formats](PROTOCOLS.md#file-formats).

## Sandbox model

At startup, after sockets are bound and the provider private key
is loaded, the broker applies Landlock at ABI 6 to itself:

- **FS allowlist** — only the state directory (`/var/lib/symbolon/`,
  read-write), `/dev/urandom`, the CA bundle, and the nameservice
  files libc's `getaddrinfo` reads are reachable. The
  provider-key directory is deliberately *not* in the allowlist,
  so a post-compromise process inside the daemon cannot re-open
  the key (it was already loaded).
- **Outbound TCP-connect** restricted to port 443.
- **Abstract Unix socket scope** — denies attaching to or creating
  abstract namespace sockets.
- **`Scope::Signal` (Linux 6.12+)** — denies sending signals to
  processes outside the broker's Landlock domain.

Levels: `[security] sandbox = required | best_effort (default) | off`.
On `best_effort`, missing kernel features degrade with a `warn`
log; on `required`, missing features abort startup. The full
ruleset (paths, scopes, edge cases) is in
[`src/sandbox.rs`](../src/sandbox.rs).

A complementary anti-swap defence is `mlockall(MCL_CURRENT |
MCL_FUTURE)` at startup (see `src/mlock.rs`). The primary
anti-swap defence is operator-side: disable swap on the broker
host. Both contribute to AGENTS.md invariant #14 ("Secrets stay
off disk").

## Concurrency model

The broker runs on a single-threaded [compio](https://docs.rs/compio)
runtime (thread-per-core with one core today). Implications:

- Tasks cooperatively yield at `.await` only. A long CPU-bound
  section without an `.await` blocks every other task — including
  the accept loop. CPU work goes through
  `crate::cpu_worker::CpuWorker`, a dedicated OS thread (used
  today for JWT signing).
- Shared mutable state uses `Rc<RefCell<T>>` (no Send/Sync
  needed). RefCell borrows MUST drop before any `.await` or the
  daemon panics at runtime. The check is manual — see
  AGENTS.md "Diagnostic discipline" and the Axis 1a notes in
  prior code reviews.
- The admin-socket loop and the per-connection accept loop are
  separate compio tasks. Per-connection handlers are bounded by
  a 5-second timeout (slow-loris defence) and drained on
  shutdown with a 5-second deadline.

Developer-facing detail and rationale (when to use `CpuWorker`
vs `spawn_blocking`, why no Tokio) lives in
[`../AGENTS.md` § Concurrency notes](../AGENTS.md).
