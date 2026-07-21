# Protocols & file formats

Wire formats and on-disk schemas for `symbolon`. Read
[`ARCHITECTURE.md`](ARCHITECTURE.md) first if you want the
"how does this thing work" pass; this file is for lookup.

See also:

- [`PROVIDER_CONTRACT.md`](PROVIDER_CONTRACT.md): RFC-2119
  contract for providers.
- [`INSTALL.md`](INSTALL.md): deploy.
- [`OPERATIONS.md`](OPERATIONS.md): operate.
- [`providers/`](providers/): per-provider setup, guarantees,
  outbound API.
- [`REFERENCES.md`](REFERENCES.md): external URLs.
- [`../AGENTS.md`](../AGENTS.md): design and style notes.

## File formats

### `/etc/symbolon/config.toml`: operator-authored

```toml
[listen]
# Informational — the daemon does NOT bind sockets itself; the
# supervisor (systemd `.socket` unit or `systemfd` wrapper) hands
# pre-bound fds via the `LISTEN_FDS` env protocol. Slot 0 = TCP
# wire, slot 1 = admin UDS. See INSTALL.md §§3.9–3.11.
bind = "0.0.0.0:9418"
# Symbolon-owned PSK store. Mutated atomically on enroll/revoke.
psk_file = "/var/lib/symbolon/psks"
# Broker static X25519 private key: 64 hex chars on one line.
# Operator-generated (`openssl rand -hex 32`), root:symbolon 0440. Read once
# at startup, before the sandbox closes. Rotating it invalidates
# every client's pinned public key — see OPERATIONS.md.
static_key_file = "/etc/symbolon/broker.key"

[admin]
# Path the CLI connects to. The supervisor owns the inode — bind,
# mode (systemd SocketMode= / systemfd umask), unlink; the daemon
# never touches it.
socket_path = "/run/symbolon/admin.sock"

[clients]
file = "/var/lib/symbolon/clients.json"

[logging]
level = "info"   # trace | debug | info | warn | error

[security]
# Sandbox enforcement policy. Controls Landlock at ABI 6 (FS allowlist
# + outbound TCP-connect to port 443 + abstract-UDS scope +
# Scope::Signal denying cross-domain signal-sending; Linux 6.12+).
#
#   required    – refuse to start if the kernel can't enforce ABI 6.
#   best_effort – default. Apply what the kernel supports; degrade and
#                 log a `sandbox_applied` warn event if not fully
#                 enforced.
#   off         – skip sandboxing entirely (tests, debugging).
sandbox = "best_effort"
# Extra read-only dirs to grant landlock access on at startup. The
# default ruleset already includes /etc/ssl/certs; RHEL/Fedora hosts
# typically also need /etc/pki/tls/certs for OpenSSL CA roots.
extra_read_dirs = []
# mlockall(MCL_CURRENT|MCL_FUTURE) policy at startup.
# Belt-and-suspenders against secret exfiltration via swap; the
# primary defence is disabling swap on the broker host (see
# docs/INSTALL.md).
#
#   required    – call mlockall; exit 1 on failure (e.g. RLIMIT_MEMLOCK too small).
#   best_effort – default. Try; on failure log `evt=mlock status=skipped` and continue.
#   off         – skip the syscall.
#
# Requires `LimitMEMLOCK=infinity` in the systemd unit (or
# CAP_IPC_LOCK) for the syscall to succeed under a non-root user.
mlock = "best_effort"

[runtime]
# Optional pidfile. When set, the daemon writes its PID here once
# it's ready to serve. Required for OpenRC's `command_background=yes`
# + `pidfile=...` convention. Leave unset under systemd;
# `Type=notify` + READY=1 covers readiness without a pidfile, and
# modern systemd man pages discourage pidfiles when notify is
# available.
#
# The parent directory of this path is added to the sandbox
# write-allowlist automatically.
pidfile = "/run/symbolon/symbolon.pid"

# Per-provider section. Field reference in per-provider docs
# under docs/providers/. Example for GitHub:
[provider.github]
host = "github.com"
api_base = "https://api.github.com"
client_id = "Iv23liABCDEFGHIJklmn"
installation_id = 789012
selfcheck_timeout = "5s"
# Signing backend — REQUIRED, no default. The daemon never holds the
# App private key in its own address space; both backends move it out.
#   "file" — a sandboxed subprocess owns the PEM (below).
#   "tpm"  — an RSA key in a vTPM ([provider.github.tpm] below).
app_key_backend = "file"

# app_key_backend = "file" ⇒ set private_key_path (and no [...tpm]).
# The PEM is read only by the signing agent subprocess, never the
# daemon.
private_key_path = "/etc/symbolon/github-app.pem"

# app_key_backend = "tpm" ⇒ set [provider.github.tpm] (and NO
# private_key_path). The device is opened once pre-sandbox.
# [provider.github.tpm]
# device = "/dev/tpmrm0"          # default; the kernel resource-mgr node
# persistent_handle = 0x81010001  # the pre-provisioned RSA-2048 key
```

Unknown top-level keys are rejected by `serde` deserialization
(`#[serde(deny_unknown_fields)]` on every struct). The `[security]`
section is optional and defaults to `sandbox = "best_effort"` with
no extra read dirs. `app_key_backend` and its matching sub-config are
cross-validated at parse time: `file` requires `private_key_path` and
forbids `[provider.github.tpm]`; `tpm` requires the reverse. A
mismatch fails fast at startup.

The broker static key is read once at startup, **before** the
sandbox is applied; with `app_key_backend = "tpm"` the TPM device is
opened at the same point, and with `"file"` the signing agent is
`execve`d at the same point (afterwards the sandbox denies both). The
default sandbox ruleset deliberately omits `/etc/symbolon/` and never
grants the TPM device path, so a post-compromise process inside the
daemon cannot re-open the broker key, the App key, or the TPM. Keep
key files under `/etc/symbolon/` (or any dir outside
`/var/lib/symbolon/`); do not place them in the directory granted
write access for atomic state-file writes. **With the `file` backend
the daemon never opens `private_key_path` at all** — only the agent
subprocess does.

### `/var/lib/symbolon/clients.json`: machine-authored

```json
{
  "clients": [
    {
      "name": "dev-vm-1",
      "providers": ["github"],
      "enrolled_at": "2026-05-26T12:34:56Z",
      "note": null
    }
  ]
}
```

`#[serde(deny_unknown_fields)]` is set on the parser, so any
extra top-level key (or extra field on a client entry) is a hard
parse failure — schema drift surfaces immediately instead of
silently dropping data. The `providers` array allows
multi-provider enrolment per client.

### `/var/lib/symbolon/psks`: machine-authored

Symbolon-owned PSK store. One identity per line:

```
client-name:hex-encoded-32-byte-key
```

The daemon parses this file once at startup and rewrites it
atomically on every `enroll` / `revoke`. Owner is the `symbolon`
user, mode `0600`. There is no in-process hot-reload — config
changes require a restart.

### `/etc/symbolon/broker.key`: operator-authored

The broker's static X25519 private key: 64 lowercase hex chars on
one line (surrounding whitespace tolerated), `root:symbolon`,
mode `0440` (root-owned so the daemon's uid cannot replace or
re-chmod it — see INSTALL.md §3.2). Generate with:

```
umask 277
openssl rand -hex 32 > /etc/symbolon/broker.key
chown root:symbolon /etc/symbolon/broker.key
chmod 0440          /etc/symbolon/broker.key
```

Any 32-byte value is a valid X25519 private key (RFC 7748 clamping
happens inside the scalar multiplication), so no dedicated keygen
tool exists. The daemon reads the file once at startup and derives
the public key; retrieve it with `symbolon pubkey` (admin socket)
or from the `startup` log event's `broker_public_key` field. The
daemon never writes this file, and there is no rotation machinery:
replacing the key is a full client re-enrollment (see
OPERATIONS.md).

## Atomic writes

`clients.json` and `psks` are mutated only by the daemon (the CLI
talks to the daemon via the admin Unix socket; see AGENTS.md
invariant #10). The daemon writes both files atomically:

1. Write to `<path>.tmp.<random>` in the same directory.
2. `fsync` the tempfile.
3. `rename(2)` over the target path.
4. `fsync` the parent directory.

A crash between steps leaves a tempfile, never a partial target. On
startup the daemon ignores stale `.tmp.*` files; operators can delete
them. No file locks are used. The daemon's single-writer invariant
makes them unnecessary.

## Wire formats

### Noise NKpsk2 handshake (binary)

Pattern: `Noise_NKpsk2_25519_ChaChaPoly_BLAKE2s` (per
[Noise spec rev 34](https://noiseprotocol.org/noise_rev34.html)),
driven by the [`snow`](https://github.com/mcginty/snow) crate.
`NK`: the client knows the broker's static X25519 public key
(pinned in its key file) and encrypts to it from the first
message; `psk2`: the per-client PSK is mixed at the end of
message 2.

Both sides exchange exactly two framed messages:

```
1. initiator → responder: e, es    payload = identity TLV (encrypted)
2. responder → initiator: e, ee, psk
```

Per-message framing on the TCP stream (handshake AND transport
messages):

```
+-----------+--------------------+
| len (u16) | message body bytes |
+-----------+--------------------+
     2              len (≤ 65535)
```

The broker decrypts message 1 with only its static key, parses the
identity TLV out of the payload, selects that identity's PSK, and
injects it (`set_psk`) before producing message 2 — that ordering
is why the pattern is `psk2` and not `psk0`: a PSK mixed before
message 1 could not depend on an identity carried inside it.

Handshake completion authenticates the connection (PSK proof on both
sides) and yields an AEAD transport state. Forward secrecy is
provided by the ephemeral X25519 keys; replay protection is provided
by the per-message AEAD nonce counter.

On handshake failure (tag check, oversized frame, EOF mid-message),
the daemon logs `evt=handshake_failed reason=...` and closes the
connection.

### Identity TLV (encrypted payload of handshake message 1)

```
+--------+---+---+----------------+
| "SBLN" | V | L | identity bytes |
+--------+---+---+----------------+
   4      1   1       L (1..=64)
```

- 4 bytes magic: ASCII `"SBLN"`. Daemon rejects with
  `evt=identity_invalid reason=bad_magic` otherwise.
- 1 byte version: `0x02`. Version `0x01` was the retired cleartext
  prelude of the NNpsk0 wire protocol; the layout is unchanged but
  the bump keeps a mixed-era client loudly rejected.
- 1 byte identity length `L`. Must be 1..=64.
- `L` bytes identity. Charset enforced to `[A-Za-z0-9._-]+` (same rule
  as git-credential values; CR/LF/NUL rejected; AGENTS.md invariant
  #12 in spirit).

The message-1 payload must be exactly one TLV — trailing bytes are
rejected (`reason=trailing_bytes`).

### Identity confidentiality (protocol-level guarantees)

The client identity travels only inside the encrypted message-1
payload (encryption key derived from `es`: client ephemeral x
broker static). Consequences, in decreasing order of comfort:

- **Confidentiality bound.** Identity confidentiality holds against
  passive observers and against any active attacker not holding the
  broker's static *private* key. Compromise of one client does not
  help decrypt other clients' identities: clients hold only the
  public key.
- **Replay bound.** Message 1 is replayable (there is no timestamp
  or challenge in it), but a replay cannot complete the handshake:
  message 2 onward requires the identity's PSK, which the replayer
  does not hold. A replay costs the broker one PSK lookup and one
  message-2 write.
- **Accepted residual: recorded traffic.** If the broker static
  private key ever leaks, identities in previously recorded traffic
  become decryptable retroactively and indefinitely. Accepted
  because an observer positioned to record that traffic already
  collects source-IP metadata of equivalent identifying value.
- **Metadata is not hidden.** Source IP, connection timing, and
  message sizes still identify clients to an on-path observer
  regardless of payload encryption.

### Anti-enumeration (unauthorized identities)

On an identity with no PSK entry, the broker MUST NOT fail early.
It substitutes a freshly random 32-byte PSK, proceeds normally
through message 2, and lets the session die at the first
transport-frame decrypt — byte-shape and connection behaviour
identical to an enrolled identity presenting a wrong PSK. An
attacker probing identities therefore cannot distinguish "enrolled"
from "unknown" by observing whether or when the connection fails.
The attempt is logged (`evt=identity_unknown`, rate-limited; see
the logging schema). If the OS RNG is unavailable the connection
is dropped instead (`reason=rng_unavailable`) — a predictable
substitute PSK would be worse than the timing leak.

### git-credential protocol (inside the Noise transport)

Reference: <https://git-scm.com/docs/gitcredentials>.

After the handshake, application-layer messages are encrypted-and-
framed Noise transport messages. The first inbound message decrypts
to a git-credential request block; the daemon's response is
encrypted and framed the same way before being written back.

**Request:**

```
capability[]=authtype           # optional, sent by git 2.46+
protocol=https
host=github.com
path=octocat/Spoon-Knife

```

(`key=value` lines terminated by an empty line. `capability[]` is
parsed but only the `authtype` value is meaningful to us; other
capabilities or unknown keys are silently ignored per
`gitcredentials(7)`.)

#### Response shape — capability negotiation

The daemon emits one of two response shapes depending on whether
the client declared `capability[]=authtype` in the request.

**Modern shape** (git 2.46+ after capability negotiation):

```
capability[]=authtype
authtype=Bearer
credential=<token>
ephemeral=true
password_expiry_utc=<epoch>

```

Git constructs `Authorization: Bearer <token>` from these fields
(per `git/http.c::http_append_auth_header`) and sends it on every
git-HTTP request. `ephemeral=true` tells git's credential cache
NOT to persist the credential — load-bearing for our short-TTL
installation tokens.

**Legacy shape** (git ≤ 2.45 or any client that didn't declare
`authtype`):

```
username=<provider-specified-username>
password=<token>
password_expiry_utc=<epoch>

```

#### `capability` action

The client helper `git-credential-symbolon` advertises its own
capabilities when invoked as
`git credential capability`. The output is:

```
version 0
capability authtype
```

Per `git-credential.adoc` § CAPABILITY INPUT/OUTPUT FORMAT, this
tells git the helper understands the `authtype` capability and
will accept the modern response shape on subsequent `get` calls.

#### Security: CR/LF rejection (mandatory)

The parser MUST reject any field value containing a 0x0D (CR) or
0x0A (LF) byte inside a value. Bare LF is valid only as a line
terminator. This defends against the **Clone2Leak** class of
vulnerabilities (CVE-2024-52006 in upstream git, CVE-2024-50338 in
Git Credential Manager, CVE-2025-23040 in GitHub Desktop) where a
crafted URL injects extra protocol lines, causing a helper to fetch
credentials for one host and send them to another. See
[GitHub's announcement](https://github.blog/open-source/git/git-security-vulnerabilities-announced-5/)
for background.

On detection: log `evt=mint_denied reason=malformed_request`, close
the connection without responding.

#### `path` handling

Accept `path=owner/repo` or `path=owner/repo.git`. Strip the `.git`
suffix before resolution. If `path` is absent (older git clients
may omit it), respond with `evt=mint_denied reason=malformed_request`.

#### Host dispatch (byte-exact)

The `host` field is matched **byte-exact** (case-sensitive,
no normalization, no suffix matching, no default) against the
`host` values in configured `[provider.X]` sections. Unknown host →
`evt=mint_denied reason=unknown_host`.

### Admin socket protocol

Line-delimited JSON over Unix-domain stream at
`admin.socket_path`. One request per connection. The daemon writes
one response and closes.

**Request:** `{"op":"<status|list|pubkey|enroll|revoke|mint|selfcheck>",
…op-specific fields}\n`

**Response on success:** `{"ok":true, …op-specific fields}\n`

**Response on failure:** `{"ok":false, "error":"<message>"}\n`

No `code` tag — operators key on the human-readable `error`
message (or follow the matching log line via `req_id`); the wire
isn't a programmatic-discrimination surface.

Op fields (request → response):

| op | request fields | response fields |
|---|---|---|
| `status` | — | `uptime_sec`, `providers`, `client_count` |
| `list` | — | `clients` (array of `{name, providers, enrolled_at, note}`) |
| `pubkey` | — | `broker_public_key` (64 hex chars — the value a client pins in its key file) |
| `enroll` | `provider`, `client`, `psk` (32-byte array; client-generated), `note` (nullable) | — (daemon response is bare `{"ok":true}`; CLI then prints `{"ok":true,"psk_hex":"…"}` synthesised locally so the PSK can be piped to the client host) |
| `revoke` | `provider`, `client` | — |
| `mint` | `provider`, `client`, `path` | `username`, `password`, `expires_at_unix`, `out_req_id`, `provider_req_id` |
| `selfcheck` | `provider` | `clock_skew_sec`, `out_req_id`, `provider_req_id`, `details` |

The `selfcheck` response's `details` carries provider-specific
diagnostic fields (e.g. for GitHub: `client_id`,
`installation_id`, `api_base`) — shape documented in
`docs/providers/<name>.md`.

`provider_req_id` is the provider's own upstream correlation id
(e.g. GitHub's `X-GitHub-Request-Id`), if any.

The daemon serialises concurrent enroll/revoke through a
single-permit async mutex (`SharedState.mutation_lock`) so on-disk
writes can't race across `atomic_write` `.await`s (AGENTS.md
invariant #10). Reads (`status`/`list`/`mint`/`selfcheck`) bypass
the lock — they don't mutate.

CR or embedded LF inside any string field is rejected (same
Clone2Leak-class defence applied to the admin path).

### Provider outbound

Per-provider outbound HTTPS contracts (endpoints, auth, headers,
body shape, retry / cache behaviour) live in
[providers/](providers/). One file per supported provider.
Currently:

- **GitHub** → [providers/github.md § Outbound API contract](providers/github.md#outbound-api-contract).

## Daemon lifecycle

### Startup

1. Parse `config.toml` (cross-validating `app_key_backend` against
   its sub-config). Fail fast on schema errors.
2. Load the broker static key (`[listen] static_key_file`) and
   `clients.json` into memory. Fail fast on parse error.
3. **Reclaim the listening sockets from the supervisor** via the
   `LISTEN_FDS` env protocol. Slot 0 = TCP wire, slot 1 = admin
   UDS. Plain `symbolon daemon` invocation with no supervisor
   exits immediately with `DaemonError::EnvFdTake`. The daemon
   never binds, chmods, or unlinks these sockets — that's the
   supervisor's job. See INSTALL.md §§3.9–3.11.
4. **Construct the signing backend.** `tpm` opens the TPM device
   node; `file` `execve`s the key subprocess over a socketpair.
   Both need access the sandbox is about to revoke, so this
   precedes it. The daemon never reads the App PEM itself.
5. Apply sandbox (Landlock at ABI 6). Per `[security] sandbox`:
   `required` aborts on missing kernel features; `best_effort`
   degrades and emits `evt=sandbox_applied` at `warn` lvl; `off`
   skips. After this step the App key dir, the broker static key
   file, and the TPM device path are all unreachable; only the
   small allowlist (state dirs, `/dev/urandom`, `/etc/ssl/certs`,
   nameservice files, TCP-connect to port 443, intra-process
   signals) remains permitted. `execve` is denied.
6. **Start each signing backend's fd-owning actor thread**
   (post-sandbox, so it inherits the ruleset) and run its
   `self_check` — a dead agent / unreachable TPM is fatal here.
7. Run per-provider selfcheck (provider-specific: verifies the
   provider identity claim and reachability; see
   [providers/](providers/)).
8. Enter the accept loop.

### Shutdown

On `SIGTERM` or `SIGINT`:
1. Stop accepting new connections on the listen socket.
2. Drain in-flight handlers with a **5-second deadline**.
3. Close the listener fds (drop on scope exit). The admin Unix
   socket inode is NOT unlinked — the supervisor owns it.
4. Exit 0.

Log `evt=shutdown signal=<sig> inflight_drained=<n> drain_ms=<ms>`.

Any other signal (including SIGHUP, which is unhandled and
defaults to `Term`): kernel terminates the process; no drain.

### Hot reload

There is none. `clients.json` and `psks` are rewritten in-process
on every admin `enroll`/`revoke`; the in-memory tables are the
truth and the file is just their serialisation. `config.toml`
and the provider private key require a restart.

## Logging schema

Structured JSON to stdout (warn/error to stderr), one record per
line. Produced by `tracing-subscriber`'s built-in JSON formatter
with `flatten_event(true)`, so user-added fields appear as
top-level keys.

**Required fields on every record:**

- `timestamp`: RFC 3339 UTC, subsecond precision. Emitted by
  `tracing-subscriber`'s default JSON timer.
- `level`: `TRACE | DEBUG | INFO | WARN | ERROR` (uppercase,
  per the built-in formatter).
- `evt`: event name (closed set, below). User-added field.
- `req_id`: ULID generated at TCP accept, threaded through.
  User-added field.

**Per-event additional fields:**

Every event additionally carries `req_id` when one is in scope,
plus `out_req_id` + `provider_req_id` for provider-call-derived
events (`mint`, `selfcheck`, `mint_denied`, `provider_error`,
`cache_invalidated`). These are not repeated per row.

The closed-set catalog of `evt` values is encoded in
`src/events.rs::EventKind`; adding a new event name requires
extending the enum and adding a row below.

| evt | additional fields |
|---|---|
| `startup` | `providers`, `broker_public_key` (hex; the value clients pin) |
| `shutdown` | `signal`, `inflight_drained`, `drain_ms`, `drain_complete` |
| `accept` | `psk_identity` (decrypted out of handshake msg1), `peer` (TCP source addr, audit-only) |
| `mint` | `provider`, `repo`, `client`, `ttl_sec`, `expires_at_unix`, `provider_ms` |
| `mint_denied` | `provider`, `client`, `repo`, `reason`, `provider_status`; `retry_after_sec` when `provider_status=429` and the provider's `Retry-After` header was parseable (else `0`) |
| `provider_error` | `provider`, `endpoint`, `status`, `body_snippet` |
| `selfcheck` | `provider`, `ok`, `clock_skew_sec` |
| `enroll` | `provider`, `client` |
| `revoke` | `provider`, `client` |
| `cache_invalidated` | `provider`, `repo`, `cause` (`404` \| `ttl_expired`) |
| `token_cache_hit` | `provider`, `repo` |
| `sandbox_applied` | `policy` (`required` \| `best_effort` \| `off`), `abi` (Landlock ABI requested; `0` if off), `status` (`fully_enforced` \| `partially_enforced` \| `not_enforced` \| `off`), `fs`, `tcp`, `scope` (bool per Landlock layer actually engaged) |
| `sandbox_path_skipped` | `path`, `reason` (`enoent` \| `open_failed`), `error` (when applicable): emitted at `debug` for nameservice / CA-bundle paths absent on this host |
| `prepare` | `version`, `config_path`: emitted by `Service::prepare` once config is loaded and the listening fds have been reclaimed from the supervisor (before selfcheck and readiness) |
| `ready` | `pid`: emitted by `main` after `service.selfcheck()` returns and `ready::notify` has sent `READY=1` to systemd (if applicable) and written the pidfile (if configured) |
| `run_failed` | `signal`, `error`: emitted at `error` lvl by `main` when `Service::run` returns `Err`. Mutually exclusive with `shutdown` (one or the other fires) |
| `ready_pidfile_write_failed` | `path`, `error`: emitted at `warn` lvl by `ready::notify` if the configured pidfile can't be written (typically a sandbox or permission issue) |
| `identity_invalid` | `peer`, `reason` (`bad_magic` \| `bad_version` \| `bad_identity_len` \| `invalid_charset` \| `trailing_bytes` \| `truncated`): emitted when the identity TLV decrypted out of handshake msg1 is malformed; connection dropped. A malformed TLV requires a peer that already encrypts to the broker pubkey, so unlike `identity_unknown` this is not rate-limited |
| `identity_unknown` | `psk_identity`, `peer`, `suppressed`: emitted at `warn` when msg1 carries an identity with no PSK entry. Rate-limited (burst 10, 10/min sustained); `suppressed` counts events dropped since the last emitted one. The connection is NOT dropped early — a random substitute PSK keeps the wire shape identical to a wrong-PSK attempt (anti-enumeration; see Wire formats) |
| `handshake_failed` | `client`, `peer`, `reason` (`responder_init` \| `rng_unavailable` \| `handshake_read_failed` \| `handshake_write_failed` \| `handshake_write_io` \| `handshake_into_transport_failed` \| `frame_too_big` \| `eof_before_msg1` \| `eof_during_handshake` \| `eof_unexpected_phase` \| `internal`): Noise handshake error; connection dropped |
| `drain_incomplete` | `inflight_drained`, `drain_ms`: emitted at `warn` lvl when the per-connection drain deadline elapses with handlers still in flight at shutdown |
| `signal_registration_failed` | `signal`, `error`: emitted at `error` lvl by `main` when `signal-hook-registry::register` fails at startup. Treated as fatal (exit 1). Without it the daemon cannot honour SIGTERM/SIGINT |
| `mlock` | `status` (`applied` \| `skipped` \| `failed` \| `off`), `policy` (`required` \| `best_effort` \| `off`), `flags` (when applied) or `error` (when skipped/failed): emitted once at startup by `main::run_daemon` after `setup_tracing`. `required` failure surfaces as the separate `mlock_required_failed` error event before exit |
| `mlock_required_failed` | `error`: emitted at `error` lvl by `main` when `[security] mlock = "required"` and `mlockall` failed. Fatal (exit 1); operator should add `LimitMEMLOCK=infinity` to the systemd unit |
| `admin_request` | `req_id`, `op`: emitted by the admin loop at entry of each request. The `req_id` (ULID) ties downstream `provider_call` / `mint` / `selfcheck` events back to this admin invocation |
| `provider_call` | `req_id`, `out_req_id`, `endpoint` (`mint_metadata_token` \| `resolve_repo_id` \| `mint_token` \| `selfcheck`), `provider`, `timeout_ms`: emitted before each outbound HTTPS call |
| `provider_call_done` | `req_id`, `out_req_id`, `status` (HTTP status code, 0 if no response), `provider_req_id` (provider's upstream correlation id — `X-GitHub-Request-Id` etc.; empty if absent), `elapsed_ms`, optional `error`: emitted after each outbound HTTPS call |

`reason` values for `mint_denied`:
`client_unknown | client_metadata_missing | unknown_host |
repo_not_accessible | provider_4xx | malformed_request |
transport_read`. `transport_read` (with `detail` = `decrypt_failed`
| `frame_too_big` | `eof`) is where a wrong-PSK or
unknown-identity session finally dies; `client_metadata_missing`
means the PSK store and `clients.json` disagree (operator desync —
the session is refused with the same wire shape as
unknown-identity, but the log is loud and unthrottled).

`endpoint` and `body_snippet` on `provider_error` are deferred
pending a redaction layer to avoid leaking sensitive data (provider
5xx responses can carry tokens). `cause = ttl_expired` on
`cache_invalidated` is also deferred. Only `cause = "404"` fires
today.