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
# TCP address the daemon binds for inbound client connections.
# Symbolon terminates Noise NNpsk0 in-process; no TLS proxy.
bind = "0.0.0.0:9418"
# Symbolon-owned PSK store. Mutated atomically on enroll/revoke.
psk_file = "/var/lib/symbolon/psks"

[admin]
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
private_key_path = "/etc/symbolon/github-app.pem"
selfcheck_timeout = "5s"
```

Unknown top-level keys are rejected by `serde` deserialization
(`#[serde(deny_unknown_fields)]` on every struct). The `[security]`
section is optional and defaults to `sandbox = "best_effort"` with
no extra read dirs.

The provider private-key path is read once at startup, **before**
the sandbox is applied. The default sandbox ruleset deliberately
omits `/etc/symbolon/` so a post-compromise process inside the
daemon cannot re-open the key. Keep the key file under
`/etc/symbolon/` (or any other dir outside `/var/lib/symbolon/`);
do not place it in the directory granted write access for atomic
state-file writes.

### `/var/lib/symbolon/clients.json`: machine-authored

```json
{
  "version": 1,
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

`version` is a literal integer the daemon checks at parse time
(currently must be `1`); it exists so a future on-disk format
change can be detected and migrated rather than silently
mis-parsed. The `providers` array allows multi-provider
enrolment per client.

### `/var/lib/symbolon/psks`: machine-authored

Symbolon-owned PSK store. One identity per line:

```
client-name:hex-encoded-32-byte-key
```

The daemon parses this file at startup and on `SIGHUP` reload,
and rewrites it atomically on every `enroll` / `revoke`. Owner is
the `symbolon` user, mode `0600`.

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

### Identity prelude (cleartext, sent before the Noise handshake)

```
+--------+---+---+----------------+
| "SBLN" | V | L | identity bytes |
+--------+---+---+----------------+
   4      1   1       L (1..=64)
```

- 4 bytes magic: ASCII `"SBLN"`. Daemon rejects with
  `evt=prelude_invalid reason=bad_magic` otherwise.
- 1 byte version: `0x01`. Future-proofing.
- 1 byte identity length `L`. Must be 1..=64.
- `L` bytes identity. Charset enforced to `[A-Za-z0-9._-]+` (same rule
  as git-credential values; CR/LF/NUL rejected; AGENTS.md invariant
  #12 in spirit).

Prelude bytes are cleartext on the wire. An attacker passively
observing the network learns which client identity is being used but
cannot impersonate without the PSK and cannot decrypt anything.

### Noise NNpsk0 handshake (binary)

Pattern: `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` (per
[Noise spec rev 34](https://noiseprotocol.org/noise_rev34.html)),
driven by the [`snow`](https://github.com/mcginty/snow) crate.

After the prelude, both sides exchange exactly two framed messages:

```
1. initiator → responder: psk, e   (one framed Noise message)
2. responder → initiator: e, ee    (one framed Noise message)
```

Per-message framing on the TCP stream:

```
+-----------+--------------------+
| len (u16) | message body bytes |
+-----------+--------------------+
     2              len (≤ 65535)
```

Handshake completion authenticates the connection (PSK proof on both
sides) and yields an AEAD transport state. Forward secrecy is
provided by the ephemeral X25519 keys; replay protection is provided
by the per-message AEAD nonce counter.

On handshake failure (binder check, oversized frame, EOF mid-message),
the daemon logs `evt=handshake_failed reason=...` and closes the
connection.

### git-credential protocol (inside the Noise transport)

Reference: <https://git-scm.com/docs/gitcredentials>.

After the handshake, application-layer messages are encrypted-and-
framed Noise transport messages. The first inbound message decrypts
to a git-credential request block; the daemon's response is
encrypted and framed the same way before being written back.

**Request:**

```
protocol=https
host=github.com
path=octocat/Spoon-Knife

```

(`key=value` lines terminated by an empty line.)

**Response** (value of `username` is provider-determined; see
per-provider doc):

```
username=<provider-specified-username>
password=<token>
password_expiry_utc=<epoch>

```

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

**Request:** `{"op":"<status|list|enroll|revoke|mint|selfcheck>",
…op-specific fields}\n`

**Response on success:** `{"ok":true, …op-specific fields}\n`

**Response on failure:** `{"ok":false, "error":"<message>",
"code":"<machine-code>"}\n`

Op fields (request → response):

| op | request fields | response fields |
|---|---|---|
| `status` | — | `uptime_sec`, `providers`, `client_count` |
| `list` | — | `clients` (array of `{name, providers, enrolled_at, note}`) |
| `enroll` | `provider`, `client`, `note` (nullable) | `identity`, `psk_hex` (64 hex chars), `client_name` |
| `revoke` | `provider`, `client` | — |
| `mint` | `provider`, `client`, `path` | `username`, `password`, `expires_at_unix`, `repo_id` |
| `selfcheck` | `provider` | `client_id`, `installation_id`, `api_base`, `clock_skew_sec` |

Error codes:
`bad_request | unknown_provider | unknown_client |
client_already_enrolled | internal | repo_not_accessible |
provider_4xx`.

The daemon serialises admin requests, so file writes to
`clients.json` / `psks` do not race the listen-side accept loop
(AGENTS.md invariant #10).

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

1. Parse `config.toml`. Fail fast on schema errors.
2. Load each configured provider's private key file into memory.
   Fail fast on parse error.
3. Unlink any stale `admin.socket_path`.
4. Bind the TCP listen socket and the admin Unix socket; set
   admin socket mode `0600`, owner `symbolon:symbolon`.
5. Load `clients.json`. Fail fast on schema errors.
6. Apply sandbox (Landlock at ABI 6). Per `[security] sandbox`:
   `required` aborts on missing kernel features; `best_effort`
   degrades and emits `evt=sandbox_applied` at `warn` lvl; `off`
   skips. After this step the provider key dir is unreachable;
   only the small allowlist (state dirs, `/dev/urandom`,
   `/etc/ssl/certs`, nameservice files, TCP-connect to port 443,
   intra-process signals) remains permitted.
7. Run per-provider selfcheck (provider-specific: verifies the
   provider identity claim and reachability; see
   [providers/](providers/)).
8. Enter the accept loop.

### Shutdown

On `SIGTERM` or `SIGINT`:
1. Stop accepting new connections on the listen socket.
2. Drain in-flight handlers with a **5-second deadline**.
3. Unlink and close the admin Unix socket; close the TCP
   listen socket (no unlink; it's not a filesystem node).
4. Exit 0.

Log `evt=shutdown signal=<sig> inflight_drained=<n> drain_ms=<ms>`.

On any other signal except SIGHUP: terminate fast; do not drain.

### Hot reload

| File | Reload mechanism |
|---|---|
| `clients.json` | SIGHUP re-reads from disk. |
| `psks` | Read AND written by daemon: per-provider `enroll`/`revoke` commands route through the admin socket; the daemon parses, mutates the in-memory `PskStore`, and atomically rewrites the file. No external process to notify. Symbolon owns the responder side of Noise NNpsk0 directly. |
| `config.toml` | Restart required. |
| Provider private key | Restart required. |

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
plus `out_req_id` + `gh_req_id` for provider-call-derived events
(`mint`, `selfcheck`, `mint_denied`, `provider_error`,
`cache_invalidated`). These are not repeated per row.

The closed-set catalog of `evt` values is encoded in
`src/events.rs::EventKind`; adding a new event name requires
extending the enum and adding a row below.

| evt | additional fields |
|---|---|
| `startup` | `providers` |
| `shutdown` | `signal`, `inflight_drained`, `drain_ms`, `drain_complete` |
| `accept` | `psk_identity` (from the Noise prelude), `peer` (TCP source addr, audit-only) |
| `mint` | `provider`, `repo`, `repo_id`, `client`, `ttl_sec`, `expires_at_unix`, `provider_ms` |
| `mint_denied` | `provider`, `client`, `repo`, `reason`, `provider_status` |
| `provider_error` | `provider`, `endpoint`, `status`, `body_snippet` |
| `selfcheck` | `provider`, `ok`, `clock_skew_sec` |
| `enroll` | `provider`, `client` |
| `revoke` | `provider`, `client` |
| `config_reload` | `triggered_by` (`sighup`) |
| `cache_invalidated` | `provider`, `repo`, `cause` (`404` \| `ttl_expired`) |
| `sandbox_applied` | `policy` (`required` \| `best_effort` \| `off`), `abi` (Landlock ABI requested; `0` if off), `status` (`fully_enforced` \| `partially_enforced` \| `not_enforced` \| `off`), `fs`, `tcp`, `scope` (bool per Landlock layer actually engaged) |
| `sandbox_path_skipped` | `path`, `reason` (`enoent` \| `open_failed`), `error` (when applicable): emitted at `debug` for nameservice / CA-bundle paths absent on this host |
| `prepare` | `version`, `config_path`, `listen_addr`, `admin_socket`: emitted by `Service::prepare` once config is loaded and sockets are bound (before selfcheck and readiness) |
| `ready` | `pid`: emitted by `main` after `service.selfcheck()` returns and `ready::notify` has sent `READY=1` to systemd (if applicable) and written the pidfile (if configured) |
| `run_failed` | `signal`, `error`: emitted at `error` lvl by `main` when `Service::run` returns `Err`. Mutually exclusive with `shutdown` (one or the other fires) |
| `ready_pidfile_write_failed` | `path`, `error`: emitted at `warn` lvl by `ready::notify` if the configured pidfile can't be written (typically a sandbox or permission issue) |
| `admin_denied` | `peer_uid`, `peer_pid`: emitted at `warn` lvl when SO_PEERCRED on the admin socket shows a UID that is neither root nor the daemon's own |
| `admin_peercred_failed` | `error`: emitted at `warn` lvl when SO_PEERCRED itself fails; the connection is still admitted (refusing on a transient kernel error would be a self-DoS) |
| `prelude_invalid` | `peer`, `reason` (`bad_magic` \| `bad_version` \| `bad_identity_len` \| `invalid_charset` \| `eof_before_prelude_head` \| `eof_before_identity`): emitted when the identity prelude is malformed; connection dropped |
| `handshake_failed` | `client`, `reason` (`handshake_read_failed` \| `handshake_write_failed` \| `handshake_into_transport_failed` \| `decrypt_failed` \| `frame_too_big`): Noise handshake or transport error; connection dropped |
| `drain_incomplete` | `inflight_drained`, `drain_ms`: emitted at `warn` lvl when the per-connection drain deadline elapses with handlers still in flight at shutdown |
| `signal_registration_failed` | `signal`, `error`: emitted at `error` lvl by `main` when `signal-hook-registry::register` fails at startup. Treated as fatal (exit 1). Without it the daemon cannot honour SIGTERM/SIGINT/SIGHUP |
| `mlock` | `status` (`applied` \| `skipped` \| `failed` \| `off`), `policy` (`required` \| `best_effort` \| `off`), `flags` (when applied) or `error` (when skipped/failed): emitted once at startup by `main::run_daemon` after `setup_tracing`. `required` failure surfaces as the separate `mlock_required_failed` error event before exit |
| `mlock_required_failed` | `error`: emitted at `error` lvl by `main` when `[security] mlock = "required"` and `mlockall` failed. Fatal (exit 1); operator should add `LimitMEMLOCK=infinity` to the systemd unit |
| `admin_request` | `req_id`, `op`: emitted by the admin loop at entry of each request. The `req_id` (ULID) ties downstream `provider_call` / `mint` / `selfcheck` events back to this admin invocation |
| `provider_call` | `req_id`, `out_req_id`, `endpoint` (`mint_metadata_token` \| `resolve_repo_id` \| `mint_token` \| `selfcheck`), `provider`, `timeout_ms`: emitted before each outbound HTTPS call |
| `provider_call_done` | `req_id`, `out_req_id`, `status` (HTTP status code, 0 if no response), `gh_req_id` (X-GitHub-Request-Id, empty if absent), `elapsed_ms`, optional `error`: emitted after each outbound HTTPS call |

`reason` values for `mint_denied`:
`client_unknown | unknown_host | repo_not_accessible | provider_4xx | malformed_request`.

`endpoint` and `body_snippet` on `provider_error` are deferred
pending a redaction layer to avoid leaking sensitive data (provider
5xx responses can carry tokens). `cause = ttl_expired` on
`cache_invalidated` is also deferred. Only `cause = "404"` fires
today.