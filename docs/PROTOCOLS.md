# Protocols & file formats

Wire formats and on-disk schemas for `gcb`. Design rationale and
conventions are in [`../AGENTS.md`](../AGENTS.md); operator material is
in [`OPERATIONS.md`](OPERATIONS.md) and [`INSTALL.md`](INSTALL.md);
authoritative URLs are in [`REFERENCES.md`](REFERENCES.md).

## File formats

### `/etc/gcb/config.toml` — operator-authored

```toml
[listen]
# Unix-domain socket the daemon listens on. stunnel forwards here.
socket = "/run/gcb/daemon.sock"

[admin]
socket_path = "/run/gcb/admin.sock"

[clients]
file = "/var/lib/gcb/clients.json"

[stunnel]
psk_file = "/etc/stunnel/gcb.psk"
pidfile = "/run/stunnel/stunnel.pid"

[logging]
level = "info"   # trace | debug | info | warn | error

[security]
# Sandbox enforcement policy. Controls landlock (FS + TCP-connect +
# abstract-UDS scope at ABI 6) and a seccomp filter that confines the
# kill-family syscalls to SIGHUP only.
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

[runtime]
# Optional pidfile. When set, the daemon writes its PID here once
# it's ready to serve. Required for OpenRC's `command_background=yes`
# + `pidfile=...` convention. Leave unset under systemd —
# `Type=notify` + READY=1 covers readiness without a pidfile, and
# modern systemd man pages discourage pidfiles when notify is
# available.
#
# The parent directory of this path is added to the sandbox
# write-allowlist automatically.
pidfile = "/run/gcb/gcb.pid"

[provider.github]
# For github.com, keep defaults below.
# For GitHub Enterprise Server, set:
#   host     = "github.example.com"
#   api_base = "https://github.example.com/api/v3"
host = "github.com"
api_base = "https://api.github.com"
client_id = "Iv23liABCDEFGHIJklmn"
installation_id = 789012
private_key_path = "/etc/gcb/github-app.pem"
selfcheck_timeout = "5s"
# request_timeout = "10s"   # optional; default 10s
```

Unknown top-level keys are rejected by `serde` deserialization
(`#[serde(deny_unknown_fields)]` on every struct). The `[security]`
section is optional and defaults to `sandbox = "best_effort"` with
no extra read dirs.

The PEM key path (`provider.github.private_key_path`) is read once
at startup, **before** the sandbox is applied. The default sandbox
ruleset deliberately omits `/etc/gcb/` so a post-compromise process
inside the daemon cannot re-open the key. Keep the PEM under
`/etc/gcb/` (or any other dir outside `/var/lib/gcb/` and
`/etc/stunnel/`); do not place it in either of the directories
granted write access for atomic state-file writes.

### `/var/lib/gcb/clients.json` — machine-authored

```json
{
  "version": 1,
  "clients": [
    {
      "name": "dev-vm-1",
      "ip": "192.168.122.10",
      "providers": ["github"],
      "enrolled_at": "2026-05-26T12:34:56Z",
      "note": null
    }
  ]
}
```

The `providers` array allows multi-provider enrolment; for the
GitHub-only build it's always `["github"]`.

### `/etc/stunnel/gcb.psk` — machine-authored

stunnel's standard PSK file format, one identity per line:

```
client-name:hex-encoded-key
```

The daemon never reads this file directly; only stunnel does.

## Atomic writes

`clients.json` and `gcb.psk` are mutated only by the daemon (the CLI
talks to the daemon via the admin Unix socket; see AGENTS.md
invariant #10). The daemon writes both files atomically:

1. Write to `<path>.tmp.<random>` in the same directory.
2. `fsync` the tempfile.
3. `rename(2)` over the target path.
4. `fsync` the parent directory.

A crash between steps leaves a tempfile, never a partial target. On
startup the daemon ignores stale `.tmp.*` files; operators can delete
them. No file locks are used — the daemon's single-writer invariant
makes them unnecessary.

## Wire formats

### TLS-PSK termination (stunnel → daemon)

[stunnel](https://www.stunnel.org/) terminates the client's TLS-PSK
connection and forwards plain TCP to the daemon's Unix-domain socket
with a PROXY v2 header. Sample stunnel service block:

```
[gcb]
accept = 0.0.0.0:9418
connect = /run/gcb/daemon.sock
PSKsecrets = /etc/stunnel/gcb.psk
ciphers = PSK
sslVersion = TLSv1.2
protocol = proxy
```

Socket permissions: `/run/gcb/daemon.sock` is owned by `gcb:gcb`,
mode `0660`. The `stunnel` user must be a supplementary member of the
`gcb` group. The daemon unlinks any stale socket at startup before
binding.

### PROXY protocol v2

Reference:
<https://www.haproxy.org/download/2.4/doc/proxy-protocol.txt>.

Every connection accepted on `listen.socket` begins with a PROXY v2
header:

- 12-byte signature: `0d 0a 0d 0a 00 0d 0a 51 55 49 54 0a`
- 1 byte: version (high nibble = 2) | command (low: 0x0 LOCAL, 0x1 PROXY)
- 1 byte: address family + transport (0x11 TCP/IPv4, 0x21 TCP/IPv6)
- 2 bytes: address-block length (big-endian u16)
- Address block: source IP, destination IP, source port, dest port

The Unix-domain transport between stunnel and the daemon is invisible
in the header; the address family is the original client's TCP family.

Parse the header before treating the stream as git-credential. If
parsing fails, log `evt=proxy_header_invalid` with the bytes read and
close the connection without reading further. Implementation in
`src/proxy_protocol.rs`; pure parsing function with property tests
against the format spec.

stunnel does NOT populate any TLV with the PSK identity, so the
daemon cannot cross-check stunnel's PSK auth against the IP-resolved
client name. See AGENTS.md invariant #7.

### git-credential protocol

Reference: <https://git-scm.com/docs/gitcredentials>.

Read after the PROXY v2 header.

**Request:**

```
protocol=https
host=github.com
path=octocat/Spoon-Knife

```

(`key=value` lines terminated by an empty line.)

**Response:**

```
username=x-access-token
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
| `list` | — | `clients` (array of `{name, ip, providers, enrolled_at, note}`) |
| `enroll` | `provider`, `client`, `ip`, `note` (nullable) | `identity`, `psk_hex` (64 hex chars), `client_name` |
| `revoke` | `provider`, `client` | — |
| `mint` | `provider`, `client`, `path` | `username`, `password`, `expires_at_unix`, `repo_id` |
| `selfcheck` | `provider` | `client_id`, `installation_id`, `api_base`, `clock_skew_sec` |

Error codes:
`bad_request | unknown_provider | unknown_client |
client_already_enrolled | client_ip_collision | malformed_request |
internal | repo_not_accessible | provider_4xx`.

The daemon serialises admin requests, so file writes to
`clients.json` / `gcb.psk` do not race the listen-side accept loop
(AGENTS.md invariant #10).

CR or embedded LF inside any string field is rejected (same
Clone2Leak-class defence applied to the admin path).

### GitHub provider outbound

References: [REST API for App installations][gh-installs],
[Installation access tokens][gh-iat], [App permissions][gh-perms],
[JWT (RFC 7519)](https://www.rfc-editor.org/rfc/rfc7519).

[gh-installs]: https://docs.github.com/en/rest/apps/installations
[gh-iat]: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app
[gh-perms]: https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app

**App JWT signing (RS256):**

- `iss`: App client ID (e.g. `Iv23liABCDEFGHIJklmn`). GitHub
  accepts either the numeric App ID or the client ID here; we use
  the client ID because it is stable across App ownership transfers.
- `iat`: now − 60 s (clock-skew tolerance).
- `exp`: now + 540 s (9 minutes; GitHub max is 10).
- Signing key: PEM at `provider.github.private_key_path`, loaded once
  at daemon startup, held in memory. To rotate, restart the daemon.
- Implementation: `jsonwebtoken::encode` with
  `EncodingKey::from_rsa_pem`.

**Token mint:**

- `POST {api_base}/app/installations/{installation_id}/access_tokens`
- Headers:
  - `Authorization: Bearer <jwt>`
  - `Accept: application/vnd.github+json`
  - `X-GitHub-Api-Version: <current>`
  - `User-Agent: <provider.github.user_agent>` — defaults to `gcb` if
    unset; configurable by the operator. Required by GitHub (missing
    UA → 403). Intentionally carries no version number so an
    attacker can't narrow the applicable CVE list.
- Body:
  ```json
  {
    "repository_ids": [<numeric_repo_id>],
    "permissions": { "contents": "write", "metadata": "read" }
  }
  ```
- Response: `201 Created` with `{token, expires_at}`. Surface 4xx as
  `evt=mint_denied provider_status=<code>`; surface 5xx as
  `evt=provider_error`.

**Repository-ID resolution and cache:**

- `GET {api_base}/repos/{owner}/{repo}` with the App JWT returns
  `{id, ...}`.
- In-memory cache keyed by `(provider_name, owner/repo)`
  (case-insensitive for `owner/repo`).
- **TTL: 600 seconds per entry.** On any 404 referring to a cached
  entry, invalidate it; the next mint re-resolves. This handles the
  delete-then-recreate-with-same-name case where the numeric ID
  changes.

## Daemon lifecycle

### Startup

1. Parse `config.toml`. Fail fast on schema errors.
2. Load App private key(s) into memory. Fail fast on parse error.
3. Unlink any stale `listen.socket` and `admin.socket_path`.
4. Bind both Unix sockets; set mode `0660`, owner `gcb:gcb`.
5. Load `clients.json`. Fail fast on schema errors.
6. Apply sandbox (landlock + seccomp). Per `[security] sandbox`:
   `required` aborts on missing kernel features; `best_effort`
   degrades and emits `evt=sandbox_applied` at `warn` lvl; `off`
   skips. After this step the PEM key dir is unreachable, only the
   small allowlist (state dirs, `/dev/urandom`, `/etc/ssl/certs`,
   nameservice files, TCP-connect to port 443, SIGHUP sends) remains
   permitted.
7. Run selfcheck (verify App ID matches JWT, verify each provider's
   `api_base` reachable, log clock skew).
8. Enter the accept loop.

### Shutdown

On `SIGTERM` or `SIGINT`:
1. Stop accepting new connections on the listen socket.
2. Drain in-flight handlers with a **5-second deadline**.
3. Close the admin socket and the listen socket (unlinking them).
4. Exit 0.

Log `evt=shutdown signal=<sig> inflight_drained=<n> drain_ms=<ms>`.

On any other signal except SIGHUP: terminate fast; do not drain.

### Hot reload

| File | Reload mechanism |
|---|---|
| `clients.json` | SIGHUP re-reads from disk. |
| `gcb.psk` | Read AND written by daemon: `gcb github enroll`/`revoke` route through the admin socket; the daemon parses, appends/removes, atomically rewrites, then SIGHUPs stunnel. The file is the daemon's serialization target, not a notification surface. |
| `config.toml` | Restart required. |
| App private key | Restart required. |

## Logging schema

Structured JSON to stdout (warn/error to stderr), one record per
line. Produced by `tracing-subscriber`'s built-in JSON formatter
with `flatten_event(true)`, so user-added fields appear as
top-level keys.

**Required fields on every record:**

- `timestamp` — RFC 3339 UTC, subsecond precision. Emitted by
  `tracing-subscriber`'s default JSON timer.
- `level` — `TRACE | DEBUG | INFO | WARN | ERROR` (uppercase,
  per the built-in formatter).
- `evt` — event name (closed set, below). User-added field.
- `req_id` — ULID generated at TCP accept, threaded through.
  User-added field.

**Per-event additional fields:**

| evt | additional fields |
|---|---|
| `startup` | `version`, `config_path`, `providers` |
| `shutdown` | `signal`, `inflight_drained`, `drain_ms` |
| `accept` | `src_ip` (from PROXY v2), `client` (resolved name) |
| `mint` | `provider`, `repo`, `repo_id`, `client`, `ttl_sec`, `expires_at_unix`, `provider_ms` |
| `mint_denied` | `provider`, `client`, `repo`, `reason`, `provider_status` |
| `proxy_header_invalid` | `bytes_read` |
| `provider_error` | `provider`, `endpoint`, `status`, `body_snippet` |
| `selfcheck` | `provider`, `ok`, `clock_skew_sec` |
| `enroll` | `provider`, `client`, `ip` |
| `revoke` | `provider`, `client` |
| `config_reload` | `triggered_by` (`sighup`) |
| `cache_invalidated` | `provider`, `repo`, `cause` (`404` \| `ttl_expired`) |
| `sandbox_applied` | `policy` (`required` \| `best_effort` \| `off`), `abi` (landlock ABI requested; `0` if off), `status` (`fully_enforced` \| `partially_enforced` \| `not_enforced` \| `off`), `fs`, `tcp`, `scope`, `seccomp` (bool per subsystem actually engaged) |
| `sandbox_path_skipped` | `path`, `reason` (`enoent` \| `open_failed`), `error` (when applicable) — emitted at `debug` for nameservice / CA-bundle paths absent on this host |
| `prepare` | `version`, `config_path`, `listen_socket`, `admin_socket` — emitted by `Service::prepare` once config is loaded and sockets are bound (before selfcheck and readiness) |
| `ready` | `pid` — emitted by `main` after `service.selfcheck()` returns and `ready::notify` has sent `READY=1` to systemd (if applicable) and written the pidfile (if configured) |
| `run_failed` | `signal`, `error` — emitted at `error` lvl by `main` when `Service::run` returns `Err`. Mutually exclusive with `shutdown` (one or the other fires) |
| `ready_pidfile_write_failed` | `path`, `error` — emitted at `warn` lvl by `ready::notify` if the configured pidfile can't be written (typically a sandbox or permission issue) |
| `admin_denied` | `peer_uid`, `peer_pid` — emitted at `warn` lvl when SO_PEERCRED on the admin socket shows a UID that is neither root nor the daemon's own |
| `admin_peercred_failed` | `error` — emitted at `warn` lvl when SO_PEERCRED itself fails; the connection is still admitted (refusing on a transient kernel error would be a self-DoS) |
| `stunnel_sighup_failed` | `error` — emitted at `warn` lvl when `StunnelController::sighup` fails after an enroll/revoke rewrote `gcb.psk`. The state mutation is NOT rolled back; operator notices via `gcb status` or stunnel logs |
| `drain_incomplete` | `inflight_drained`, `drain_ms` — emitted at `warn` lvl when the per-connection drain deadline elapses with handlers still in flight at shutdown |
| `signal_registration_failed` | `signal`, `error` — emitted at `error` lvl by `main` when `signal-hook-registry::register` fails at startup. Treated as fatal (exit 1) — without it the daemon cannot honour SIGTERM/SIGINT/SIGHUP |

`reason` values for `mint_denied`:
`client_unknown | unknown_host | repo_not_accessible | provider_4xx | malformed_request`.

`endpoint` and `body_snippet` on `provider_error` are deferred
pending a redaction layer to avoid leaking sensitive data (provider
5xx responses can carry tokens). `cause = ttl_expired` on
`cache_invalidated` is also deferred — only `cause = "404"` fires
today.