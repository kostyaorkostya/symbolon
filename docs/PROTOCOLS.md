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
file = "/etc/gcb/clients.json"

[stunnel]
psk_file = "/etc/stunnel/gcb.psk"
pidfile = "/run/stunnel/stunnel.pid"

[logging]
level = "info"   # trace | debug | info | warn | error

[provider.github]
# For github.com, keep defaults below.
# For GitHub Enterprise Server, set:
#   host     = "github.example.com"
#   api_base = "https://github.example.com/api/v3"
host = "github.com"
api_base = "https://api.github.com"
app_id = 123456
installation_id = 789012
private_key_path = "/etc/gcb/github-app.pem"
```

Unknown top-level keys are rejected by `serde` deserialization
(`#[serde(deny_unknown_fields)]` on every struct).

### `/etc/gcb/clients.json` — machine-authored

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

### GitHub provider outbound

References: [REST API for App installations][gh-installs],
[Installation access tokens][gh-iat], [App permissions][gh-perms],
[JWT (RFC 7519)](https://www.rfc-editor.org/rfc/rfc7519).

[gh-installs]: https://docs.github.com/en/rest/apps/installations
[gh-iat]: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app
[gh-perms]: https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app

**App JWT signing (RS256):**

- `iss`: App ID (numeric string).
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
  - `User-Agent: gcb/<version>` (required by GitHub; missing UA → 403)
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
6. Run selfcheck (verify App ID matches JWT, verify each provider's
   `api_base` reachable, log clock skew).
7. Enter the accept loop.

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
| `gcb.psk` | Not read by daemon; `gcb github enroll`/`revoke` update it and SIGHUP stunnel. |
| `config.toml` | Restart required. |
| App private key | Restart required. |

## Logging schema

Structured JSON to stdout (warn/error to stderr), one record per
line.

**Required fields on every record:**

- `ts` — RFC 3339 UTC, millisecond precision.
- `lvl` — `trace | debug | info | warn | error`.
- `evt` — event name (closed set, below).
- `req_id` — ULID generated at TCP accept, threaded through.

**Per-event additional fields:**

| evt | additional fields |
|---|---|
| `startup` | `version`, `config_path`, `providers` |
| `shutdown` | `signal`, `inflight_drained`, `drain_ms` |
| `accept` | `src_ip` (from PROXY v2), `client` (resolved name) |
| `mint` | `provider`, `repo`, `repo_id`, `client`, `ttl_sec`, `expires_at`, `provider_ms` |
| `mint_denied` | `provider`, `client`, `repo`, `reason`, `provider_status` |
| `proxy_header_invalid` | `bytes_read` |
| `provider_error` | `provider`, `endpoint`, `status`, `body_snippet` |
| `selfcheck` | `provider`, `ok`, `clock_skew_sec` |
| `enroll` | `provider`, `client`, `ip` |
| `revoke` | `provider`, `client` |
| `config_reload` | `triggered_by` (`sighup`) |
| `cache_invalidated` | `provider`, `repo`, `cause` (`404` \| `ttl_expired`) |

`reason` values for `mint_denied`:
`client_unknown | unknown_host | repo_not_accessible | provider_4xx | malformed_request`.