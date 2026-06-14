# Operating `symbolon`

Cross-provider operator reference. Per-provider specifics
(commands, hardening, hard-cutoff procedures) live in
[providers/](providers/); fresh deploy in
[INSTALL.md](INSTALL.md); design rationale in
[../AGENTS.md](../AGENTS.md); wire and file formats in
[PROTOCOLS.md](PROTOCOLS.md).

CLI commands talk to the daemon over its admin Unix socket. The
socket is SO_PEERCRED-gated to root or the daemon's UID, so the
commands need to run as one of those. How you arrange that
(invoking as root, `sudo -u`, `machinectl shell`, etc.) is up to
your local convention.

## Commands

### Cross-provider

```
symbolon [--config /etc/symbolon/config.toml]
    Run the daemon. Default when invoked with no subcommand.

symbolon status
    Print daemon health: uptime, last successful mint, last error,
    cached-repo-id count, configured providers.

symbolon list
    Print all enrolled clients across providers, with the providers
    each is enrolled for and the enrollment timestamp.
```

### Per-provider

`enroll`, `revoke`, `mint`, `selfcheck` are grouped under each
provider subcommand. See:

- **GitHub** → [providers/github.md](providers/github.md) § Commands.

## Logging

Structured JSON to stdout (warn/error to stderr), one record per
line. Schema and event catalog:
[PROTOCOLS.md § Logging schema](PROTOCOLS.md#logging-schema).

Useful one-liners:

```sh
tail -f /var/log/symbolon.log | jq -c .

jq -c 'select(.evt == "mint" and .client == "dev-vm-1")' < /var/log/symbolon.log

jq -c 'select(.evt == "mint_denied") | {timestamp, client, repo, reason}' \
  < /var/log/symbolon.log

jq -c 'select(.evt == "provider_error")' < /var/log/symbolon.log | tail -100
```

Hook into your log shipper as you would for any structured-JSON
service (rsyslog `imuxsock` + `omfwd`, Vector, journald, etc.).

### `evt=sandbox_applied`

Emitted exactly once at startup. Reports the result of applying
Landlock.

```jsonc
{"evt":"sandbox_applied","policy":"best_effort","abi":6,
 "status":"fully_enforced","fs":true,"tcp":true,"scope":true}
```

- `status: "fully_enforced"` → all of FS, outbound TCP-connect to
  port 443, and the scope layer (abstract-UDS + cross-process
  signal-send) are active. Logged at `info`.
- `status: "partially_enforced"` → some features were downgraded
  because the kernel doesn't support them. The per-subsystem
  booleans show which. Logged at `warn`. Common cause: kernel
  < 6.12, so `Scope::Signal` is unavailable and the scope layer
  reports false.
- `status: "not_enforced"` → kernel has no Landlock at all.
  Logged at `warn`. The daemon runs with no sandbox; operators on
  this kernel should set `[security] sandbox = "required"` to
  force startup failure rather than silent degradation.
- `status: "off"` → `[security] sandbox = "off"` in `config.toml`.
  Logged at `info`. There is no sandboxing of any kind.

## Sandbox

Brief: the broker self-sandboxes at startup with Landlock at ABI 6
— FS read/write allowlist, outbound TCP-connect restricted to port
443, abstract-UDS scope, and `Scope::Signal` (Linux 6.12+) denying
signals to processes outside the broker's domain. The exact
allowlist (paths, scopes, edge cases) is in
[`src/sandbox.rs`](../src/sandbox.rs) — read the source when
something behaves unexpectedly.

The atomic-write directory grant on `/var/lib/symbolon/` covers
everything in that directory; the provider key lives outside this
dir on purpose.

For additional host-policy enforcement (per-process syscall scope
etc.), layer AppArmor or SELinux from the surrounding LXC/systemd
config. Out of scope for the broker itself.

## Troubleshooting

### `git clone` fails with "Authentication failed" or similar

Walk the chain end to end.

**1. Is the daemon running and healthy?**

```sh
symbolon status
symbolon github selfcheck      # or whichever provider you're using
```

If `selfcheck` fails: the daemon can't reach the provider, the
provider key is wrong, or clock skew is large. The output names
which.

**2. Is the daemon listening?**

```sh
ss -tlnp | grep ':9418'          # symbolon should be listening here
ls -l /run/symbolon/admin.sock   # admin UDS, owner symbolon:symbolon, mode 0600
```

If the admin socket is missing after a reboot: `/run` is tmpfs,
cleared at boot — `checkpath` (OpenRC) or `tmpfiles.d` (systemd)
must recreate `/run/symbolon`. See
[INSTALL.md §3.8 / §3.9](INSTALL.md).

**3. Can the client reach the broker over Noise?**

From the client:

```sh
echo 'protocol=https
host=github.com
path=octocat/Spoon-Knife
' | git-credential-symbolon \
    --endpoint broker.lan:9418 \
    --identity dev-vm-1 \
    --psk-file /etc/symbolon/psk \
    get
```

A successful response prints `username`, `password`, and
`password_expiry_utc` on stdout. If the helper exits non-zero with
a stderr message, the cause is a PSK mismatch, an unknown identity
on the broker side, or a network path block.

**4. Can a mint succeed end to end?**

From the broker:

```sh
symbolon github mint dev-vm-1 octocat/Spoon-Knife
```

This bypasses the client transport and runs the mint logic
directly. If this fails, the issue is provider-side, not
transport-side.

**5. What does the daemon log say?**

```sh
tail -f /var/log/symbolon.log | jq -c .
```

Find the `req_id` of the failing request and trace it from
`accept` through `mint` or `mint_denied`. The `reason` field on
`mint_denied` points at the fix.

### Common failure causes

- **`mint_denied reason=client_unknown`**: the PSK identity from
  the Noise prelude didn't match any enrolled client. Either the
  client's `--identity` flag is wrong, the client was revoked, or
  the operator and client disagree about the spelling.
- **`mint_denied reason=unknown_host`**: the credential helper
  sent a `host=` that isn't one of the configured providers. The
  match is byte-exact against `provider.<name>.host` — no suffix
  match, no case-folding.
- **`mint_denied reason=repo_not_accessible`**: the provider does
  not grant the configured identity access to that repo. Fix on
  the provider side (e.g. add the repo to the App's install
  settings on github.com).
- **`mint_denied reason=malformed_request`**: the credential
  request had embedded CR/LF in a field value (defended against
  per [PROTOCOLS.md § CR/LF rejection](PROTOCOLS.md#security-crlf-rejection-mandatory)),
  or `path` was missing. A modern git with
  `credential.protectProtocol=true` should never trigger this; if
  it does, suspect a malicious URL.
- **`mint_denied reason=provider_4xx`**: the provider rejected
  the mint with a 4xx. The full response body is in the log.
  Per-provider causes are in the provider's doc.
- **`provider_error` with 5xx**: the provider had a temporary
  issue. Retry the git operation; the daemon does not retry.
- **`sandbox_applied status=not_enforced` or
  `partially_enforced`**: the kernel doesn't support the
  requested landlock features. Check `uname -r` — need 6.12+ for
  full ABI 6 (`Scope::Signal` landed in 6.12); 6.10–6.11 enforce
  everything else but report `scope: false`. Also
  `grep landlock /sys/kernel/security/lsm`. If the host kernel is
  fine but you're in an LXC container, confirm the container
  hasn't masked `/sys/kernel/security/`. Set
  `[security] sandbox = "required"` to make the daemon refuse to
  start on hosts that can't enforce.

## Identity attribution

Identity is the PSK identity surfaced by the Noise handshake. A
connection only completes the handshake if the client presented an
enrolled identity AND held the matching PSK; the `evt=accept` log
field `psk_identity` reflects that authenticated value, not the
client-claimed string. The TCP source address is logged as `peer`
for audit only — never used for identity decisions (DHCP-friendly).

## Revocation

To revoke a single client (general flow; the command is
per-provider):

```sh
symbolon github revoke <client>
```

This removes the client's PSK entry from the daemon's PSK store
and from `clients.json`. Subsequent handshakes from that identity
are rejected with `evt=mint_denied reason=client_unknown` before
the handshake completes.

**Tokens already minted are not invalidated** — they live their
full provider-side TTL regardless. For hard cutoff (kill all
outstanding tokens immediately), see the per-provider doc; the
exact procedure depends on what the provider supports (private-key
rotation, App uninstall, etc.).

To stop all clients at once: stop the symbolon daemon. Restart
when the situation is resolved.

## Updating

```sh
VERSION=v0.2.0
TARGET=x86_64-unknown-linux-musl
BASE=https://github.com/kostyaorkostya/symbolon/releases/download/${VERSION}
curl -fsSLO "${BASE}/symbolon-${TARGET}"
curl -fsSLO "${BASE}/symbolon-${TARGET}.sha256"
sha256sum -c "symbolon-${TARGET}.sha256"

install -o root -g root -m 0755 "symbolon-${TARGET}" /usr/local/bin/symbolon
rc-service symbolon restart
symbolon github selfcheck
```

Shutdown is graceful: on SIGTERM the daemon stops accepting new
connections, drains in-flight handlers with a 5-second deadline,
then exits. Restart latency is typically <1 second for an idle
broker.

Read the release notes before upgrading across a minor version;
config-format changes will be called out there.

## Backup

What to back up:

- `/etc/symbolon/config.toml` — operator-authored.
- `/var/lib/symbolon/clients.json` — machine-authored; can be
  regenerated by re-enrolling, but timestamps are useful for
  forensics.
- The provider key file (path per provider; for GitHub typically
  `/etc/symbolon/github-app.pem`) — treat as a secret; back up to
  a place at least as protected as the broker itself.
- `/var/lib/symbolon/psks` — per-client PSKs. Treat as a secret;
  back up to a place at least as protected as the broker itself.
  Restoring this alongside `clients.json` is sufficient to keep
  existing clients working without re-enrolling.

What NOT to back up:

- Logs in `/var/log/symbolon.log` — useful for forensics but not
  for recovery. Ship them off-host via your log pipeline if you
  want retention.
