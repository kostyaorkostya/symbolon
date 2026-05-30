# Operating `gcb`

Day-to-day operator reference. For a fresh deployment, see
[INSTALL.md](INSTALL.md). For design rationale, see
[../AGENTS.md](../AGENTS.md). For wire formats and schemas, see
[PROTOCOLS.md](PROTOCOLS.md).

## Commands

All commands run on the broker host as the `gcb` user (or via
`sudo -u gcb`).

### Provider-agnostic

```
gcb [--config /etc/gcb/config.toml]
    Run the daemon. Default when invoked with no subcommand.

gcb status
    Print daemon health: uptime, last successful mint, last error,
    cached-repo-id count, configured providers.

gcb list
    Print all enrolled clients across providers, with the providers
    each is enrolled for and the enrollment timestamp.
```

### GitHub provider

```
gcb github enroll <client> --ip <ip> [--note <text>]
    Generate a per-client PSK, append to stunnel's psk file and
    clients.json (both atomically), SIGHUP stunnel, and print a
    paste-ready provisioning snippet to stdout.

gcb github revoke <client>
    Remove the client's GitHub enrollment. If the client has no
    remaining provider enrollments, remove from clients.json and
    stunnel.psk entirely. SIGHUP stunnel.

    NOTE: Outstanding tokens minted in the past hour are NOT
    revoked. They live out their full TTL.

gcb github mint <client> <owner/repo>
    Test path: run the full mint flow as if <client> requested a
    token for <owner/repo>. Prints token and expiry to stdout.
    Useful for verifying provider-side state without spinning up
    a client.

gcb github selfcheck
    Verify the App private key parses, the App ID matches the JWT,
    api.github.com (or your GHES api_base) is reachable, and clock
    skew is bounded. Exits non-zero on any failed check.
```

## Logging

Structured JSON to stdout, one record per line. Schema and event
catalog: [PROTOCOLS.md §"Logging schema"](PROTOCOLS.md#logging-schema).

Useful one-liners:

```sh
tail -f /var/log/gcb.log | jq -c .

jq -c 'select(.evt == "mint" and .client == "dev-vm-1")' < /var/log/gcb.log

jq -c 'select(.evt == "mint_denied") | {ts, client, repo, reason}' \
  < /var/log/gcb.log

jq -c 'select(.evt == "provider_error")' < /var/log/gcb.log | tail -100
```

Hook into your log shipper as you would for any structured-JSON
service (rsyslog `imuxsock` + `omfwd`, Vector, journald, etc.).

## Troubleshooting

### `git clone` fails with "Authentication failed" or similar

Walk the chain end to end.

**1. Is the daemon running and healthy?**

```sh
sudo -u gcb gcb status
sudo -u gcb gcb github selfcheck
```

If `selfcheck` fails: the daemon can't reach the provider, the App
key is wrong, or clock skew is large. The output names which.

**2. Is stunnel listening, and is the daemon's socket present?**

```sh
rc-service stunnel status        # or `systemctl status stunnel`
ss -tlnp | grep ':9418'          # stunnel should be listening here
ls -l /run/gcb/daemon.sock       # owner gcb:gcb, mode 0660
```

If the socket is missing after a reboot: see [INSTALL.md §3.9](INSTALL.md)
(`/run` is tmpfs, cleared at boot — `checkpath` / `tmpfiles.d` must
recreate `/run/gcb`). If the socket exists but stunnel can't connect,
verify `stunnel` is in the `gcb` group: `id stunnel`.

**3. Can the client reach the broker over TLS-PSK?**

From the client:

```sh
openssl s_client -tls1_2 -cipher PSK \
  -psk_identity dev-vm-1 -psk "$(cat /etc/gcb/psk)" \
  -connect broker.lan:9418 -quiet < /dev/null
```

A clean handshake with no output (and exit 0 given `< /dev/null`)
means TLS is fine and the daemon closed because there was no request.
If handshake fails: PSK mismatch, or network path blocked.

**4. Can a mint succeed end to end?**

From the broker:

```sh
sudo -u gcb gcb github mint dev-vm-1 octocat/Spoon-Knife
```

This bypasses the client transport and runs the mint logic directly.
If this fails, the issue is provider-side, not transport-side.

**5. What does the daemon log say?**

```sh
tail -f /var/log/gcb.log | jq -c .
```

Find the `req_id` of the failing request and trace it from `accept`
through `mint` or `mint_denied`. The `reason` field on `mint_denied`
points at the fix.

### Common failure causes

- **`mint_denied reason=client_unknown`**: the source IP in the
  PROXY v2 header didn't match any client in `clients.json`. Either
  the client moved IPs (re-enroll with the new IP) or upstream IP
  attestation isn't working as expected.
- **`mint_denied reason=unknown_host`**: the credential helper sent
  a `host=` that isn't one of the configured providers. For GitHub
  it must be the value in `provider.github.host` exactly — no suffix
  match, no case-folding.
- **`mint_denied reason=repo_not_accessible`**: the GitHub App has
  not been granted access to that repo. Open the App's install
  settings on github.com and add the repo to the access set.
- **`mint_denied reason=malformed_request`**: the credential request
  had embedded CR/LF in a field value (defended against per
  PROTOCOLS.md "CR/LF rejection"), or `path` was missing. A modern
  git with `credential.protectProtocol=true` should never trigger
  this; if it does, suspect a malicious URL.
- **`mint_denied reason=provider_4xx`**: GitHub rejected the mint
  with a 4xx. The full response body is in the log. Common causes:
  installation ID is wrong in config, App was uninstalled, App's
  permissions were changed.
- **`provider_error` with 5xx**: GitHub had a temporary issue.
  Retry the git operation; the daemon does not retry.

## Audit caveat: stunnel does not forward PSK identity

The daemon attributes every connection to a client by looking up the
source IP from the PROXY v2 header against `clients.json`. **stunnel
does not place the negotiated PSK identity into a PROXY TLV**, so the
daemon cannot cross-check that the PSK-authenticated identity matches
the IP-resolved client name. The upstream IP-attestation layer (e.g.
libvirt `clean-traffic`) is therefore load-bearing for correct
attribution.

If you suspect attribution drift, correlate stunnel's own logs
(`/var/log/stunnel/stunnel.log` records PSK identities at debug
levels) against `gcb`'s `accept`/`mint` events by timestamp.

## Revocation

To revoke a single client:

```sh
sudo -u gcb gcb github revoke <client>
```

This removes the client's PSK entry from stunnel and removes the
client from `clients.json`. The client can no longer establish a
TLS-PSK connection.

**Important caveat:** outstanding tokens minted in the previous hour
are NOT revoked. Tokens live their full TTL regardless. If you need
hard cutoff:

- Remove the repository from the App's access set on github.com.
  This prevents any NEW mints for that repo from anywhere but does
  not revoke outstanding tokens.
- If a compromise is suspected, regenerate the App private key on
  github.com (this revokes the App's ability to issue new tokens
  entirely; existing minted tokens still live out their TTL). Then
  update `/etc/gcb/github-app.pem` on the broker and **restart the
  daemon**: the App key is loaded at startup and is not
  hot-reloadable.

To revoke all clients at once: stop `stunnel`. Clients can no longer
connect. Restart when the situation is resolved.

## Updating

To deploy a new release:

```sh
VERSION=v0.2.0
TARGET=x86_64-unknown-linux-musl
BASE=https://github.com/<you>/gcb/releases/download/${VERSION}
curl -fsSLO "${BASE}/gcb-${TARGET}"
curl -fsSLO "${BASE}/gcb-${TARGET}.sha256"
sha256sum -c "gcb-${TARGET}.sha256"

install -o root -g root -m 0755 "gcb-${TARGET}" /usr/local/bin/gcb
rc-service gcb restart
sudo -u gcb gcb github selfcheck
```

The daemon's shutdown is graceful: on SIGTERM it stops accepting
new connections, drains in-flight handlers with a 5-second deadline,
then exits. Restart latency is typically <1 second for an idle
broker.

Read the release notes before upgrading across a minor version; config
format changes will be called out there.

## Backup

What to back up:

- `/etc/gcb/config.toml` — operator-authored.
- `/etc/gcb/clients.json` — machine-authored; can be regenerated by
  re-enrolling but timestamps are useful for forensics.
- `/etc/gcb/github-app.pem` — the App private key. Treat as a secret;
  back up to a place at least as protected as the broker itself.
- `/etc/stunnel/gcb.psk` — per-client PSKs. Treat as a secret;
  back up to a place at least as protected as the broker itself.
  Restoring this alone is sufficient to keep existing clients
  working without re-enrolling.

What NOT to back up:

- Logs in `/var/log/gcb.log` — useful for forensics but not for
  recovery. Ship them off-host via your log pipeline if you want
  retention.