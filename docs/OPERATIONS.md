# Operating `symbolon`

Day-to-day operator reference. For a fresh deployment, see
[INSTALL.md](INSTALL.md). For design rationale, see
[../AGENTS.md](../AGENTS.md). For wire formats and schemas, see
[PROTOCOLS.md](PROTOCOLS.md).

## Commands

All commands run on the broker host as the `symbolon` user (or via
`sudo -u symbolon`).

### Provider-agnostic

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

### GitHub provider

```
symbolon github enroll <client> --ip <ip> [--note <text>]
    Generate a per-client PSK, append to stunnel's psk file and
    clients.json (both atomically), SIGHUP stunnel, and print a
    paste-ready provisioning snippet to stdout.

symbolon github revoke <client>
    Remove the client's GitHub enrollment. If the client has no
    remaining provider enrollments, remove from clients.json and
    stunnel.psk entirely. SIGHUP stunnel.

    NOTE: Outstanding tokens minted in the past hour are NOT
    revoked. They live out their full TTL.

symbolon github mint <client> <owner/repo>
    Test path: run the full mint flow as if <client> requested a
    token for <owner/repo>. Prints token and expiry to stdout.
    Useful for verifying provider-side state without spinning up
    a client.

symbolon github selfcheck
    Verify the App private key parses, the App ID matches the JWT,
    api.github.com (or your GHES api_base) is reachable, and clock
    skew is bounded. Exits non-zero on any failed check.
```

## Logging

Structured JSON to stdout, one record per line. Schema and event
catalog: [PROTOCOLS.md §"Logging schema"](PROTOCOLS.md#logging-schema).

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
landlock + seccomp.

```jsonc
{"evt":"sandbox_applied","policy":"best_effort","abi":6,
 "status":"fully_enforced","fs":true,"tcp":true,"scope":true,"seccomp":true}
```

- `status: "fully_enforced"` → all of FS, TCP-connect scoping,
  abstract-UDS scope, and the seccomp signal filter are active.
  Logged at `info`.
- `status: "partially_enforced"` → some features were downgraded
  because the kernel doesn't support them. The per-subsystem booleans
  show which. Logged at `warn`. Common cause: kernel < 6.10, so
  scope is dropped.
- `status: "not_enforced"` → kernel has no landlock at all. Logged at
  `warn`. The seccomp filter still applies (`seccomp: true`).
- `status: "off"` → `[security] sandbox = "off"` in `config.toml`.
  Logged at `info`. There is no sandboxing of any kind.

To verify the running process is actually sandboxed:

```sh
PID=$(pgrep -f 'symbolon$')
grep -E 'Seccomp|NoNewPrivs' /proc/$PID/status
# Expect: Seccomp: 2  and  NoNewPrivs: 1
```

## Troubleshooting

### `git clone` fails with "Authentication failed" or similar

Walk the chain end to end.

**1. Is the daemon running and healthy?**

```sh
sudo -u symbolon symbolon status
sudo -u symbolon symbolon github selfcheck
```

If `selfcheck` fails: the daemon can't reach the provider, the App
key is wrong, or clock skew is large. The output names which.

**2. Is stunnel listening, and is the daemon's socket present?**

```sh
rc-service stunnel status        # or `systemctl status stunnel`
ss -tlnp | grep ':9418'          # stunnel should be listening here
ls -l /run/symbolon/daemon.sock       # owner symbolon:symbolon, mode 0660
```

If the socket is missing after a reboot: see [INSTALL.md §3.9](INSTALL.md)
(`/run` is tmpfs, cleared at boot — `checkpath` / `tmpfiles.d` must
recreate `/run/symbolon`). If the socket exists but stunnel can't connect,
verify `stunnel` is in the `symbolon` group: `id stunnel`.

**3. Can the client reach the broker over TLS-PSK?**

From the client:

```sh
openssl s_client -tls1_2 -cipher PSK \
  -psk_identity dev-vm-1 -psk "$(cat /etc/symbolon/psk)" \
  -connect broker.lan:9418 -quiet < /dev/null
```

A clean handshake with no output (and exit 0 given `< /dev/null`)
means TLS is fine and the daemon closed because there was no request.
If handshake fails: PSK mismatch, or network path blocked.

**4. Can a mint succeed end to end?**

From the broker:

```sh
sudo -u symbolon symbolon github mint dev-vm-1 octocat/Spoon-Knife
```

This bypasses the client transport and runs the mint logic directly.
If this fails, the issue is provider-side, not transport-side.

**5. What does the daemon log say?**

```sh
tail -f /var/log/symbolon.log | jq -c .
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
- **`sandbox_applied status=not_enforced` or `partially_enforced`**:
  the kernel doesn't support the requested landlock features. Check
  `uname -r` (need 6.10+ for full ABI 6) and
  `grep landlock /sys/kernel/security/lsm`. If the host kernel is
  fine but you're in an LXC container, confirm the container hasn't
  masked `/sys/kernel/security/`. Set `[security] sandbox = "required"`
  to make the daemon refuse to start on hosts that can't enforce.

## Sandbox: scope of protection and limitations

The broker self-sandboxes at startup with landlock (FS read/write
allowlist + outbound TCP-connect restricted to port 443 + abstract
Unix-socket scope) and a seccomp-BPF filter that confines the
kill-family syscalls (`kill`, `tkill`, `tgkill`,
`pidfd_send_signal`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`) so
their `sig` argument must equal `SIGHUP` — every other signal is
denied with EPERM.

**What this prevents** if a dependency CVE ever lets code execute
inside the daemon:
- Re-reading the App PEM key off disk (the key was loaded once at
  startup and the PEM dir is unreachable post-sandbox).
- Reading or modifying anything outside the small allowlist (state
  files, stunnel pidfile, `/dev/urandom`, CA bundle, nameservice
  files).
- Binding a TCP listener, or connecting outbound to anywhere other
  than port 443.
- Sending any signal that isn't SIGHUP.

**Known limitations:**
- The seccomp filter does NOT pin the *target* PID — it only checks
  the signum. A compromised broker could still SIGHUP some other
  process owned by the `symbolon` UID. In typical deployments stunnel is
  the only such process, but operators co-locating daemons under
  `symbolon` should be aware.
- The atomic-write directory grant on `/var/lib/symbolon/` covers
  everything in that directory. A post-compromise process could
  overwrite `clients.json` (which the daemon already self-rewrites).
  The PEM key is protected because it lives outside this dir.
- Landlock's `Scope::Signal` is deliberately omitted because stunnel
  is started by init (outside the broker's Landlock domain) and the
  broker must keep being able to SIGHUP it. The seccomp filter above
  is the substitute for that piece of the protection.
- If you want host-policy enforcement *in addition* to landlock
  (per-target signal scoping, per-process syscall scope, etc.), layer
  AppArmor or SELinux from the LXC config. This is out of scope for
  the broker itself.

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
levels) against `symbolon`'s `accept`/`mint` events by timestamp.

## Hardening recommendations

The per-mint scoping (`repository_ids: [one_repo]` plus
`contents: write` + `metadata: read`) is the narrowest permission
set GitHub will issue for a token that can push commits. Within
that scope, a compromised token can do more than `git push` —
notably, manage releases (create, edit, delete release records,
replace release assets, move release tags). These capabilities
can be mitigated at the GitHub side without changing the broker.
They are recommended for any repository the broker is allowed to
mint for, especially if that repository publishes release
artifacts trusted by downstream consumers.

### Enable Immutable Releases (per repository)

Settings → General → Releases → **Enable release immutability**.

Once enabled, every release published from that point forward is
immutable: assets cannot be added, modified, or deleted, and the
release's tag is locked to its publication commit. Existing
releases remain mutable unless re-published. Release attestations
(Sigstore-signed) are generated automatically; consumers can
verify with `gh release verify <tag>` or
`gh release verify-asset <tag> <file>`.

Available on all GitHub plans including Free. See the [official
documentation](https://docs.github.com/en/enterprise-cloud@latest/code-security/concepts/supply-chain-security/immutable-releases).

### Restrict creation of release tags (per repository)

Settings → Rules → New ruleset → **New tag ruleset**.

- **Target tags**: pattern matching your release tags (e.g. `v*`).
- **Bypass list**: keep `Repository admin` only. Do NOT add the
  broker's GitHub App.
- **Tag rules**: enable **Restrict creations**, **Restrict
  updates**, **Restrict deletions**, and **Block force pushes**.

The broker's tokens act as the App identity, not as the
repository admin, so they cannot create, update, or delete tags
matching the release pattern. Legitimate release tagging
continues to work from contexts that authenticate as the admin
(your local clone, a GitHub Actions workflow, etc.).

Combined with Immutable Releases above, this closes both the
release-asset-tampering vector (existing releases) and the
rogue-release-creation vector (new releases) on the GitHub side.

#### Plan-tier caveat

Repository rulesets are enforced on:
- Any **public** repository (all plans, including Free).
- **Private** repositories on GitHub Pro, Team, or Enterprise
  Cloud.

On Free accounts, rulesets created on **private** repositories
save successfully and appear in the UI, but are not enforced;
GitHub shows a banner indicating this. If the repository is
private and the account is on the Free tier, the protection
takes effect only after the repo is made public or the plan is
upgraded.

## Revocation

To revoke a single client:

```sh
sudo -u symbolon symbolon github revoke <client>
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
  update `/etc/symbolon/github-app.pem` on the broker and **restart the
  daemon**: the App key is loaded at startup and is not
  hot-reloadable.

To revoke all clients at once: stop `stunnel`. Clients can no longer
connect. Restart when the situation is resolved.

## Updating

To deploy a new release:

```sh
VERSION=v0.2.0
TARGET=x86_64-unknown-linux-musl
BASE=https://github.com/<you>/symbolon/releases/download/${VERSION}
curl -fsSLO "${BASE}/symbolon-${TARGET}"
curl -fsSLO "${BASE}/symbolon-${TARGET}.sha256"
sha256sum -c "symbolon-${TARGET}.sha256"

install -o root -g root -m 0755 "symbolon-${TARGET}" /usr/local/bin/symbolon
rc-service symbolon restart
sudo -u symbolon symbolon github selfcheck
```

The daemon's shutdown is graceful: on SIGTERM it stops accepting
new connections, drains in-flight handlers with a 5-second deadline,
then exits. Restart latency is typically <1 second for an idle
broker.

Read the release notes before upgrading across a minor version; config
format changes will be called out there.

## Backup

What to back up:

- `/etc/symbolon/config.toml` — operator-authored.
- `/var/lib/symbolon/clients.json` — machine-authored; can be regenerated
  by re-enrolling but timestamps are useful for forensics.
- `/etc/symbolon/github-app.pem` — the App private key. Treat as a secret;
  back up to a place at least as protected as the broker itself.
- `/etc/stunnel/symbolon.psk` — per-client PSKs. Treat as a secret;
  back up to a place at least as protected as the broker itself.
  Restoring this alone is sufficient to keep existing clients
  working without re-enrolling.

What NOT to back up:

- Logs in `/var/log/symbolon.log` — useful for forensics but not for
  recovery. Ship them off-host via your log pipeline if you want
  retention.