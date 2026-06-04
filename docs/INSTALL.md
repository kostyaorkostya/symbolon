# Installing `gcb`

This guide covers a fresh deployment: setting up the GitHub App, the
broker host, and a first client. Adapt to your environment as needed.

This document is **operational** and will go out of date as releases,
package versions, and provider UIs change. The stable design lives in
[AGENTS.md](../AGENTS.md); wire formats and schemas live in
[PROTOCOLS.md](PROTOCOLS.md).

## 1. Prerequisites

- A trusted LAN where the broker and clients can reach each other and
  where source IP can be reasonably attested. This typically means
  libvirt with [`clean-traffic` filterref](https://libvirt.org/firewall.html)
  plus host-bridge nftables anti-rogue-DHCP, or an equivalent.
- A GitHub account where you can create a GitHub App.
- A host for the broker. Any small Linux environment works; an Alpine
  LXC is a common choice. The host needs:
  - [`stunnel`](https://www.stunnel.org/) package available.
  - Outbound HTTPS to `api.github.com` (or your GHES API base).
  - Enough headroom for a ~3 MiB daemon plus `stunnel`.
  - **Linux kernel 6.10+** recommended. The broker self-sandboxes
    with landlock (FS + TCP-connect + abstract-UDS scope at ABI 6)
    plus a seccomp-BPF filter scoping the kill-family syscalls to
    `SIGHUP` only. Older kernels degrade under the default
    `[security] sandbox = "best_effort"` policy and the daemon emits
    `evt=sandbox_applied lvl=warn status=partially_enforced` so the
    operator notices. Check with `uname -r`; check landlock LSM is
    enabled with `grep landlock /sys/kernel/security/lsm`. In an LXC
    container, the host kernel is what counts.
- On each client: `openssl`, `git`, and the ability to drop a small
  shell script and a config file in place.

## 2. Create the GitHub App

On github.com:

1. Settings → Developer settings → GitHub Apps → **New GitHub App**.
2. Permissions:
   - **Contents: Read & Write**
   - **Metadata: Read** (mandatory floor for any App)
   - **Nothing else.** Do NOT add `Workflows`, `Actions`,
     `Pull requests`, `Issues`, or anything else. The absence of
     `Workflows` is the load-bearing property that prevents a
     compromised client from pushing CI changes.
3. Webhook: disable. The broker does not consume webhooks.
4. Where can this App be installed? **Only on this account.**
5. Generate a private key; download the `.pem` file.
6. Install the App on your account. Note the **App ID** (top of the
   App settings page) and the **installation ID** (visible in the URL
   after installation, e.g. `/installations/789012`).
7. Choose **Only select repositories** and pick the ones you want the
   broker to be able to mint for. This is the working set — the
   broker will mint tokens for any of these. Keep it small.

For **GitHub Enterprise Server**: the same steps apply on your GHES
instance. The App ID and installation ID will differ from any public
github.com Apps.

## 3. Set up the broker host

Examples below assume an Alpine LXC. Adapt commands for Debian/Ubuntu
(`apt`, `useradd`, systemd init) as needed.

### 3.1 Install packages

```sh
apk add stunnel ca-certificates
```

### 3.2 Create users, groups, directories

```sh
addgroup -S gcb
adduser  -S -G gcb -H -D -s /sbin/nologin gcb

# stunnel runs as user `stunnel` by default. Add stunnel to the gcb
# group so it can connect to the daemon's Unix socket.
adduser  stunnel gcb   # Alpine; Debian/Ubuntu: `usermod -aG gcb stunnel`

install -d -o gcb -g gcb     -m 0700 /etc/gcb
install -d -o gcb -g gcb     -m 0700 /var/lib/gcb
install -d -o gcb -g gcb     -m 0750 /run/gcb
install -d -o gcb -g stunnel -m 0750 /etc/stunnel
```

`/etc/gcb/` holds the App PEM key and `config.toml` (read-only at
runtime); `/var/lib/gcb/` holds `clients.json` (mutated atomically by
the daemon). They are kept separate because the daemon's landlock
ruleset grants write access to `/var/lib/gcb/` (needed for the
tempfile-then-rename atomic-write pattern); putting the PEM key
under that dir would defeat the sandbox's protection of the key.

The `/run/gcb` directory is recreated on every boot — see §3.10.

**Upgrading from a pre-`/var/lib/gcb` layout:** if your existing
deployment places `clients.json` under `/etc/gcb/`, move it before
restarting the daemon and update `clients.file` in `config.toml`:

```sh
install -d -o gcb -g gcb -m 0700 /var/lib/gcb
mv /etc/gcb/clients.json /var/lib/gcb/clients.json
sed -i 's,/etc/gcb/clients.json,/var/lib/gcb/clients.json,' /etc/gcb/config.toml
```

### 3.3 Fetch and verify the binary

```sh
VERSION=v0.1.0
TARGET=x86_64-unknown-linux-musl   # or aarch64-unknown-linux-musl
BASE=https://github.com/<you>/gcb/releases/download/${VERSION}

curl -fsSLO "${BASE}/gcb-${TARGET}"
curl -fsSLO "${BASE}/gcb-${TARGET}.sha256"
sha256sum -c "gcb-${TARGET}.sha256"
install -o root -g root -m 0755 "gcb-${TARGET}" /usr/local/bin/gcb
```

### 3.4 Place the GitHub App private key

```sh
install -o gcb -g gcb -m 0400 /path/to/github-app.pem /etc/gcb/github-app.pem
```

### 3.5 Write `config.toml`

`/etc/gcb/config.toml` (schema in [PROTOCOLS.md](PROTOCOLS.md)):

```toml
[listen]
socket = "/run/gcb/daemon.sock"

[admin]
socket_path = "/run/gcb/admin.sock"

[clients]
file = "/var/lib/gcb/clients.json"

[stunnel]
psk_file = "/etc/stunnel/gcb.psk"
pidfile  = "/run/stunnel/stunnel.pid"   # must match `pid = …` in step 3.7

[logging]
level = "info"

# Optional. Defaults to `sandbox = "best_effort"` with no extra dirs.
# Uncomment and set `extra_read_dirs = ["/etc/pki/tls/certs"]` on
# RHEL/Fedora where OpenSSL's CA roots live outside /etc/ssl/certs.
# [security]
# sandbox = "best_effort"
# extra_read_dirs = []

[provider.github]
# For github.com, keep these defaults.
# For GitHub Enterprise Server, set:
#   host     = "github.example.com"
#   api_base = "https://github.example.com/api/v3"
host = "github.com"
api_base = "https://api.github.com"
app_id = 123456            # from step 2
installation_id = 789012   # from step 2
private_key_path = "/etc/gcb/github-app.pem"
```

```sh
chown gcb:gcb /etc/gcb/config.toml
chmod 0600    /etc/gcb/config.toml
```

### 3.6 Initialize state files

```sh
echo '{"version":1,"clients":[]}' > /var/lib/gcb/clients.json
chown gcb:gcb /var/lib/gcb/clients.json
chmod 0600    /var/lib/gcb/clients.json

install -o gcb -g stunnel -m 0640 /dev/null /etc/stunnel/gcb.psk
```

Both files are mutated atomically by the daemon (tempfile + fsync +
rename) — never hand-edit while the daemon is running unless
recovering from corruption.

### 3.7 Configure stunnel

`/etc/stunnel/stunnel.conf`:

```ini
foreground = no
pid = /run/stunnel/stunnel.pid
output = /var/log/stunnel/stunnel.log

[gcb]
accept = 0.0.0.0:9418
# Daemon listens on a Unix-domain socket; stunnel forwards plain TCP
# over the Unix socket and prepends a PROXY v2 header carrying the
# original TCP client's IP and port.
connect = /run/gcb/daemon.sock
PSKsecrets = /etc/stunnel/gcb.psk
ciphers = PSK
sslVersion = TLSv1.2
protocol = proxy
```

Enable and start:

```sh
rc-update add stunnel default
rc-service stunnel start
```

(systemd: `systemctl enable --now stunnel.service`.)

The path in `pid = …` must match `[stunnel] pidfile` in
`/etc/gcb/config.toml` — the daemon reads it to send `SIGHUP` after
`gcb github enroll`/`revoke` rewrites `gcb.psk`.

### 3.8 Lock down with nftables

The daemon listens on a Unix socket inside `/run/gcb`; only stunnel's
TCP listen needs LAN-scoped firewall coverage.

Replace `<lan-cidr>` with your trusted LAN (e.g. `192.168.122.0/24`):

```sh
nft -f - <<'EOF'
table inet gcb {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    tcp dport 9418 ip saddr <lan-cidr> accept
  }
}
EOF
```

Persist via your distro's nftables service.

### 3.9 Install and start the daemon (OpenRC)

`/etc/init.d/gcb`:

```sh
#!/sbin/openrc-run
name="gcb"
command="/usr/local/bin/gcb"
command_args="daemon"
command_user="gcb:gcb"
command_background=yes
pidfile="/run/gcb/gcb.pid"
output_log="/var/log/gcb.log"
error_log="/var/log/gcb.log"

depend() {
    need net
    after stunnel
}

# /run is tmpfs and is cleared at every boot; re-create the daemon's
# runtime directory before starting. checkpath is idempotent.
start_pre() {
    checkpath -d -m 0750 -o gcb:gcb /run/gcb
}
```

```sh
chmod +x /etc/init.d/gcb
rc-update add gcb default
rc-service gcb start
```

### 3.10 systemd alternative

If you deploy under systemd instead, the equivalent of `start_pre +
checkpath` is `tmpfiles.d`. Drop `/usr/lib/tmpfiles.d/gcb.conf`:

```
d /run/gcb 0750 gcb gcb -
```

systemd-tmpfiles creates the directory at boot and on demand. Without
this entry, the daemon will fail to start after a reboot with a
permission error when binding its socket.

A minimal systemd unit (`/etc/systemd/system/gcb.service`):

```ini
[Unit]
Description=git credentials broker
After=network-online.target stunnel.service
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/gcb daemon
User=gcb
Group=gcb

[Install]
WantedBy=multi-user.target
```

`Type=notify` makes systemd wait for the daemon's `sd_notify(READY=1)`
call before marking the service active. **Leave `[runtime] pidfile`
unset in `config.toml` under systemd** — `Type=notify` covers
readiness; modern systemd man pages discourage pidfiles when notify
is available.

OpenRC operators, by contrast, **must** set `[runtime] pidfile` to
match the init script's `pidfile=` (see §3.9).

### 3.11 Verify

```sh
sudo -u gcb gcb status
sudo -u gcb gcb github selfcheck
```

`selfcheck` should report the App ID matches the JWT, GitHub is
reachable, and clock skew is small. Exit code 0 means everything's
good.

## 4. Enroll a client

### 4.1 On the broker host

```sh
sudo -u gcb gcb github enroll dev-vm-1 --ip 192.168.122.10
```

Output is a paste-ready snippet showing:

- The PSK hex string (for the client's `/etc/gcb/psk`).
- The git-credential helper command line (for the client's
  `~/.gitconfig` or `/etc/gitconfig`).
- The host:port to use as `--endpoint`.

### 4.2 On the client

Place the PSK:

```sh
install -d -o root -g root -m 0700 /etc/gcb
echo '<HEX-PSK-FROM-ENROLL>' > /etc/gcb/psk
chmod 0400 /etc/gcb/psk
```

Install the credential helper:

```sh
cat > /usr/local/bin/git-credential-broker <<'EOF'
#!/bin/sh
endpoint= psk_file= identity= action=
while [ $# -gt 0 ]; do
  case "$1" in
    --endpoint)      endpoint=$2;  shift 2 ;;
    --psk-file)      psk_file=$2;  shift 2 ;;
    --identity)      identity=$2;  shift 2 ;;
    get|store|erase) action=$1;    shift   ;;
    *) shift ;;
  esac
done
[ "$action" = get ] || exit 0
exec openssl s_client -quiet -tls1_2 -cipher PSK \
  -psk_identity "$identity" -psk "$(cat "$psk_file")" \
  -connect "$endpoint" 2>/dev/null
EOF
chmod 0755 /usr/local/bin/git-credential-broker
```

Configure git to use the helper for github.com (replace values with
those from the enroll output):

```sh
git config --global credential.https://github.com.helper \
  "/usr/local/bin/git-credential-broker --endpoint broker.lan:9418 --psk-file /etc/gcb/psk --identity dev-vm-1"
```

### 4.3 Verify

```sh
git clone https://github.com/<owner>/<repo>
```

If this works, you're done. If not, see
[OPERATIONS.md](OPERATIONS.md) for troubleshooting.

## 5. Day two

Operator commands, log inspection, troubleshooting, and revocation
are covered in [OPERATIONS.md](OPERATIONS.md).