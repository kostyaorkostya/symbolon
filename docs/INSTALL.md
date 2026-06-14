# Installing `symbolon`

How-to — fresh-deployment guide. Operational details (commands,
paths, packaging) drift over time; the stable explanation is
elsewhere.

| Doc | Mode |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Explanation — how the system works |
| [`PROTOCOLS.md`](PROTOCOLS.md) | Reference — wire / file / log schemas |
| [`PROVIDER_CONTRACT.md`](PROVIDER_CONTRACT.md) | Reference — RFC-2119 provider contract |
| [`OPERATIONS.md`](OPERATIONS.md) | How-to — day-to-day operations |
| [`providers/`](providers/) | Per-provider setup (App creation, config block) |
| [`../AGENTS.md`](../AGENTS.md) | Agent guidance — design + style |

## 1. Prerequisites

- A trusted LAN where the broker and clients can reach each other.
  Client identity is proven cryptographically (Noise NNpsk0), so
  client IPs may change freely (DHCP is fine).
- A host for the broker. Any small Linux environment works; an
  Alpine LXC is a common choice. The host needs:
  - Outbound HTTPS to the configured provider API.
  - Enough headroom for a ~3 MiB daemon. No TLS proxy needed —
    symbolon terminates Noise NNpsk0 in-process.
  - **Linux kernel 6.12+** recommended. The broker self-sandboxes
    with Landlock at ABI 6: FS allowlist, outbound TCP-connect
    to port 443, abstract-UDS scope, and `Scope::Signal` (Linux
    6.12+) denying cross-process signal-sending. Kernels
    6.10–6.11 work but degrade the signal scope; the daemon
    emits `evt=sandbox_applied status=partially_enforced` so the
    operator notices. Check with `uname -r`; check Landlock LSM
    is enabled with `grep landlock /sys/kernel/security/lsm`. In
    an LXC container, the host kernel is what counts.
- On each client: `git` and the ability to drop a small binary
  (`git-credential-symbolon`) in `/usr/local/bin/` plus a single
  PSK file at `/etc/symbolon/psk`.

## 2. Per-provider setup

Before deploying the broker, complete the setup for the provider
you'll use — you'll need its private key file and identifiers to
fill in `config.toml` below.

- **GitHub** → [providers/github.md](providers/github.md).

## 3. Set up the broker host

Examples below assume an Alpine LXC. Adapt commands for
Debian/Ubuntu (`apt`, `useradd`, systemd init) as needed.

### 3.1 Install packages

```sh
apk add ca-certificates
```

### 3.2 Create users, groups, directories

```sh
addgroup -S symbolon
adduser  -S -G symbolon -H -D -s /sbin/nologin symbolon

install -d -o symbolon -g symbolon -m 0700 /etc/symbolon
install -d -o symbolon -g symbolon -m 0700 /var/lib/symbolon
install -d -o symbolon -g symbolon -m 0750 /run/symbolon
```

`/etc/symbolon/` holds the provider private key and `config.toml`
(read-only at runtime); `/var/lib/symbolon/` holds `clients.json`
AND the symbolon-owned `psks` file (both mutated atomically by the
daemon). They are kept separate because the daemon's landlock
ruleset grants write access to `/var/lib/symbolon/`; putting the
provider key under that dir would defeat the sandbox's protection
of the key.

The `/run/symbolon` directory is recreated on every boot — see
§3.8/§3.9.

### 3.3 Fetch and verify the binary

```sh
VERSION=v0.1.0
TARGET=x86_64-unknown-linux-musl   # or aarch64-unknown-linux-musl
BASE=https://github.com/kostyaorkostya/symbolon/releases/download/${VERSION}

curl -fsSLO "${BASE}/symbolon-${TARGET}"
curl -fsSLO "${BASE}/symbolon-${TARGET}.sha256"
sha256sum -c "symbolon-${TARGET}.sha256"
install -o root -g root -m 0755 "symbolon-${TARGET}" /usr/local/bin/symbolon
```

### 3.4 Place the provider private key

Path and file format are per-provider; see your provider doc. For
GitHub:

```sh
install -o symbolon -g symbolon -m 0400 /path/to/github-app.pem /etc/symbolon/github-app.pem
```

### 3.5 Write `config.toml`

`/etc/symbolon/config.toml` (full schema in
[PROTOCOLS.md](PROTOCOLS.md); per-provider blocks in
[providers/](providers/)):

```toml
[listen]
# TCP address the daemon binds for inbound client connections.
# 0.0.0.0:9418 = git smart-http port; pick another if you're
# already using 9418 for something else.
bind = "0.0.0.0:9418"
# Symbolon-owned PSK store (`identity:hex_psk` per line, mode 0600).
# Mutated atomically on enroll/revoke.
psk_file = "/var/lib/symbolon/psks"

[admin]
socket_path = "/run/symbolon/admin.sock"

[clients]
file = "/var/lib/symbolon/clients.json"

[logging]
level = "info"

# Optional. Defaults to `sandbox = "best_effort"` with no extra dirs.
# Uncomment and set `extra_read_dirs = ["/etc/pki/tls/certs"]` on
# RHEL/Fedora where OpenSSL's CA roots live outside /etc/ssl/certs.
# [security]
# sandbox = "best_effort"
# extra_read_dirs = []

# Per-provider section — one per provider you've set up.
# Field reference: per-provider docs under docs/providers/.
[provider.github]
host = "github.com"
api_base = "https://api.github.com"
client_id = "Iv23liABCDEFGHIJklmn"
installation_id = 789012
private_key_path = "/etc/symbolon/github-app.pem"
selfcheck_timeout = "5s"
```

```sh
chown symbolon:symbolon /etc/symbolon/config.toml
chmod 0600    /etc/symbolon/config.toml
```

### 3.6 Initialize state files

```sh
echo '{"version":1,"clients":[]}' > /var/lib/symbolon/clients.json
chown symbolon:symbolon /var/lib/symbolon/clients.json
chmod 0600    /var/lib/symbolon/clients.json

install -o symbolon -g symbolon -m 0600 /dev/null /var/lib/symbolon/psks
```

Both files are mutated atomically by the daemon (tempfile + fsync
+ rename) — never hand-edit while the daemon is running unless
recovering from corruption.

### 3.7 Optional: IP-level filtering

Symbolon's access control is the per-client PSK and the Noise
NNpsk0 handshake — a connection that doesn't present a known
identity and the matching PSK never completes the handshake,
regardless of where it originated. **IP-based filtering is
optional defense-in-depth, not required.** The daemon binds
`0.0.0.0:9418` deliberately so it works behind any LAN topology
(DHCP clients, NAT, container bridges).

Three deployment patterns when you do want a network-level layer:

**Bare metal — host-level nftables on the broker.** Replace
`<lan-cidr>` with your trusted LAN (e.g. `192.168.122.0/24`):

```sh
nft -f - <<'EOF'
table inet symbolon {
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

**libvirt VM — apply [`clean-traffic`](https://libvirt.org/firewall.html)
at the host bridge.** The filter runs in the host's network
namespace, so the guest doesn't need any in-VM nft rules and
can't disable the policy from inside.

**LXC / Docker / Incus containers — apply filtering at the bridge
layer on the host, NOT inside the container.** Unprivileged
containers typically can't load nftables rules under their user
namespace — `nft -f` will either silently no-op or fail with a
permission error. For Incus: `security.ipv4_filtering=true` /
`security.ipv6_filtering=true` on the instance. For Docker: the
default bridge anti-spoof behaviour. For raw LXC: whatever your
bridge driver supports.

### 3.8 Install and start the daemon (OpenRC)

`/etc/init.d/symbolon`:

```sh
#!/sbin/openrc-run
name="symbolon"
command="/usr/local/bin/symbolon"
command_args="daemon"
command_user="symbolon:symbolon"
command_background=yes
pidfile="/run/symbolon/symbolon.pid"
output_log="/var/log/symbolon.log"
error_log="/var/log/symbolon.log"

depend() {
    need net
    after net
}

# /run is tmpfs and is cleared at every boot; re-create the daemon's
# runtime directory before starting. checkpath is idempotent.
start_pre() {
    checkpath -d -m 0750 -o symbolon:symbolon /run/symbolon
}
```

```sh
chmod +x /etc/init.d/symbolon
rc-update add symbolon default
rc-service symbolon start
```

### 3.9 systemd alternative

If you deploy under systemd instead, the equivalent of `start_pre +
checkpath` is `tmpfiles.d`. Drop `/usr/lib/tmpfiles.d/symbolon.conf`:

```
d /run/symbolon 0750 symbolon symbolon -
```

systemd-tmpfiles creates the directory at boot and on demand.
Without this entry, the daemon will fail to start after a reboot
with a permission error when binding its socket.

A minimal systemd unit (`/etc/systemd/system/symbolon.service`):

```ini
[Unit]
Description=git credentials broker
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/symbolon daemon
User=symbolon
Group=symbolon
# Required for `[security] mlock = "best_effort"` (the default).
# Without it, mlockall fails with EAGAIN under the per-user
# 64 KB default ulimit; daemon logs `evt=mlock status=skipped`
# and continues without anti-swap hardening.
LimitMEMLOCK=infinity
# Suppress coredumps so the provider private key, in-flight JWTs,
# and freshly-minted tokens can't leak via core files in
# /var/lib/systemd/coredump/ after a process crash. Complements
# LimitMEMLOCK=infinity above on the secrets-don't-touch-disk
# axis: that one prevents pages reaching swap, this one prevents
# them reaching dump files.
LimitCORE=0

[Install]
WantedBy=multi-user.target
```

**Primary anti-swap defence: disable swap on the broker host.**
This is industry standard for daemons holding long-lived secrets
(nginx, haproxy, envoy all assume it). `symbolon`'s
`[security] mlock` is belt-and-suspenders on top of swap-disable,
not a substitute. To disable swap:

```sh
swapoff -a
# Comment out swap entries in /etc/fstab so it stays off across reboots.
```

`Type=notify` makes systemd wait for the daemon's
`sd_notify(READY=1)` call before marking the service active.
**Leave `[runtime] pidfile` unset in `config.toml` under
systemd** — `Type=notify` covers readiness; modern systemd man
pages discourage pidfiles when notify is available.

**OpenRC: also leave `[runtime] pidfile` unset.**
`command_background=yes` + `pidfile=...` in the init script tells
OpenRC's `start-stop-daemon` to create and manage the pidfile via
`--make-pidfile` from the supervisor side. A daemon-side pidfile
would be redundant and would force the pidfile's parent directory
into the Landlock write-allowlist for no benefit.

### 3.10 Verify

```sh
symbolon status
symbolon github selfcheck
```

`selfcheck` should report the provider reachable and clock skew
small. Exit code 0 means everything's good. (CLI commands talk to
the daemon over its admin Unix socket, which is locked down by
SO_PEERCRED to root or the daemon's UID — run the commands as one
of those.)

## 4. Enroll a client

### 4.1 On the broker host

```sh
symbolon github enroll dev-vm-1
```

(Replace `github` with the provider key you configured, and
`dev-vm-1` with whatever stable name you want for the client.)

The output is a paste-ready snippet containing:

- The PSK hex string (for the client's `/etc/symbolon/psk`).
- The exact `git config` command to install the helper.

### 4.2 On the client

Install the bundled helper binary (cross-compiled for musl, same
release tarball as the daemon):

```sh
VERSION=v0.1.0
TARGET=x86_64-unknown-linux-musl   # or aarch64-unknown-linux-musl
BASE=https://github.com/kostyaorkostya/symbolon/releases/download/${VERSION}

curl -fsSLO "${BASE}/git-credential-symbolon-${TARGET}"
curl -fsSLO "${BASE}/git-credential-symbolon-${TARGET}.sha256"
sha256sum -c "git-credential-symbolon-${TARGET}.sha256"
install -o root -g root -m 0755 \
  "git-credential-symbolon-${TARGET}" /usr/local/bin/git-credential-symbolon
```

Drop the PSK from the enroll output:

```sh
install -d -o root -g root -m 0700 /etc/symbolon
echo '<HEX-PSK-FROM-ENROLL>' > /etc/symbolon/psk
chmod 0400 /etc/symbolon/psk
```

Configure git to use the helper (replace `<broker-host>` and
`dev-vm-1` with the values from the enroll output; the
`credential.https://<host>.helper` URL stem matches the provider
host you configured in `config.toml`):

```sh
git config --global credential.https://github.com.helper \
  "/usr/local/bin/git-credential-symbolon \
   --endpoint <broker-host>:9418 \
   --identity dev-vm-1 \
   --psk-file /etc/symbolon/psk"
```

### 4.3 Verify

```sh
git clone https://github.com/<owner>/<repo>
```

If this works, you're done. Operator commands, logging, and
troubleshooting are in [OPERATIONS.md](OPERATIONS.md). Per-provider
specifics (hardening, incident response) are in
[providers/](providers/).
