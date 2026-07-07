# Installing `symbolon`

Fresh-deployment guide. Commands, paths, and packaging drift
over time; the stable explanation is elsewhere.

See also:

- [`ARCHITECTURE.md`](ARCHITECTURE.md): how the system works.
- [`PROTOCOLS.md`](PROTOCOLS.md): wire, file, log schemas.
- [`PROVIDER_CONTRACT.md`](PROVIDER_CONTRACT.md): RFC-2119
  provider contract.
- [`OPERATIONS.md`](OPERATIONS.md): day-to-day operations.
- [`providers/`](providers/): per-provider setup (App creation,
  config block).
- [`../AGENTS.md`](../AGENTS.md): design and style notes for
  contributors.

## 1. Prerequisites

- A trusted LAN where the broker and clients can reach each other.
  Client identity is proven cryptographically (Noise NKpsk2), so
  client IPs may change freely (DHCP is fine).
- A host for the broker. Any small Linux environment works; an
  Alpine LXC is a common choice. The host needs:
  - Outbound HTTPS to the configured provider API.
  - Enough headroom for a ~3 MiB daemon. No TLS proxy needed;
    symbolon terminates Noise NKpsk2 in-process.
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
  key file at `/etc/symbolon/key` (broker public key + PSK).

## 2. Per-provider setup

Before deploying the broker, complete the setup for the provider
you'll use. You'll need its private key file and identifiers to
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

`/etc/symbolon/` holds the provider private key, the broker
static key, and `config.toml` (read-only at runtime);
`/var/lib/symbolon/` holds `clients.json` AND the symbolon-owned
`psks` file (both mutated atomically by the daemon). They are kept
separate because the daemon's landlock ruleset grants write access
to `/var/lib/symbolon/`; putting either key under that dir would
defeat the sandbox's protection of the keys.

The `/run/symbolon` directory is recreated on every boot — under
systemd by the `.service` unit's `RuntimeDirectory=symbolon` (§3.10),
under OpenRC by the init script's `start_pre` + `checkpath` (§3.11).
The `install -d` above seeds it for the first start before either
supervisor is wired up.

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

### 3.5 Generate the broker static key

The broker's Noise NKpsk2 identity is a static X25519 keypair. The
private half is 32 random bytes — any 32-byte value is a valid
X25519 key — stored as 64 hex chars on one line:

```sh
umask 277
openssl rand -hex 32 > /etc/symbolon/broker.key
chown symbolon:symbolon /etc/symbolon/broker.key
```

There is no keygen subcommand and no rotation machinery: the
daemon derives the public half at startup (retrieve it later with
`symbolon pubkey`), and replacing the key means updating every
client's key file (see
[OPERATIONS.md § Suspected broker compromise](OPERATIONS.md#suspected-broker-compromise)).

### 3.6 Write `config.toml`

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
# Broker static X25519 private key (generated in §3.5).
static_key_file = "/etc/symbolon/broker.key"

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

# Per-provider section. One per provider you've set up.
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

### 3.7 Initialize state files

```sh
echo '{"clients":[]}' > /var/lib/symbolon/clients.json
chown symbolon:symbolon /var/lib/symbolon/clients.json
chmod 0600    /var/lib/symbolon/clients.json

install -o symbolon -g symbolon -m 0600 /dev/null /var/lib/symbolon/psks
```

Both files are mutated atomically by the daemon (tempfile + fsync
+ rename). Never hand-edit while the daemon is running unless
recovering from corruption.

### 3.8 Optional: IP-level filtering

Symbolon's access control is the per-client PSK and the Noise
NKpsk2 handshake. A connection that doesn't present a known
identity and the matching PSK never completes the handshake,
regardless of where it originated. **IP-based filtering is
optional defense-in-depth, not required.** The daemon binds
`0.0.0.0:9418` deliberately so it works behind any LAN topology
(DHCP clients, NAT, container bridges).

Three deployment patterns when you do want a network-level layer:

**Bare metal: host-level nftables on the broker.** Replace
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

**libvirt VM: apply [`clean-traffic`](https://libvirt.org/firewall.html)
at the host bridge.** The filter runs in the host's network
namespace, so the guest doesn't need any in-VM nft rules and
can't disable the policy from inside.

**LXC / Docker / Incus containers: apply filtering at the bridge
layer on the host, NOT inside the container.** Unprivileged
containers can't load nftables rules under their user
namespace; `nft -f` will either silently no-op or fail with a
permission error. For Incus: `security.ipv4_filtering=true` /
`security.ipv6_filtering=true` on the instance. For Docker: the
default bridge anti-spoof behaviour. For raw LXC: whatever your
bridge driver supports.

### 3.9 Socket activation: the supervisor binds, the daemon inherits

**`symbolon daemon` does NOT bind sockets itself.** Both the inbound
TCP listener (`:9418`) and the admin UDS (`/run/symbolon/admin.sock`)
are obtained via the `LISTEN_FDS` env protocol from a supervisor:

- under **systemd**, via a `.socket` unit (§3.10);
- under **OpenRC** (or any non-systemd init), via the
  [`systemfd`](https://github.com/mitsuhiko/systemfd) wrapper (§3.11).

A plain `symbolon daemon` invocation with no supervisor exits
immediately with `evt=run_failed` and an `EnvFdTake` error message
naming the missing `LISTEN_FDS` env var. This is by design — the
supervisor owns socket lifecycle, perms, and unlink; the daemon owns
the per-connection logic.

### 3.10 systemd (`.socket` + `.service`)

The runtime directory is created by systemd via the `.service`
unit's `RuntimeDirectory=` (no `tmpfiles.d` needed).

**`/etc/systemd/system/symbolon.socket`:**

```ini
[Unit]
Description=git credentials broker sockets

[Socket]
ListenStream=0.0.0.0:9418
ListenStream=/run/symbolon/admin.sock
SocketMode=0600
SocketUser=symbolon
SocketGroup=symbolon
Backlog=128
BindIPv6Only=both

[Install]
WantedBy=sockets.target
```

The two `ListenStream=` entries must appear in this order — the
daemon takes slot 0 as the TCP wire and slot 1 as the admin UDS.
`SocketMode=0600` applies only to the UDS (TCP sockets ignore it).

**`/etc/systemd/system/symbolon.service`:**

```ini
[Unit]
Description=git credentials broker
Requires=symbolon.socket
After=symbolon.socket network-online.target
Wants=network-online.target

[Service]
Type=notify
Sockets=symbolon.socket
ExecStart=/usr/local/bin/symbolon daemon
User=symbolon
Group=symbolon
RuntimeDirectory=symbolon
RuntimeDirectoryMode=0750
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

Enable both units; systemd will start the daemon on first connection
(socket activation) or at boot if you `systemctl enable` the service:

```sh
systemctl enable --now symbolon.socket symbolon.service
```

### 3.11 OpenRC + `systemfd`

OpenRC has no native socket-activation analogue, so the daemon runs
under the [`systemfd`](https://github.com/mitsuhiko/systemfd) wrapper.
`systemfd` binds the sockets, sets `LISTEN_FDS` / `LISTEN_PID`, and
execs the daemon — same `LISTEN_FDS` protocol the daemon already
understands.

Install `systemfd` (cargo or your distro's package):

```sh
cargo install systemfd
# or, on Alpine: apk add systemfd  (when packaged)
```

**`/etc/init.d/symbolon`:**

```sh
#!/sbin/openrc-run
name="symbolon"
description="git credentials broker"
command="/usr/local/bin/systemfd"
command_args="--no-pid -b 128 -s tcp::0.0.0.0:9418 -s unix::/run/symbolon/admin.sock -- /usr/local/bin/symbolon daemon"
command_user="symbolon:symbolon"
supervisor="supervise-daemon"
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

The `-s` flag arguments must appear in this order — the daemon takes
slot 0 as the TCP wire and slot 1 as the admin UDS.

**Caveat: socket mode under OpenRC.** Unlike systemd's
`SocketMode=0600`, `systemfd` does not chmod the UDS — it inherits
the daemon process's umask (typically `0o755` for sockets). Access
control falls entirely on the `/run/symbolon/` directory mode
(`0o750 root:symbolon`, per `start_pre`'s `checkpath`). This matches
the broker's threat model — the directory mode is the primary gate —
but is worth knowing if you ever loosen the directory perms.

```sh
chmod +x /etc/init.d/symbolon
rc-update add symbolon default
rc-service symbolon start
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
**Leave `[runtime] pidfile` unset in `config.toml`** under both
systemd and OpenRC. Modern systemd man pages discourage pidfiles
when `Type=notify` is available, and OpenRC's `supervise-daemon`
manages PIDs from the supervisor side. A daemon-side pidfile
would be redundant and would force the pidfile's parent directory
into the Landlock write-allowlist for no benefit.

### 3.12 Verify

```sh
symbolon status
symbolon github selfcheck
```

`selfcheck` should report the provider reachable and clock skew
small. Exit code 0 means everything's good. (CLI commands talk to
the daemon over its admin Unix socket; access is gated by the
`/run/symbolon/` directory mode — group `symbolon` only. Run the
commands as a user in that group, or as root.)

## 4. Enroll a client

### 4.1 On the broker host

```sh
symbolon github enroll dev-vm-1
symbolon pubkey
```

(Replace `github` with the provider key you configured, and
`dev-vm-1` with whatever stable name you want for the client.)

The two outputs together are everything the client needs:

- `enroll` prints the client's PSK hex string.
- `pubkey` prints the broker's static public key hex (same value
  for every client; fetch it once per enrollment batch).

Both halves go into the client's single key file
(`/etc/symbolon/key`, next step).

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

Write the key file — one line, broker public key and PSK
colon-separated:

```sh
install -d -o root -g root -m 0700 /etc/symbolon
echo '<BROKER-PUBKEY-HEX>:<HEX-PSK-FROM-ENROLL>' > /etc/symbolon/key
chmod 0400 /etc/symbolon/key
```

The pinned broker public key is what lets the helper encrypt its
identity to the broker from the first handshake message — nobody
without the broker's private key can learn which identity this
client uses (see
[PROTOCOLS.md § Identity confidentiality](PROTOCOLS.md#identity-confidentiality-protocol-level-guarantees)).

Configure git to use the helper (replace `<broker-host>` and
`dev-vm-1` with the values from the enroll output; the
`credential.https://<host>.helper` URL stem matches the provider
host you configured in `config.toml`):

```sh
git config --global credential.https://github.com.helper \
  "/usr/local/bin/git-credential-symbolon \
   --endpoint <broker-host>:9418 \
   --identity dev-vm-1 \
   --key-file /etc/symbolon/key"

# Required: the broker mints per-repo tokens, so it MUST know the
# `owner/repo` from the request. Git omits the `path=` field on
# credential queries by default; this flag tells it to send it.
# Without it, the first clone fails with
# `evt=mint_denied reason=malformed_request` because `path` is
# absent from the request block.
git config --global credential.https://github.com.useHttpPath true
```

### 4.3 Verify

```sh
git clone https://github.com/<owner>/<repo>
```

If this works, you're done. Operator commands, logging, and
troubleshooting are in [OPERATIONS.md](OPERATIONS.md). Per-provider
specifics (hardening, incident response) are in
[providers/](providers/).
