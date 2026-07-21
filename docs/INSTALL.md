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

install -d -o root     -g symbolon -m 0750 /etc/symbolon
install -d -o symbolon -g symbolon -m 0700 /var/lib/symbolon
install -d -o symbolon -g symbolon -m 0700 /run/symbolon
```

`/etc/symbolon/` holds the provider private key, the broker
static key, and `config.toml` (read-only at runtime);
`/var/lib/symbolon/` holds `clients.json` AND the symbolon-owned
`psks` file (both mutated atomically by the daemon). They are kept
separate because the daemon's landlock ruleset grants write access
to `/var/lib/symbolon/`; putting either key under that dir would
defeat the sandbox's protection of the keys.

`/etc/symbolon/` is **root-owned with group read** (files land
`root:symbolon 0440`/`0640` in §§3.4–3.6): a file's owner can
always `chmod`/`chown` it back open, and Landlock does not govern
metadata operations (there is no `LANDLOCK_ACCESS_FS_*` right for
chmod — see landlock(7)), so ownership by the daemon's own uid
would let a compromised broker rewrite its config to weaken the
next restart (`sandbox = "off"`, a different `api_base`) or
replace its keys. Root ownership makes the config surface
read-only to the broker unconditionally. `/var/lib/symbolon/`
cannot get the same treatment — the daemon is the sole writer
there (tempfile + rename needs dir write); that residual is fine
because everything in it is already in the daemon's memory.

The `/run/symbolon` directory is recreated on every boot — under
systemd by the `.socket` unit's `RuntimeDirectory=symbolon` (§3.10),
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

### 3.4 Provision the App signing key

The daemon never holds the provider's private key — it signs
through a backend you choose with `app_key_backend` (see
[providers/github.md § App key custody](providers/github.md#app-key-custody-file-vs-tpm)).
Pick one:

**`file` backend** (no special hardware; recommended default) — a
sandboxed subprocess owns the PEM:

```sh
install -o root -g symbolon -m 0440 /path/to/github-app.pem /etc/symbolon/github-app.pem
```

**`tpm` backend** — the RSA key lives in a per-instance vTPM. On an
Incus/LXD container, attach a software TPM to the instance:

```sh
incus config device add <instance> vtpm tpm \
    path=/dev/tpm0 pathrm=/dev/tpmrm0
```

Host prerequisites: `swtpm` installed and the `tpm_vtpm_proxy`
kernel module loadable (`modprobe tpm_vtpm_proxy`). Some distros
ship an AppArmor policy that denies swtpm the `sys_admin` capability
it needs for the vtpm-proxy device; if the device doesn't appear,
check `dmesg` / the host AppArmor logs.

The `tpm` device node arrives **root-owned** inside the container,
and Incus's `tpm` device does *not* accept `uid`/`gid`/`mode` keys
(they're rejected as unknown options — verified against the Incus
device schema). So `chown` the node to the `symbolon` user from the
container's init (a systemd `tmpfiles.d` entry or an OpenRC
`start_pre`), e.g.:

```
# /etc/tmpfiles.d/symbolon-tpm.conf
z /dev/tpmrm0 0600 symbolon symbolon -
z /dev/tpm0   0600 symbolon symbolon -
```

Then provision the persistent RSA-2048 key with `tpm2-tools` — the
`tpm2_createprimary` → `tpm2_import` → `tpm2_load` →
`tpm2_evictcontrol` recipe is in
[providers/github.md § App key custody](providers/github.md#app-key-custody-file-vs-tpm).
Destroy or offline the PEM afterwards.

### 3.5 Generate the broker static key

The broker's Noise NKpsk2 identity is a static X25519 keypair. The
private half is 32 random bytes — any 32-byte value is a valid
X25519 key — stored as 64 hex chars on one line:

```sh
umask 277
openssl rand -hex 32 > /etc/symbolon/broker.key
chown root:symbolon /etc/symbolon/broker.key
chmod 0440          /etc/symbolon/broker.key
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
# Wire TCP address. Informational: the daemon does NOT bind — the
# supervisor (systemd .socket / systemfd) binds and hands the fd
# via LISTEN_FDS (§3.9). Keep this in sync with the supervisor
# config. 0.0.0.0:9418 = git smart-http port.
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
selfcheck_timeout = "5s"
# Signing backend (required). "file" (§3.4) shown; for "tpm":
#   app_key_backend = "tpm"
#   [provider.github.tpm]
#   persistent_handle = 0x81010001
app_key_backend = "file"
private_key_path = "/etc/symbolon/github-app.pem"
```

```sh
chown root:symbolon /etc/symbolon/config.toml
chmod 0640          /etc/symbolon/config.toml
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
optional defense-in-depth, not required.** The wire listens on
`0.0.0.0:9418` deliberately (the supervisor binds it — §3.9) so it
works behind any LAN topology (DHCP clients, NAT, container
bridges).

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

The runtime directory is created by systemd via the `.socket`
unit's `RuntimeDirectory=` (no `tmpfiles.d` needed).
`RuntimeDirectory=` is a systemd.exec setting and socket units
support it; it must live on the `.socket`, NOT the `.service`,
for two reasons: on a fresh boot the socket unit binds
`/run/symbolon/admin.sock` before the service has ever started
(`/run` is tmpfs — a service-side `RuntimeDirectory=` isn't there
yet and the bind fails), and systemd removes a unit's runtime
directory when that unit stops, so a service-side declaration
would unlink the still-listening socket's parent directory on
every `systemctl restart symbolon.service`.

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
RuntimeDirectory=symbolon
RuntimeDirectoryMode=0700
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
# Belt-and-braces for state-file modes: the daemon passes explicit
# 0600 modes to open(2), and a 0077 umask guarantees nothing it
# ever creates can be born group/world-accessible even if a mode
# slips. (The admin UDS is unaffected — the .socket unit binds it
# and SocketMode= chmods it.)
UMask=0077
# Shrink default-sized thread stacks (Rust's default is 2 MiB) to
# musl's own 128 KiB per-thread default. Under mlockall (see
# LimitMEMLOCK below) every live thread's full stack is pre-faulted
# into locked, unevictable memory, so the default costs 2 MiB per
# thread. The only threads taking the default are compio's blocking
# pool (DNS getaddrinfo; measured worst-case frame ~16 KiB) — the
# daemon's own actor threads set their size explicitly and ignore
# this. Musl-target-only guidance; overflow is a loud SIGSEGV.
Environment=RUST_MIN_STACK=131072
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
# Socket + state-file modes hang on this line; see the caveat below.
umask="077"
# Same rationale as Environment=RUST_MIN_STACK in the systemd unit
# (§3.10): cap default-sized thread stacks at musl's 128 KiB so
# mlockall doesn't lock 2 MiB per blocking-pool thread. Plain
# `export` works: supervise-daemon passes the environment through
# (it scrubs only RC_* variables), as does systemfd.
export RUST_MIN_STACK=131072
# OpenRC counterpart of the systemd unit's LimitMEMLOCK=infinity
# (§3.10). Without it, mlockall fails under the kernel's 64 KB
# default RLIMIT_MEMLOCK: `mlock = "best_effort"` (the default)
# silently degrades to `evt=mlock status=skipped` and the daemon
# runs without anti-swap hardening; `mlock = "required"` refuses
# to start. openrc-run applies rc_ulimit before starting the
# service; the limit is inherited through supervise-daemon and
# systemfd.
rc_ulimit="-l unlimited"
output_log="/var/log/symbolon.log"
error_log="/var/log/symbolon.log"

depend() {
    need net
    after net
}

# /run is tmpfs and is cleared at every boot; re-create the daemon's
# runtime directory before starting. checkpath is idempotent.
start_pre() {
    checkpath -d -m 0700 -o symbolon:symbolon /run/symbolon
}
```

The `-s` flag arguments must appear in this order — the daemon takes
slot 0 as the TCP wire and slot 1 as the admin UDS.

**Caveat: socket mode under OpenRC — `umask="077"` is what sets
it.** Unlike systemd's `SocketMode=0600`, `systemfd` never chmods
the UDS: it binds and leaves the inode at `0777 & ~umask`
(verified against systemfd's `src/fd.rs` — no mode handling in
the bind path). And the umask systemfd runs under is NOT inherited
from the environment: `supervise-daemon` unconditionally resets it
to its own default of `022` before exec (see `numask` in OpenRC's
`src/supervise-daemon/supervise-daemon.c`), which would leave the
socket world-readable-looking at `0755` — connectable only by
owner and root, since connect(2) on a Unix socket requires *write*
permission on the inode (unix(7)), but sloppy. The `umask="077"`
service variable is OpenRC's first-class knob for this (passed
through as `supervise-daemon --umask`); with it the socket is born
`0700` and the daemon's state files are additionally clamped to
owner-only. A `umask` call in `start_pre` would be silently
overridden — it must be the service variable. The
`0700 symbolon:symbolon` directory is the outer gate either way;
run the CLI as root (or as the `symbolon` user).

Unlike the systemd flow (where the `.socket` unit's
`RuntimeDirectory=` owns `/run/symbolon`), here `start_pre`'s
`checkpath` recreates it every boot — systemfd runs as
`symbolon` and needs write on the directory to create the socket
inode, hence `symbolon`-owned rather than root-owned.

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
`/run/symbolon/` directory, mode 0700 — owner-only. Run the
commands as root, or as the `symbolon` user where it owns the
directory (the OpenRC setup).)

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
