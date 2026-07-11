//! The `file`-backend signing agent: a hidden subcommand
//! (`symbolon __sign-agent`) that the daemon spawns via a
//! `SOCK_SEQPACKET` socketpair. The agent owns the GitHub App PEM; the
//! daemon never maps the key. A daemon compromise is thereby reduced
//! from *key theft* to a *logged, time-bounded signing oracle* — every
//! sign is written to stderr (→ journald) as the audit trail.
//!
//! Startup order is load-bearing (each step narrows what a later
//! compromise can do):
//!   1. take the socket fd from `SYMBOLON_AGENT_FD`
//!   2. read + parse the PEM (needs FS access)
//!   3. `mlockall` best-effort — the key never reaches swap
//!   4. `PR_SET_DUMPABLE = 0` — no core dump can leak the key
//!   5. `PR_SET_PDEATHSIG(SIGTERM)` — die if the daemon dies
//!   6. register the SIGHUP handler (hot key reload) — before seccomp
//!      forbids `rt_sigaction`
//!   7. Landlock: the key path read-only, nothing else; no network
//!   8. seccomp: a syscall allowlist — closes the UDP / raw-socket
//!      exfiltration hole Landlock's net layer doesn't cover, and
//!      forbids `execve` / `socket` / `connect` / io_uring outright
//!   9. serve loop: one request in, one signature out, per datagram
//!
//! The process is synchronous and single-threaded — SEQPACKET gives
//! message framing, so the loop is a plain `recv` → sign → `send`. No
//! compio, no async: the whole point is a tiny, auditable surface.

use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::providers::agent_protocol::{
    AGENT_FD_ENV, AgentRequest, AgentResponse, MAX_MESSAGE, decode, encode,
};
use crate::providers::jwt_rs256::JwtSigningKey;

/// Set by the SIGHUP handler; consumed by the serve loop to trigger a
/// PEM re-read. A plain atomic store is async-signal-safe.
static RELOAD: AtomicBool = AtomicBool::new(false);

/// Entry point for the `__sign-agent` subcommand. Returns an exit
/// code; the process never returns to normal daemon logic. Any error
/// before the serve loop is fatal (the daemon observes the socket EOF
/// and exits non-zero in turn).
pub fn run(key_path: &Path) -> ExitCode {
    match run_inner(key_path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // stderr → journald. No key material in `e`.
            eprintln!("symbolon-sign-agent: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_inner(key_path: &Path) -> Result<(), String> {
    // 1. Reclaim the socketpair end the daemon handed us.
    let sock = take_socket_fd()?;

    // 2. Read + parse the PEM while we still have FS access.
    let mut signer = load_key(key_path)?;

    // 3–5. Harden the process against swap, core dumps, and orphaning.
    lock_memory();
    set_undumpable()?;
    set_parent_death_signal()?;

    // 6. Hot-reload on SIGHUP. Registered before seccomp removes
    //    rt_sigaction from the allowlist.
    install_sighup_handler()?;

    // 7–8. Self-sandbox: FS down to the key path, no network, then a
    //    syscall allowlist.
    apply_landlock(key_path)?;
    apply_seccomp()?;

    // 9. Serve until the daemon closes its end (EOF) or we die.
    serve(sock.as_raw_fd(), key_path, &mut signer)
}

fn take_socket_fd() -> Result<OwnedFd, String> {
    let raw = std::env::var(AGENT_FD_ENV)
        .map_err(|_| format!("{AGENT_FD_ENV} not set"))?
        .parse::<RawFd>()
        .map_err(|e| format!("{AGENT_FD_ENV} not an fd: {e}"))?;
    if raw < 0 {
        return Err(format!("{AGENT_FD_ENV} is negative"));
    }
    // SAFETY: the daemon passed this fd via CommandExt::pre_exec having
    // cleared CLOEXEC on exactly this number; we take sole ownership.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn load_key(key_path: &Path) -> Result<JwtSigningKey, String> {
    let pem =
        std::fs::read(key_path).map_err(|e| format!("read key {}: {e}", key_path.display()))?;
    JwtSigningKey::from_pem(&pem).map_err(|e| format!("parse key {}: {e}", key_path.display()))
}

/// `mlockall(MCL_CURRENT | MCL_FUTURE)`, best-effort. Locks every page
/// (including the parsed key's heap allocations) against swap.
///
/// `memfd_secret` was considered per the plan but doesn't fit: the
/// `rsa` crate holds the key as internal bignum allocations on the
/// normal heap, not in a raw buffer we could place in a secret memfd —
/// so a memfd would protect bytes we no longer hold while missing the
/// live key. `mlockall` covers exactly those live allocations.
fn lock_memory() {
    // SAFETY: mlockall takes integer flags only; no memory is
    // dereferenced. Failure (e.g. RLIMIT_MEMLOCK) is non-fatal — swap
    // is a defence-in-depth layer, and the operator disables swap on
    // the broker host regardless (docs/INSTALL.md).
    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if rc != 0 {
        eprintln!(
            "symbolon-sign-agent: mlockall failed ({}); continuing",
            std::io::Error::last_os_error()
        );
    }
}

fn set_undumpable() -> Result<(), String> {
    // SAFETY: prctl with PR_SET_DUMPABLE takes an integer; no pointers.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
    if rc != 0 {
        return Err(format!(
            "PR_SET_DUMPABLE failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn set_parent_death_signal() -> Result<(), String> {
    // SAFETY: prctl with PR_SET_PDEATHSIG takes a signal number.
    let rc = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    if rc != 0 {
        return Err(format!(
            "PR_SET_PDEATHSIG failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // Race guard: if the daemon died between fork and here, PDEATHSIG
    // won't fire (it's keyed on the parent that set it). Nothing to
    // check portably; the serve loop's EOF handling is the backstop.
    Ok(())
}

fn install_sighup_handler() -> Result<(), String> {
    // SAFETY: the handler only does a relaxed atomic store, which is
    // async-signal-safe. signal-hook-registry keeps the disposition
    // for the process lifetime (same rationale as src/signals.rs).
    unsafe {
        signal_hook_registry::register(libc::SIGHUP, || RELOAD.store(true, Ordering::Relaxed))
    }
    .map_err(|e| format!("register SIGHUP: {e}"))?;
    Ok(())
}

/// Landlock ABI 6: grant `ReadFile` on the key path and nothing else;
/// handle the network layer but add no rule, so all `connect(2)` is
/// denied. This is stricter than the daemon's ruleset (which permits
/// outbound 443) — the agent has no business talking to anything but
/// its parent over the already-open socketpair.
fn apply_landlock(key_path: &Path) -> Result<(), String> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, Scope,
    };
    let abi = ABI::V6;
    let ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| format!("landlock fs: {e}"))?
        .handle_access(AccessNet::from_all(abi))
        .map_err(|e| format!("landlock net: {e}"))?
        .scope(Scope::AbstractUnixSocket | Scope::Signal)
        .map_err(|e| format!("landlock scope: {e}"))?;
    let key_fd = PathFd::new(key_path).map_err(|e| format!("open key for landlock: {e}"))?;
    ruleset
        .create()
        .map_err(|e| format!("landlock create: {e}"))?
        .add_rule(PathBeneath::new(key_fd, AccessFs::ReadFile))
        .map_err(|e| format!("landlock rule: {e}"))?
        .restrict_self()
        .map_err(|e| format!("landlock restrict: {e}"))?;
    Ok(())
}

/// Install a seccomp syscall allowlist. Anything not listed kills the
/// process (`SECCOMP_RET_KILL_PROCESS`). The list is exactly what the
/// serve loop plus RSA signing and a SIGHUP reload need — notably NO
/// `socket` / `connect` / `execve` / io_uring `io_uring_setup`. It
/// closes the UDP and raw-socket exfiltration paths that Landlock's
/// network layer (which only governs `connect`/`bind` on inet
/// sockets, not socket creation) leaves open.
fn apply_seccomp() -> Result<(), String> {
    use seccompiler::{SeccompAction, SeccompFilter};
    use std::convert::TryInto;

    // Empty rule vec = unconditional match on that syscall number.
    let allow: std::collections::BTreeMap<i64, Vec<seccompiler::SeccompRule>> = ALLOWED_SYSCALLS
        .iter()
        .map(|&nr| (nr, Vec::new()))
        .collect();

    let filter = SeccompFilter::new(
        allow,
        SeccompAction::KillProcess, // default: anything not listed
        SeccompAction::Allow,       // matched: listed syscalls run
        std::env::consts::ARCH
            .try_into()
            .map_err(|e| format!("seccomp target arch: {e}"))?,
    )
    .map_err(|e| format!("seccomp filter: {e}"))?;
    let program: seccompiler::BpfProgram = filter
        .try_into()
        .map_err(|e| format!("seccomp compile: {e}"))?;
    seccompiler::apply_filter(&program).map_err(|e| format!("seccomp apply: {e}"))?;
    Ok(())
}

/// The syscall allowlist. Kept as `libc::SYS_*` so it resolves
/// per-arch (x86_64 + aarch64 musl). Grouped by why each is needed;
/// if a future dependency bump adds a syscall, the agent dies loudly
/// on first use rather than silently widening its surface.
const ALLOWED_SYSCALLS: &[i64] = &[
    // socketpair I/O (libc recv/send lower to these)
    libc::SYS_recvfrom,
    libc::SYS_sendto,
    // PEM reload on SIGHUP (std::fs::read)
    libc::SYS_openat,
    libc::SYS_read,
    libc::SYS_close,
    libc::SYS_lseek,
    libc::SYS_statx,
    // audit line to stderr
    libc::SYS_write,
    // allocator + RSA bignum working set
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_brk,
    libc::SYS_madvise,
    // RSA blinding RNG
    libc::SYS_getrandom,
    // audit timestamp fallback when the vDSO path isn't taken
    libc::SYS_clock_gettime,
    // std / allocator internal synchronization
    libc::SYS_futex,
    libc::SYS_sched_yield,
    // signal return from the SIGHUP handler
    libc::SYS_rt_sigreturn,
    // orderly and abnormal exit
    libc::SYS_exit,
    libc::SYS_exit_group,
];

/// The serve loop. Blocks on `recv`; each datagram is one request.
/// Returns `Ok(())` on clean EOF (daemon closed its end). A malformed
/// request is answered with `AgentResponse::Error` and the loop
/// continues — one bad datagram is not fatal.
fn serve(fd: RawFd, key_path: &Path, signer: &mut JwtSigningKey) -> Result<(), String> {
    let mut buf = vec![0u8; MAX_MESSAGE];
    loop {
        if RELOAD.swap(false, Ordering::Relaxed) {
            match load_key(key_path) {
                Ok(k) => {
                    *signer = k;
                    eprintln!("symbolon-sign-agent: reloaded key on SIGHUP");
                }
                Err(e) => eprintln!("symbolon-sign-agent: SIGHUP reload failed: {e}"),
            }
        }
        let n = match recv(fd, &mut buf) {
            Ok(0) => return Ok(()), // daemon closed the socket
            Ok(n) => n,
            Err(e) if e == libc::EINTR => continue, // SIGHUP interrupted recv
            Err(e) => return Err(format!("recv: {}", std::io::Error::from_raw_os_error(e))),
        };
        let reply = handle(&buf[..n], signer);
        let bytes = encode(&reply).unwrap_or_else(|e| {
            // Encoding a small enum can't realistically fail; if it
            // does, fall back to a fixed error datagram.
            encode(&AgentResponse::Error(format!("encode: {e}"))).unwrap_or_default()
        });
        send(fd, &bytes)?;
    }
}

fn handle(bytes: &[u8], signer: &JwtSigningKey) -> AgentResponse {
    let req: AgentRequest = match decode(bytes) {
        Ok(r) => r,
        Err(e) => return AgentResponse::Error(e),
    };
    match req {
        AgentRequest::Ping => AgentResponse::Pong,
        AgentRequest::SignJwt { claims } => {
            // Audit trail: log what we are about to sign BEFORE
            // signing. iss/iat/exp only — never the key or the token.
            eprintln!(
                "symbolon-sign-agent: sign iss={} iat={} exp={}",
                claims.iss, claims.iat, claims.exp
            );
            match signer.sign_rs256(&claims) {
                Ok(jwt) => AgentResponse::Jwt(jwt),
                Err(e) => AgentResponse::Error(format!("sign: {e}")),
            }
        }
    }
}

fn recv(fd: RawFd, buf: &mut [u8]) -> Result<usize, i32> {
    // SAFETY: `buf` is a valid writable slice of `buf.len()` bytes.
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n < 0 {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    } else {
        Ok(n as usize)
    }
}

fn send(fd: RawFd, bytes: &[u8]) -> Result<(), String> {
    // SAFETY: `bytes` is a valid readable slice of `bytes.len()` bytes.
    // SEQPACKET send is atomic — one datagram, no partial writes.
    let n = unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), 0) };
    if n < 0 {
        return Err(format!("send: {}", std::io::Error::last_os_error()));
    }
    if n as usize != bytes.len() {
        return Err(format!("short send: {n} of {}", bytes.len()));
    }
    Ok(())
}

/// Argument parse for the hidden subcommand. `--key-file <path>` is the
/// only flag; the socket fd arrives via the environment.
pub fn parse_args(args: &[String]) -> Result<PathBuf, String> {
    let mut it = args.iter();
    let mut key_path: Option<PathBuf> = None;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--key-file" => {
                key_path = Some(PathBuf::from(it.next().ok_or("--key-file needs a value")?));
            }
            other => return Err(format!("unexpected agent arg: {other}")),
        }
    }
    key_path.ok_or_else(|| "--key-file required".to_string())
}
