//! Linux sandboxing layer: applies landlock (FS + TCP + abstract-UDS
//! scope at ABI 6) and a seccomp-BPF filter that **denies** every
//! PID-targeted signal syscall (`kill` / `tkill` / `tgkill` /
//! `rt_sigqueueinfo` / `rt_tgsigqueueinfo`) and **constrains**
//! `pidfd_send_signal` to `SIGHUP`. `pidfd_open` is allowed (any
//! args) because `StunnelController` opens a fresh pidfd per
//! enroll/revoke as stunnel's PID changes over restarts.
//!
//! Why the tightening matters: signal-sending syscalls' first arg
//! is a `pid_t` that BPF cannot bind to a runtime value (stunnel's
//! PID is dynamic). Moving SIGHUP delivery to `pidfd_send_signal`
//! lets us delete the broad sig-arg-only filter and replace it
//! with: "pidfd_send_signal allowed iff sig==SIGHUP, everything
//! else EPERM." Knowing PIDs to target would require `/proc`
//! enumeration, which landlock blocks; the residual capability is
//! a SIGHUP to whichever pid lives in the stunnel pidfile.
//!
//! The seccomp filter substitutes for landlock's `Scope::Signal`, which
//! cannot be enabled here: stunnel lives in a separate process tree
//! and the broker must keep being able to SIGHUP it on enroll/revoke.
//!
//! Landlock is intentionally NOT given any rule for `/etc/gcb/`, so
//! the App PEM key (read once at startup before this module runs) is
//! unreachable post-restriction. State files live under
//! `/var/lib/gcb/`; the parent-dir rule there is required by the
//! tempfile-then-rename atomic-write pattern.

use std::io;
use std::path::PathBuf;

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath,
    PathFd, PathFdError, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError, RulesetStatus,
    Scope,
};
use seccompiler::{
    BackendError, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch,
};

use crate::config::SandboxMode;

/// Filesystem paths the daemon needs after restriction. Anything not
/// listed here becomes unreachable.
pub(crate) struct SandboxPaths {
    /// Files needing `ReadFile` only.
    pub read_files: Vec<PathBuf>,
    /// Dirs needing `ReadFile | ReadDir` (e.g. CA-bundle dirs).
    pub read_dirs: Vec<PathBuf>,
    /// Per-file `ReadFile` rules tolerated to ENOENT (glibc-only
    /// nameservice files on musl).
    pub resolv_files: Vec<PathBuf>,
    /// Parent dirs of atomic-write targets. Need a bundle of FS
    /// access bits to support the tempfile-create + fsync + rename +
    /// fsync-parent sequence in `src/admin.rs::atomic_write`.
    pub write_parent_dirs: Vec<PathBuf>,
}

/// What `apply` actually managed to put in place. Reported back so the
/// daemon can log a structured `sandbox_applied` event.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SandboxOutcome {
    /// Landlock ABI we built the ruleset against (always 6 unless
    /// `Off`).
    pub requested_abi: u8,
    /// Whether `restrict_self` reports the ruleset as
    /// `FullyEnforced`, `PartiallyEnforced`, `NotEnforced`, or `off`
    /// when sandboxing was skipped.
    pub status: &'static str,
    pub fs: bool,
    pub tcp: bool,
    pub scope: bool,
    pub seccomp: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// `Required` policy but the kernel rejected an ABI-6 feature.
    #[error("kernel does not support the requested Landlock ABI")]
    AbiUnavailable(#[source] RulesetError),
    /// Opening a mandatory path for a landlock rule failed.
    #[error("failed to open landlock path")]
    PathOpen(#[from] PathFdError),
    /// Building the landlock ruleset (handle_access / add_rule /
    /// create) failed.
    #[error("landlock ruleset construction failed")]
    Ruleset(#[source] RulesetError),
    /// `restrict_self()` failed for a reason unrelated to ABI
    /// availability.
    #[error("landlock restrict_self failed")]
    Restrict(#[source] RulesetError),
    /// Building the seccomp filter or compiling its BPF program
    /// failed.
    #[error("seccomp filter construction failed")]
    SeccompBuild(#[source] seccompiler::Error),
    /// Loading the BPF program into the kernel failed.
    #[error("seccomp filter install failed")]
    SeccompInstall(#[source] seccompiler::Error),
    /// The host architecture is not one seccompiler recognises
    /// (x86_64 / aarch64 / riscv64).
    #[error("unsupported host architecture for seccomp: {0}")]
    UnsupportedArch(String),
}

/// Apply landlock + seccomp to the calling thread. Effects persist
/// for the lifetime of the thread and propagate to descendants. Only
/// call once per process.
pub(crate) fn apply(
    level: SandboxMode,
    paths: &SandboxPaths,
) -> Result<SandboxOutcome, SandboxError> {
    if level == SandboxMode::Off {
        return Ok(SandboxOutcome {
            requested_abi: 0,
            status: "off",
            fs: false,
            tcp: false,
            scope: false,
            seccomp: false,
        });
    }

    let landlock_outcome = apply_landlock(level, paths)?;
    apply_seccomp()?;

    Ok(SandboxOutcome {
        seccomp: true,
        ..landlock_outcome
    })
}

fn apply_landlock(
    level: SandboxMode,
    paths: &SandboxPaths,
) -> Result<SandboxOutcome, SandboxError> {
    let compat = match level {
        SandboxMode::Required => CompatLevel::HardRequirement,
        SandboxMode::BestEffort => CompatLevel::BestEffort,
        SandboxMode::Off => unreachable!("Off short-circuited in apply"),
    };
    let abi = ABI::V6;
    let fs_bits = AccessFs::from_all(abi);
    let net_bits = AccessNet::from_all(abi);

    let ruleset = Ruleset::default()
        .set_compatibility(compat)
        .handle_access(fs_bits)
        .map_err(|e| classify_ruleset_err(level, e))?
        .handle_access(net_bits)
        .map_err(|e| classify_ruleset_err(level, e))?
        .scope(Scope::AbstractUnixSocket)
        .map_err(|e| classify_ruleset_err(level, e))?;

    let mut created = ruleset.create().map_err(SandboxError::Ruleset)?;

    let write_bits: BitFlags<AccessFs> = AccessFs::ReadFile
        | AccessFs::WriteFile
        | AccessFs::MakeReg
        | AccessFs::RemoveFile
        | AccessFs::Truncate
        | AccessFs::Refer;
    let read_dir_bits: BitFlags<AccessFs> = AccessFs::ReadFile | AccessFs::ReadDir;

    for f in &paths.read_files {
        let fd = PathFd::new(f)?;
        created = created
            .add_rule(PathBeneath::new(fd, AccessFs::ReadFile))
            .map_err(SandboxError::Ruleset)?;
    }
    for d in &paths.read_dirs {
        let fd = match PathFd::new(d) {
            Ok(fd) => fd,
            Err(e) => {
                // CA-bundle paths vary by distro; missing one is
                // tolerable on best-effort and we surface it at debug
                // so an operator running `--required` can chase it.
                tracing::debug!(
                    evt = "sandbox_path_skipped",
                    path = %d.display(),
                    reason = "open_failed",
                    error = %e,
                );
                continue;
            }
        };
        created = created
            .add_rule(PathBeneath::new(fd, read_dir_bits))
            .map_err(SandboxError::Ruleset)?;
    }
    for f in &paths.resolv_files {
        match PathFd::new(f) {
            Ok(fd) => {
                created = created
                    .add_rule(PathBeneath::new(fd, AccessFs::ReadFile))
                    .map_err(SandboxError::Ruleset)?;
            }
            Err(PathFdError::OpenCall { source, .. })
                if source.kind() == io::ErrorKind::NotFound =>
            {
                tracing::debug!(
                    evt = "sandbox_path_skipped",
                    path = %f.display(),
                    reason = "enoent",
                );
            }
            Err(e) => return Err(SandboxError::PathOpen(e)),
        }
    }
    for d in &paths.write_parent_dirs {
        let fd = PathFd::new(d)?;
        created = created
            .add_rule(PathBeneath::new(fd, write_bits))
            .map_err(SandboxError::Ruleset)?;
    }

    created = created
        .add_rule(NetPort::new(443, AccessNet::ConnectTcp))
        .map_err(SandboxError::Ruleset)?;

    let status = created.restrict_self().map_err(SandboxError::Restrict)?;
    let status_str = match status.ruleset {
        RulesetStatus::FullyEnforced => "fully_enforced",
        RulesetStatus::PartiallyEnforced => "partially_enforced",
        RulesetStatus::NotEnforced => "not_enforced",
    };
    let fully = matches!(status.ruleset, RulesetStatus::FullyEnforced);

    Ok(SandboxOutcome {
        requested_abi: 6,
        status: status_str,
        fs: fully,
        tcp: fully,
        scope: fully,
        seccomp: false,
    })
}

fn classify_ruleset_err(level: SandboxMode, e: RulesetError) -> SandboxError {
    match level {
        SandboxMode::Required => SandboxError::AbiUnavailable(e),
        SandboxMode::BestEffort | SandboxMode::Off => SandboxError::Ruleset(e),
    }
}

fn apply_seccomp() -> Result<(), SandboxError> {
    let arch: TargetArch = std::env::consts::ARCH
        .try_into()
        .map_err(|_| SandboxError::UnsupportedArch(std::env::consts::ARCH.to_string()))?;
    let filter = build_signal_filter(arch)?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|e: BackendError| SandboxError::SeccompBuild(seccompiler::Error::Backend(e)))?;
    seccompiler::apply_filter(&program).map_err(SandboxError::SeccompInstall)?;
    Ok(())
}

fn build_signal_filter(arch: TargetArch) -> Result<SeccompFilter, SandboxError> {
    let mut rules: std::collections::BTreeMap<i64, Vec<SeccompRule>> =
        std::collections::BTreeMap::new();

    // Unconditional deny. The daemon never calls these — SIGHUP to
    // stunnel goes through `pidfd_send_signal` (see
    // `src/stunnel.rs`). An empty rule chain matches every call,
    // routing it to `match_action = EPERM`.
    for nr in [
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
    ] {
        rules.insert(nr, Vec::new());
    }

    // Conditional allow: `pidfd_send_signal(pidfd, sig, ...)` is
    // EPERM'd unless sig == SIGHUP. `pidfd_open` is not listed at
    // all, so it falls through `mismatch_action = Allow` (needed
    // because stunnel's PID is dynamic across restarts).
    let sighup = libc::SIGHUP as u64;
    let cond = SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, sighup)
        .map_err(|e| SandboxError::SeccompBuild(seccompiler::Error::Backend(e)))?;
    let rule = SeccompRule::new(vec![cond])
        .map_err(|e| SandboxError::SeccompBuild(seccompiler::Error::Backend(e)))?;
    rules.insert(libc::SYS_pidfd_send_signal, vec![rule]);

    SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e: BackendError| SandboxError::SeccompBuild(seccompiler::Error::Backend(e)))
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use std::fs;
    use std::thread;

    // Landlock + seccomp persist for the calling thread's lifetime.
    // Confine every test that calls `apply` (or its sub-pieces) to a
    // dedicated worker thread so the test-binary process itself stays
    // pristine for the rest of the test run.
    fn run_isolated<F, R>(f: F) -> R
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        thread::spawn(f).join().expect("worker thread panicked")
    }

    fn make_paths(read_files: Vec<PathBuf>, write_dirs: Vec<PathBuf>) -> SandboxPaths {
        SandboxPaths {
            read_files,
            read_dirs: vec![],
            resolv_files: vec![],
            write_parent_dirs: write_dirs,
        }
    }

    #[test]
    fn apply_off_is_noop() {
        let out = run_isolated(|| {
            let paths = make_paths(vec![], vec![]);
            apply(SandboxMode::Off, &paths).unwrap()
        });
        assert_eq!(out.status, "off");
        assert!(!out.fs && !out.tcp && !out.scope && !out.seccomp);
        // Still able to read arbitrary paths from the worker thread —
        // but we're back on the test thread now, so just sanity-check
        // the outcome shape.
    }

    #[test]
    fn apply_best_effort_blocks_unlisted_reads() {
        let outcome = run_isolated(|| {
            let allowed =
                std::env::temp_dir().join(format!("gcb-sandbox-test-allow-{}", std::process::id()));
            fs::write(&allowed, b"hello").unwrap();
            let other =
                std::env::temp_dir().join(format!("gcb-sandbox-test-deny-{}", std::process::id()));
            fs::write(&other, b"secret").unwrap();

            let paths = make_paths(vec![allowed.clone()], vec![]);
            let out = apply(SandboxMode::BestEffort, &paths).unwrap();

            // Allowed path still readable.
            let allowed_data = fs::read(&allowed).unwrap();
            assert_eq!(allowed_data, b"hello");
            // Unlisted path denied (when landlock actually engaged).
            let other_res = fs::read(&other);
            (out, other_res, allowed, other)
        });
        let (out, other_res, allowed, other) = outcome;
        let _ = fs::remove_file(&allowed);
        let _ = fs::remove_file(&other);
        if out.fs {
            let err = other_res.expect_err("expected sandbox to deny unlisted read");
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        } else {
            // Kernel lacks landlock support — best-effort degraded to
            // a no-op; test cannot verify FS denial.
            assert!(other_res.is_ok() || other_res.is_err());
        }
    }

    #[test]
    fn seccomp_blocks_kill_even_with_sighup() {
        // After the Q3 tightening, SYS_kill is denied unconditionally
        // — even kill(getpid(), SIGHUP). The legitimate SIGHUP path
        // goes through pidfd_send_signal in src/stunnel.rs. This test
        // asserts that the legacy kill(2) entry-point is fully
        // closed.
        let blocked = run_isolated(|| {
            let paths = make_paths(vec![], vec![]);
            let _ = apply(SandboxMode::BestEffort, &paths).expect("sandbox apply");
            unsafe {
                let pid = libc::getpid();
                let rc = libc::kill(pid, libc::SIGHUP);
                if rc == 0 {
                    return Ok(());
                }
                let errno = *libc::__errno_location();
                Err(errno)
            }
        });
        match blocked {
            Ok(()) => panic!("expected kill(SIGHUP) to be blocked by seccomp filter"),
            Err(errno) => assert_eq!(errno, libc::EPERM, "expected EPERM, got {errno}"),
        }
    }

    #[test]
    fn seccomp_blocks_non_sighup_self_signal() {
        // Send SIGHUP first (a child receives it harmlessly when
        // running under cargo, since `kill` to self with SIGHUP is
        // synchronous and we control the process). Then attempt
        // SIGUSR1, which the filter must reject with EPERM.
        let blocked = run_isolated(|| {
            // Apply only seccomp (landlock off-mode skips both, but
            // we want JUST seccomp here so the test is hermetic). We
            // need NO_NEW_PRIVS set; landlock's restrict_self does
            // that even when the ruleset is empty, so go through it.
            let paths = make_paths(vec![], vec![]);
            let _ = apply(SandboxMode::BestEffort, &paths).expect("sandbox apply");

            // SIGUSR1: should be EPERM under the filter.
            unsafe {
                let pid = libc::getpid();
                let rc = libc::kill(pid, libc::SIGUSR1);
                if rc == 0 {
                    return Ok(());
                }
                let errno = *libc::__errno_location();
                Err(errno)
            }
        });
        match blocked {
            Ok(()) => panic!("expected SIGUSR1 to be blocked by seccomp filter"),
            Err(errno) => assert_eq!(errno, libc::EPERM, "expected EPERM, got {errno}"),
        }
    }

    #[test]
    fn resolv_files_missing_is_tolerated() {
        run_isolated(|| {
            let paths = SandboxPaths {
                read_files: vec![],
                read_dirs: vec![],
                resolv_files: vec![PathBuf::from("/definitely/does/not/exist/gcb-test")],
                write_parent_dirs: vec![],
            };
            // Should not error on the missing resolv file.
            let _ = apply(SandboxMode::BestEffort, &paths).expect("apply with missing resolv ok");
        });
    }

    #[test]
    fn off_mode_returns_off_status() {
        let paths = make_paths(vec![], vec![]);
        let out = apply(SandboxMode::Off, &paths).unwrap();
        assert_eq!(out.status, "off");
    }
}
