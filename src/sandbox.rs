//! Linux sandboxing layer: applies Landlock at ABI 6 (FS allowlist +
//! outbound TCP-connect to port 443 + abstract-UDS scope +
//! cross-process signal scope).
//!
//! `Scope::Signal` (Linux 6.12+, Landlock ABI 6) denies sending any
//! signal to a process outside the broker's Landlock domain.
//! Intra-process signals (panic handlers, libc `abort()`,
//! thread-local plumbing) remain permitted — which is correct,
//! because the things we want to *prevent* (a compromised broker
//! attacking other processes via signals) all involve crossing the
//! domain boundary. Symbolon does not legitimately send any
//! cross-process signal.
//!
//! Landlock is intentionally NOT given any rule for `/etc/symbolon/`,
//! so the App PEM key (read once at startup before this module runs) is
//! unreachable post-restriction. State files live under
//! `/var/lib/symbolon/`; the parent-dir rule there is required by the
//! tempfile-then-rename atomic-write pattern.

use std::io;
use std::path::PathBuf;

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath,
    PathFd, PathFdError, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError, RulesetStatus,
    Scope,
};

use crate::config::SandboxMode;
use crate::events::EventKind;

/// Filesystem paths the daemon needs after restriction. Anything
/// not listed here becomes unreachable.
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

// The listen-side TCP socket is bound BEFORE the sandbox closes,
// so the Landlock ruleset never needs `BindTcp` rules. Only
// `ConnectTcp` to port 443 (for outbound provider HTTPS) is added.

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
}

/// Apply Landlock to the calling thread. Effects persist for the
/// lifetime of the thread and propagate to descendants. Only call
/// once per process.
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
        });
    }

    apply_landlock(level, paths)
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
    let scope_bits: BitFlags<Scope> = Scope::AbstractUnixSocket | Scope::Signal;

    let ruleset = Ruleset::default()
        .set_compatibility(compat)
        .handle_access(fs_bits)
        .map_err(|e| classify_ruleset_err(level, e))?
        .handle_access(net_bits)
        .map_err(|e| classify_ruleset_err(level, e))?
        .scope(scope_bits)
        .map_err(|e| classify_ruleset_err(level, e))?;

    let mut created = ruleset.create().map_err(SandboxError::Ruleset)?;

    // `ReadDir` is needed for the parent-dir fsync step at the
    // end of `src/admin.rs::atomic_write` (the tempfile→fsync→
    // rename→fsync-parent pattern): opening the dir as a
    // read-only file to fsync it goes through Landlock's
    // open-directory check. Without it, the rename succeeds and
    // the data lands but `File::open(&dir)` returns EACCES,
    // surfacing as a confusing "write X: Permission denied"
    // partial failure.
    let write_bits: BitFlags<AccessFs> = AccessFs::ReadFile
        | AccessFs::ReadDir
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
                    evt = %EventKind::SandboxPathSkipped,
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
                    evt = %EventKind::SandboxPathSkipped,
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
    })
}

fn classify_ruleset_err(level: SandboxMode, e: RulesetError) -> SandboxError {
    match level {
        SandboxMode::Required => SandboxError::AbiUnavailable(e),
        SandboxMode::BestEffort | SandboxMode::Off => SandboxError::Ruleset(e),
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use std::fs;
    use std::thread;

    // Landlock persists for the calling thread's lifetime. Confine
    // every test that calls `apply` to a dedicated worker thread so
    // the test-binary process itself stays pristine for the rest of
    // the test run.
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
        assert!(!out.fs && !out.tcp && !out.scope);
    }

    #[test]
    fn apply_best_effort_blocks_unlisted_reads() {
        let outcome = run_isolated(|| {
            let allowed = std::env::temp_dir().join(format!(
                "symbolon-sandbox-test-allow-{}",
                std::process::id()
            ));
            fs::write(&allowed, b"hello").unwrap();
            let other = std::env::temp_dir()
                .join(format!("symbolon-sandbox-test-deny-{}", std::process::id()));
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
    fn resolv_files_missing_is_tolerated() {
        run_isolated(|| {
            let paths = SandboxPaths {
                read_files: vec![],
                read_dirs: vec![],
                resolv_files: vec![PathBuf::from("/definitely/does/not/exist/symbolon-test")],
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

    #[test]
    fn write_parent_dirs_allow_parent_fsync() {
        // Regression: `src/admin.rs::atomic_write` ends with
        // `File::open(&parent_dir).sync_all()` to fsync the parent
        // directory. Opening a directory for read requires
        // `AccessFs::ReadDir`; if the `write_bits` bundle omits it,
        // the rename succeeds (data lands on disk) but the parent
        // fsync returns EACCES, surfacing as a confusing partial
        // failure ("write psks: Permission denied") from
        // `symbolon github enroll`.
        let outcome = run_isolated(|| {
            let dir = std::env::temp_dir().join(format!(
                "symbolon-sandbox-write-parent-fsync-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir(&dir).unwrap();

            let paths = SandboxPaths {
                read_files: vec![],
                read_dirs: vec![],
                resolv_files: vec![],
                write_parent_dirs: vec![dir.clone()],
            };
            let out = apply(SandboxMode::BestEffort, &paths).unwrap();

            // Mirror the syscall sequence atomic_write's final
            // step performs: open(dir, O_RDONLY) + fsync(fd).
            let parent_fsync = fs::File::open(&dir).and_then(|f| f.sync_all());
            (out, parent_fsync, dir)
        });
        let (out, parent_fsync, dir) = outcome;
        let _ = fs::remove_dir_all(&dir);
        if out.fs {
            parent_fsync
                .expect("parent-dir fsync must succeed when write_parent_dirs covers the dir");
        } else {
            // Kernel lacks Landlock support — sandbox degraded;
            // test cannot verify enforcement.
            let _ = parent_fsync;
        }
    }
}
