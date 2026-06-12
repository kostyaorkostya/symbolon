//! `mlockall` current + future pages into RAM.
//!
//! Hardens against secret-exfiltration via swap: the App
//! private key (`Arc<JwtSigningKey>` → `rsa::RsaPrivateKey`)
//! and any in-flight mint token never reach disk, even under
//! kernel memory pressure. The recommended *primary* anti-swap
//! defence is to disable swap on the broker host
//! (`swapoff -a` + fstab edit, per docs/INSTALL.md); this
//! syscall is belt-and-suspenders on top.
//!
//! No `MCL_ONFAULT`: pages are pre-faulted at the time mlockall
//! is invoked (for current pages) and at allocation time (for
//! future pages). Deferring locks to first-fault produces a
//! footgun where `best_effort` + finite `RLIMIT_MEMLOCK` logs
//! `status=applied` and then the process aborts at the first
//! allocation that exceeds the limit. Without `ONFAULT`, the
//! kernel reports the rlimit shortfall synchronously, either at
//! the mlockall call (current pages don't fit) or at the
//! offending allocation (future pages don't fit) — never at an
//! unpredictable later page fault.

use tracing::{error, info, warn};

use crate::config::MlockMode;
use crate::events::EventKind;

#[derive(Debug, thiserror::Error)]
#[error("mlockall(MCL_CURRENT|MCL_FUTURE) failed (security.mlock = \"required\")")]
pub struct MlockRequiredFailed(#[source] pub std::io::Error);

pub fn apply(mode: MlockMode) -> Result<(), MlockRequiredFailed> {
    if mode == MlockMode::Off {
        info!(evt = %EventKind::Mlock, status = "off", policy = "off");
        return Ok(());
    }
    let flags = libc::MCL_CURRENT | libc::MCL_FUTURE;
    // SAFETY: mlockall takes integer flags only; no memory is
    // dereferenced. Effect is process-wide page-lock state,
    // which is exactly what we want.
    let rc = unsafe { libc::mlockall(flags) };
    if rc == 0 {
        info!(
            evt = %EventKind::Mlock,
            status = "applied",
            policy = ?mode,
            flags = "current|future",
        );
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    match mode {
        MlockMode::Required => {
            error!(
                evt = %EventKind::Mlock,
                status = "failed",
                policy = "required",
                error = %err,
            );
            Err(MlockRequiredFailed(err))
        }
        MlockMode::BestEffort => {
            warn!(
                evt = %EventKind::Mlock,
                status = "skipped",
                policy = "best_effort",
                error = %err,
            );
            Ok(())
        }
        MlockMode::Off => unreachable!("handled above"),
    }
}
