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
//! `MCL_ONFAULT` (Linux 4.4+) defers each page's lock to first
//! fault, which sidesteps the well-documented bug where
//! mmap'd files get force-loaded into RAM at lock time
//! ([openbao#354](https://github.com/openbao/openbao/issues/354)).
//! We don't mmap any file today; the flag is free insurance
//! for if a future dep adds one.

use tracing::{error, info, warn};

use crate::config::MlockMode;

#[derive(Debug, thiserror::Error)]
#[error("mlockall(MCL_CURRENT|MCL_FUTURE|MCL_ONFAULT) failed (security.mlock = \"required\")")]
pub struct MlockRequiredFailed(#[source] pub std::io::Error);

pub fn apply(mode: MlockMode) -> Result<(), MlockRequiredFailed> {
    if mode == MlockMode::Off {
        info!(evt = "mlock", status = "off", policy = "off");
        return Ok(());
    }
    let flags = libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT;
    // SAFETY: mlockall takes integer flags only; no memory is
    // dereferenced. Effect is process-wide page-lock state,
    // which is exactly what we want.
    let rc = unsafe { libc::mlockall(flags) };
    if rc == 0 {
        info!(
            evt = "mlock",
            status = "applied",
            policy = ?mode,
            flags = "current|future|onfault",
        );
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    match mode {
        MlockMode::Required => {
            error!(
                evt = "mlock",
                status = "failed",
                policy = "required",
                error = %err,
            );
            Err(MlockRequiredFailed(err))
        }
        MlockMode::BestEffort => {
            warn!(
                evt = "mlock",
                status = "skipped",
                policy = "best_effort",
                error = %err,
            );
            Ok(())
        }
        MlockMode::Off => unreachable!("handled above"),
    }
}
