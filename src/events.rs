//! Closed-set catalog of `evt` names emitted to the structured-log
//! stream. Each variant maps via `Display` to the exact snake_case
//! string operators query in jq pipelines; the schema is documented
//! in `docs/PROTOCOLS.md § Logging schema`. Adding a new event name
//! is a deliberate two-step act: extend this enum, then document it
//! in PROTOCOLS.md.
//!
//! Renaming a variant is a wire break for any operator-side
//! pipeline that filters on `evt`; treat it as a schema migration,
//! not a refactor.

use strum::{Display, IntoStaticStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoStaticStr, Display)]
#[strum(serialize_all = "snake_case")]
pub enum EventKind {
    Accept,
    AdminRequest,
    CacheInvalidated,
    ConfigReload,
    DrainIncomplete,
    Enroll,
    HandshakeFailed,
    Mint,
    MintDenied,
    Mlock,
    MlockRequiredFailed,
    PreludeInvalid,
    Prepare,
    ProviderCall,
    ProviderCallDone,
    ProviderError,
    Ready,
    ReadyPidfileWriteFailed,
    Revoke,
    RunFailed,
    SandboxApplied,
    SandboxPathSkipped,
    Selfcheck,
    Shutdown,
    SignalRegistrationFailed,
    Startup,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_emits_snake_case() {
        assert_eq!(EventKind::Mint.to_string(), "mint");
        assert_eq!(EventKind::MintDenied.to_string(), "mint_denied");
        assert_eq!(
            EventKind::SandboxPathSkipped.to_string(),
            "sandbox_path_skipped"
        );
        assert_eq!(
            EventKind::ReadyPidfileWriteFailed.to_string(),
            "ready_pidfile_write_failed"
        );
    }
}
