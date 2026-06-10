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

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Accept,
    AdminDenied,
    AdminPeercredFailed,
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

impl EventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            EventKind::Accept => "accept",
            EventKind::AdminDenied => "admin_denied",
            EventKind::AdminPeercredFailed => "admin_peercred_failed",
            EventKind::AdminRequest => "admin_request",
            EventKind::CacheInvalidated => "cache_invalidated",
            EventKind::ConfigReload => "config_reload",
            EventKind::DrainIncomplete => "drain_incomplete",
            EventKind::Enroll => "enroll",
            EventKind::HandshakeFailed => "handshake_failed",
            EventKind::Mint => "mint",
            EventKind::MintDenied => "mint_denied",
            EventKind::Mlock => "mlock",
            EventKind::MlockRequiredFailed => "mlock_required_failed",
            EventKind::PreludeInvalid => "prelude_invalid",
            EventKind::Prepare => "prepare",
            EventKind::ProviderCall => "provider_call",
            EventKind::ProviderCallDone => "provider_call_done",
            EventKind::ProviderError => "provider_error",
            EventKind::Ready => "ready",
            EventKind::ReadyPidfileWriteFailed => "ready_pidfile_write_failed",
            EventKind::Revoke => "revoke",
            EventKind::RunFailed => "run_failed",
            EventKind::SandboxApplied => "sandbox_applied",
            EventKind::SandboxPathSkipped => "sandbox_path_skipped",
            EventKind::Selfcheck => "selfcheck",
            EventKind::Shutdown => "shutdown",
            EventKind::SignalRegistrationFailed => "signal_registration_failed",
            EventKind::Startup => "startup",
        }
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
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
