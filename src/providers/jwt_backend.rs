//! The signing seam: `JwtBackend` is the ONLY place the daemon's
//! signing path branches on backend. Everything downstream (the
//! provider's mint/selfcheck flow) holds a `Box<dyn JwtBackend>` and
//! cannot tell a vTPM from a key subprocess — AGENTS.md invariant.
//!
//! Two implementors:
//! - [`crate::providers::tpm_backend`]: RSA in a vTPM, in-process. The
//!   daemon computes SHA-256 of the JWS signing input in Rust; only
//!   the 32-byte digest crosses into the TPM.
//! - [`crate::providers::agent_backend`]: RSA in a sandboxed
//!   subprocess that owns the PEM. The daemon ships claims; the agent
//!   builds and signs the whole JWT and logs each request (audit
//!   trail).
//!
//! Both return a complete compact JWS. The trait takes the claims
//! struct rather than pre-serialised bytes so the agent can log the
//! claims it actually signed.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::sandbox::Sandboxed;

/// GitHub App JWT claims: `iss` (App client id), `iat`, `exp`. The
/// registered-claim shape is standard JOSE; GitHub App auth uses
/// exactly these three. Serialised to JSON by both backends (the TPM
/// path via `jwt_rs256::signing_input`, the agent path over the wire).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub iss: String,
    pub iat: u64,
    pub exp: u64,
}

impl JwtClaims {
    /// Clock-skew leeway: stamp `iat` 60 s in the past so a slightly
    /// behind broker still passes GitHub's "iat in the future" check.
    const LEEWAY_PAST_SECS: u64 = 60;
    /// Lifetime: 9 minutes. GitHub caps App JWTs at 10 minutes; the
    /// 60 s margin matches `LEEWAY_PAST_SECS` so total skew tolerance
    /// is 1 minute on either side.
    const LIFETIME_SECS: u64 = 540;

    pub fn new(now: SystemTime, client_id: &str) -> Self {
        let unix = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Self {
            iss: client_id.to_string(),
            iat: unix.saturating_sub(Self::LEEWAY_PAST_SECS),
            exp: unix.saturating_add(Self::LIFETIME_SECS),
        }
    }
}

/// Backend failure. Kept deliberately coarse — the daemon collapses
/// these into `GithubError::JwtSign` / `JwtSignerDead`, so the wire
/// vocabulary doesn't grow a backend dimension. `Display` is
/// operator-facing; it names the backend and the failing stage but
/// never carries key material or signed bytes.
#[derive(Debug, thiserror::Error)]
pub enum JwtBackendError {
    #[error("signing backend is no longer running")]
    BackendDead,
    #[error("signing backend I/O failed: {0}")]
    Io(String),
    #[error("signing backend protocol error: {0}")]
    Protocol(String),
    #[error("signing backend rejected the request: {0}")]
    Rejected(String),
    /// A backend-internal failure (e.g. a wire-marshaling or
    /// device-level error). Kept opaque — the seam doesn't name which
    /// backend, and the daemon collapses it into `GithubError::JwtSign`
    /// either way. The detail string is operator-facing and carries no
    /// key material.
    #[error("signing backend error: {0}")]
    Backend(String),
    #[error("backend construction failed: {0}")]
    Construct(String),
}

/// The signing seam. `?Send` because the daemon runtime (compio) is
/// single-threaded; the returned futures never cross threads. Both
/// methods are `async` even though the work happens on a dedicated
/// actor thread — the future resolves when the actor replies.
#[async_trait::async_trait(?Send)]
pub trait JwtBackend {
    /// Sign `claims` into a complete compact JWS (RS256).
    async fn sign(&self, claims: &JwtClaims) -> Result<String, JwtBackendError>;

    /// Startup readiness probe. The TPM backend runs `TPM2_ReadPublic`
    /// and verifies the key is RSA-2048 with a compatible scheme; the
    /// agent backend pings its subprocess. Called once at provider
    /// construction, before the first mint.
    async fn self_check(&self) -> Result<(), JwtBackendError>;
}

/// The pre-sandbox half of a signing backend: the fd-acquiring step
/// (open the TPM device / `execve` the key subprocess) that must run
/// *before* the daemon sandboxes itself. [`Self::into_backend`] then
/// starts the fd-owning actor thread *after* the sandbox is in place,
/// producing the live [`JwtBackend`].
///
/// Trait-, not enum-based, for the same reason as `JwtBackend`: a new
/// backend is a new impl, with no central `match` to extend.
pub trait SpawnedBackend {
    /// Start the actor thread and hand back the live backend. Consumes
    /// the boxed spawn. The `&Sandboxed` argument is proof the daemon
    /// sandbox has been applied — the actor thread is spawned through
    /// it, so it inherits the Landlock ruleset. This makes the
    /// two-phase (acquire fd pre-sandbox, start thread post-sandbox)
    /// split self-documenting: you cannot call this without a witness,
    /// and the only witness comes from `sandbox::apply`.
    fn into_backend(self: Box<Self>, sandboxed: &Sandboxed) -> Box<dyn JwtBackend>;
}
