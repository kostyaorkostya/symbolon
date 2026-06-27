//! Provider abstraction. The daemon talks to every configured
//! provider through this trait — repo-ID resolution, per-mint
//! token issuance, startup selfcheck. Each concrete provider is
//! a sibling module (`github`, future `gitlab`, etc.) holding
//! its own private-key/PAT machinery, HTTP client, and caches.
//! AGENTS.md invariant #1: one identity per (broker, provider).
//!
//! Trait dispatch goes through `Vec<Box<dyn Provider>>` in
//! `SharedState`; methods use `#[async_trait(?Send)]` because
//! compio is single-threaded.

pub mod github;
pub mod jwt_rs256;

use std::time::Duration;

use async_trait::async_trait;
use derive_more::{AsRef, Display, From};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::ids::OutReqId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumString, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum ProviderKind {
    Github,
}

/// Abstract failure modes the daemon switches on. Generalizable
/// variants come from observed behaviour across GitHub, GitLab,
/// Gitea, Forgejo, Bitbucket. GitHub-private failures (PEM load,
/// JWT signer dead, identity mismatch) collapse into `Internal`
/// with the original error boxed as a `source` so
/// `crate::logging::ErrorChain` can walk the chain in the catch-all
/// log arm.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("transport error")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("unauthorized: {body}")]
    Unauthorized { body: String },

    #[error("forbidden: {body}")]
    Forbidden { body: String },

    #[error("repository not found or credential lacks access")]
    RepoNotFound,

    #[error("rate limited")]
    RateLimited {
        /// Server-suggested wait time before retry. Provider impls
        /// fill this in from whatever upstream signal exists (e.g.
        /// GitHub's `Retry-After` header). `None` means the upstream
        /// didn't say.
        retry_after: Option<Duration>,
    },

    #[error("provider returned unexpected status {status}")]
    UnexpectedStatus { status: u16 },

    #[error("malformed repository path: {path}")]
    MalformedPath { path: String },

    // `context` and `detail` are `&'static` deliberately — provider
    // responses can carry token bytes in 2xx bodies, and Display on
    // a parse error commonly includes a fragment of the offending
    // input. Static strings here forbid any payload from reaching
    // a log line via this variant.
    #[error("malformed response from {context} ({detail})")]
    MalformedResponse {
        context: &'static str,
        detail: &'static str,
    },

    #[error("provider request timed out after {elapsed:?}")]
    Timeout { elapsed: Duration },

    #[error("provider request cancelled (daemon shutting down)")]
    Cancelled,

    /// Provider-private failure (PEM load, JWT signer dead,
    /// identity mismatch, ...). The boxed source preserves the
    /// `source()` chain for `crate::logging::ErrorChain`.
    #[error("internal provider error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Upstream provider's own correlation id, surfaced on the
/// abstract outcome shapes and on the `provider_call_done`
/// breadcrumb. For GitHub, this is `X-GitHub-Request-Id`. Other
/// providers fill it from whatever their equivalent header is.
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsRef, Display, From, Serialize, Deserialize)]
#[as_ref(str)]
#[from(String)]
#[serde(transparent)]
pub struct ProviderReqId(String);

impl ProviderReqId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct MintOutcome {
    pub response: crate::git_credential::Response,
    pub out_req_id: OutReqId,
    pub provider_req_id: Option<ProviderReqId>,
}

#[derive(Debug, Clone)]
pub struct SelfcheckOutcome {
    pub out_req_id: OutReqId,
    pub provider_req_id: Option<ProviderReqId>,
    pub clock_skew_sec: i64,
    /// Provider-specific diagnostic dump — flattened into the
    /// admin JSON response under `details`. Shape is documented
    /// per-provider in `docs/providers/<name>.md`.
    pub details: JsonValue,
}

#[async_trait(?Send)]
pub trait Provider {
    /// Host string the client's `host=` field must match byte-exact
    /// (AGENTS.md invariant #11).
    fn host(&self) -> &str;

    /// Mint a short-lived credential scoped to one repository.
    /// `path` is the `owner/repo` (or namespace/project) from the
    /// git-credential request. Correlation IDs (`req_id`,
    /// `out_req_id`) flow via the active `tracing::Span` opened by
    /// the daemon at request entry — implementations log under the
    /// inherited span rather than threading IDs as parameters.
    async fn mint(&self, path: &str) -> Result<MintOutcome, ProviderError>;

    /// Verify the configured credential can talk to the provider's
    /// API and return diagnostic info. Called once per provider at
    /// startup and on-demand via `symbolon <provider> selfcheck`.
    async fn selfcheck(&self) -> Result<SelfcheckOutcome, ProviderError>;
}
