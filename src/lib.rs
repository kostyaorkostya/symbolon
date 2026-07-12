//! `symbolon` — a Rust daemon that mints short-lived, single-repository
//! git credentials on demand.
//!
//! *symbolon* (σύμβολον): in Ancient Greek, an object broken in two
//! halves; each party kept one, and matching them proved identity.
//! Fits a daemon that authenticates clients by PSK and hands them
//! short-lived, single-repository git credentials.
//!
//! Currently implements GitHub via GitHub App installation tokens. The
//! broker holds the provider's private key on a trusted host and hands
//! out ≤1-hour, repository-scoped tokens to enrolled clients, so a
//! client compromise cannot leak account-wide credentials.
//!
//! See [`AGENTS.md`](../AGENTS.md) for the design rationale and
//! architectural invariants, and [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md)
//! for wire formats and file schemas.
//!
//! # Public surface
//!
//! `symbolon` ships as a daemon binary, not as a library. The items
//! re-exported below are needed by `src/main.rs`, `tests/`, and
//! `fuzz/fuzz_targets/`, which Cargo treats as separate crates and
//! therefore cannot see `pub` items. They are marked
//! `#[doc(hidden)]` to indicate they are NOT a public API — external
//! code should not depend on them.

pub mod admin;
pub mod atomic_fs;
pub mod broker_key;
pub mod config;
pub mod connection_tracker;
pub mod daemon;
pub mod events;
pub mod git_credential;
pub mod identity;
pub mod ids;
pub mod loader;
pub mod logging;
pub mod mlock;
pub mod note;
pub mod providers;
pub mod psk;
pub mod psk_store;
pub mod rate_limit;
pub mod ready;
pub mod sandbox;
pub mod signals;
pub mod singleflight_cache;
#[doc(hidden)]
pub mod transport;
pub mod ttl_cache;

// Curated in-package surface. Cargo forces these to be `pub` because
// main.rs / tests / fuzz are separate crates from the lib, even
// though they live in the same package. `#[doc(hidden)]` signals
// "internal — do not depend on this from outside the package", the
// same pattern tokio / serde use for cross-crate internal surface.

#[doc(hidden)]
pub use crate::admin::{CliCommand, cli_dispatch};
#[doc(hidden)]
pub use crate::broker_key::{BrokerPrivateKey, BrokerPublicKey};
#[doc(hidden)]
pub use crate::config::{
    AdminConfig, AppKeyBackend, ClientsConfig, Config, ListenConfig, LoggingConfig, MlockMode,
    ProviderGithub, ProviderGithubTpm, Providers, RuntimeConfig, SandboxMode, SecurityConfig,
};
#[doc(hidden)]
pub use crate::daemon::Service;
#[doc(hidden)]
pub use crate::events::EventKind;
#[doc(hidden)]
pub use crate::identity::{Identity, IdentityError};
#[doc(hidden)]
pub use crate::loader::load_config;
#[doc(hidden)]
pub use crate::logging::{ErrorChain, setup_tracing};
#[doc(hidden)]
pub use crate::mlock::apply as mlock_apply;
#[doc(hidden)]
pub use crate::note::Note;
#[doc(hidden)]
pub use crate::providers::agent::{parse_args as agent_parse_args, run as run_sign_agent};
#[doc(hidden)]
pub use crate::providers::agent_backend::AgentSpawn;
#[doc(hidden)]
pub use crate::providers::github::{GitHubProvider, GithubError};
#[doc(hidden)]
pub use crate::providers::jwt_backend::{JwtBackend, JwtBackendError, JwtClaims, SpawnedBackend};
#[doc(hidden)]
pub use crate::providers::jwt_rs256::JwtSigningKey;
#[doc(hidden)]
pub use crate::providers::tpm_backend::TpmSpawn;
#[doc(hidden)]
pub use crate::psk::Psk;
#[doc(hidden)]
pub use crate::ready::notify as ready_notify;
#[doc(hidden)]
pub use crate::sandbox::Sandboxed;
#[doc(hidden)]
pub use crate::signals::spawn_shutdown_watcher;

// Fuzz harnesses call these parser entry points directly.
#[doc(hidden)]
pub use crate::git_credential::Request as GitCredentialRequest;
#[doc(hidden)]
pub use crate::transport::parse_identity_tlv;
