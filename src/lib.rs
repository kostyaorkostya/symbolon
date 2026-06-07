//! `gcb` — a Rust daemon that mints short-lived, single-repository git
//! credentials on demand.
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
//! `gcb` ships as a daemon binary, not as a library. The items
//! re-exported below are needed by `src/main.rs`, `tests/`, and
//! `fuzz/fuzz_targets/`, which Cargo treats as separate crates and
//! therefore cannot see `pub(crate)` items. They are marked
//! `#[doc(hidden)]` to indicate they are NOT a public API — external
//! code should not depend on them.

pub(crate) mod admin;
pub(crate) mod config;
pub(crate) mod connection_tracker;
pub(crate) mod cpu_worker;
pub(crate) mod daemon;
pub(crate) mod git_credential;
pub(crate) mod loader;
pub(crate) mod logging;
pub(crate) mod providers;
pub(crate) mod proxy_protocol;
pub(crate) mod ready;
pub(crate) mod sandbox;
pub(crate) mod signals;
pub(crate) mod stunnel;

// Curated in-package surface. Cargo forces these to be `pub` because
// main.rs / tests / fuzz are separate crates from the lib, even
// though they live in the same package. `#[doc(hidden)]` signals
// "internal — do not depend on this from outside the package", the
// same pattern tokio / serde use for cross-crate internal surface.

#[doc(hidden)]
pub use crate::admin::{CliCommand, cli_dispatch};
#[doc(hidden)]
pub use crate::config::{
    AdminConfig, ClientsConfig, Config, ListenConfig, LogLevel, LoggingConfig, ProviderGithub,
    Providers, RuntimeConfig, SandboxMode, SecurityConfig, StunnelConfig,
};
#[doc(hidden)]
pub use crate::cpu_worker::CpuWorker;
#[doc(hidden)]
pub use crate::daemon::{Service, ServiceHandle, run as run_daemon};
#[doc(hidden)]
pub use crate::loader::load_config;
#[doc(hidden)]
pub use crate::logging::setup_tracing;
#[doc(hidden)]
pub use crate::providers::github::{GitHubProvider, GithubError};
#[doc(hidden)]
pub use crate::ready::notify as ready_notify;
#[doc(hidden)]
pub use crate::signals::{spawn_shutdown_watcher, spawn_sighup_handler};

// Fuzz harnesses call these parser entry points directly.
#[doc(hidden)]
pub use crate::git_credential::parse as parse_git_credential;
#[doc(hidden)]
pub use crate::proxy_protocol::parse as parse_proxy_protocol;
