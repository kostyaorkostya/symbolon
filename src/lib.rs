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

pub mod admin;
pub mod config;
pub mod cpu_worker;
pub mod daemon;
pub mod git_credential;
pub mod loader;
pub mod logging;
pub mod providers;
pub mod proxy_protocol;
pub mod ready;
pub mod sandbox;
pub mod signals;
