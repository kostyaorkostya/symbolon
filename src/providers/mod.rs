//! Provider abstraction.
//!
//! Single responsibility: the trait (or enum) the daemon uses to
//! talk to a configured provider — repo-ID resolution and per-mint
//! token issuance. Each concrete provider is a sibling module with
//! its own private-key handling and HTTP client. AGENTS.md invariant
//! #1: one identity per (broker, provider).

pub mod github;
pub mod jwt_rs256;
