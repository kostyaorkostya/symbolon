//! Crate-wide error composition (deferred).
//!
//! Originally intended to hold a top-level enum that bridges the
//! per-module `<Module>Error` types at the `main` boundary. In
//! practice `main.rs` matches on the relevant errors directly via
//! their `Display` impls (`tracing::error!(error = %e)`), so no
//! unified enum is needed today. Kept as a stub for the AGENTS.md
//! module layout; revisit when a consumer actually needs a single
//! error type.
