//! Crate-wide error composition.
//!
//! Single responsibility: top-level error types that bridge module
//! errors at boundaries. Per the AGENTS.md style guide each module
//! defines its own `thiserror`-derived `<Module>Error`; this file
//! holds whatever wider enum the daemon/CLI need to surface those
//! at the `main` boundary.
