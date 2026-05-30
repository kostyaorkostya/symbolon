//! Daemon lifecycle: bind the listen socket, accept connections,
//! drive each one through PROXY v2 parsing → git-credential parsing →
//! provider dispatch → response, and handle SIGTERM/SIGINT/SIGHUP
//! per `docs/PROTOCOLS.md`.
//!
//! Single responsibility: orchestration. Wire-level parsing lives in
//! `proxy_protocol` and `git_credential`; provider-specific minting
//! lives under `providers::`.
