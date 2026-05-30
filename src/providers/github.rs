//! GitHub provider: App JWT signing, repository-ID resolution (with
//! TTL cache), and installation-access-token minting.
//!
//! Single responsibility: everything GitHub-specific. Per-mint scope
//! is hard-coded to `repository_ids: [<one>]` plus
//! `permissions: {contents: write, metadata: read}` (AGENTS.md
//! invariants #4 and #5). The App private key is loaded once at
//! daemon startup and held in memory; rotation requires a restart.
//!
//! See `docs/PROTOCOLS.md` ("GitHub provider outbound") for the
//! wire-level contract.
