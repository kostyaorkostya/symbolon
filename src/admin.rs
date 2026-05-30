//! Admin Unix-domain socket and CLI dispatch.
//!
//! Single responsibility: the operator-facing surface. CLI subcommands
//! (`gcb status`, `gcb github enroll`, etc.) connect to the admin
//! socket; the daemon serialises requests and is therefore the sole
//! writer of `clients.json` and `gcb.psk` (AGENTS.md invariant #10).
//! No HTTP admin endpoints — see AGENTS.md invariant #9.
