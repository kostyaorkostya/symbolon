//! git-credential helper wire protocol: parsing the `key=value` request
//! block and emitting the `username` / `password` / `password_expiry_utc`
//! response.
//!
//! Single responsibility: protocol translation. Host dispatch and mint
//! logic live elsewhere.
//!
//! # Security: CR/LF rejection (mandatory)
//!
//! Per `docs/PROTOCOLS.md` and AGENTS.md invariant #12, the parser
//! MUST reject any field value containing a 0x0D (CR) or 0x0A (LF)
//! byte. Bare LF is valid only as a line terminator. This defends
//! against the Clone2Leak class (CVE-2024-52006, CVE-2024-50338,
//! CVE-2025-23040), where a crafted URL injects an extra protocol
//! line to redirect credentials to an attacker-controlled host. On
//! detection, the connection is closed without a response and the
//! event is logged as `evt=mint_denied reason=malformed_request`.
