//! PROXY protocol v2 header parsing.
//!
//! Single responsibility: read the 16-byte fixed prefix and the
//! variable-length address block from a byte stream, return the
//! original client's source IP, and fail closed on any deviation
//! from the spec. The header is the daemon's only source of client
//! identity (AGENTS.md invariant #7), so parsing is intentionally
//! strict.
//!
//! Reference: <https://www.haproxy.org/download/2.4/doc/proxy-protocol.txt>.
