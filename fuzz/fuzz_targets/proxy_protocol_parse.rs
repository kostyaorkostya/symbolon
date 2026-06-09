//! Fuzz the PROXY v2 header parser. The parser is security-load-
//! bearing per AGENTS.md invariant #7 (source IP from this header
//! is the daemon's sole source of client identity). When parsing
//! succeeds, this harness ALSO asserts:
//!
//! - `header_len <= input.len()` (no out-of-bounds slicing for the
//!   caller, who uses `&input[header_len..]` to find the
//!   git-credential block).
//! - `header_len >= 16` (the fixed PROXY v2 signature + version
//!   byte + family + addr-block-len are at least 16 bytes).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = symbolon::parse_proxy_protocol(data) {
        assert!(
            parsed.header_len <= data.len(),
            "header_len {} > input len {}",
            parsed.header_len,
            data.len(),
        );
        assert!(
            parsed.header_len >= 16,
            "header_len {} < fixed PROXY v2 minimum",
            parsed.header_len,
        );
    }
});
