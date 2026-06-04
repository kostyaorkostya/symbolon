//! Fuzz the PROXY v2 header parser. The parser is security-load-
//! bearing per AGENTS.md invariant #7 (source IP from this header
//! is the daemon's sole source of client identity).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = gcb::proxy_protocol::parse(data);
});
