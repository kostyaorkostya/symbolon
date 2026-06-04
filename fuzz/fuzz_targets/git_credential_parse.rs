//! Fuzz the git-credential request-block parser. The parser is
//! security-load-bearing per AGENTS.md invariant #12 (CR/LF
//! rejection / Clone2Leak class).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = gcb::git_credential::parse(data);
});
