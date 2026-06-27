//! Fuzz the git-credential request-block parser. The parser is
//! security-load-bearing per AGENTS.md invariant #12 (CR/LF
//! rejection / Clone2Leak class). When parsing succeeds, this
//! harness ALSO asserts the Clone2Leak post-condition: no CR
//! (0x0D) byte may appear in any returned field. The parser's
//! invariant is what defends downstream callers against the
//! CVE-2024-52006/50338/CVE-2025-23040 family — drift here would
//! reintroduce the vulnerability silently.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = symbolon::GitCredentialRequest::parse(data) {
        // Clone2Leak post-condition: parse succeeded ⇒ no CR
        // anywhere in the structured request.
        assert!(
            !req.protocol.as_bytes().contains(&b'\r'),
            "CR in protocol: {:?}",
            req.protocol,
        );
        assert!(
            !req.host.as_bytes().contains(&b'\r'),
            "CR in host: {:?}",
            req.host,
        );
        assert!(
            !req.path.as_bytes().contains(&b'\r'),
            "CR in path: {:?}",
            req.path,
        );
        // And LF, while we're here — bare LF should never appear
        // in a parsed value either (it's the line terminator).
        assert!(
            !req.protocol.as_bytes().contains(&b'\n'),
            "LF in protocol: {:?}",
            req.protocol,
        );
        assert!(
            !req.host.as_bytes().contains(&b'\n'),
            "LF in host: {:?}",
            req.host,
        );
        assert!(
            !req.path.as_bytes().contains(&b'\n'),
            "LF in path: {:?}",
            req.path,
        );
    }
});
