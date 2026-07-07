//! Fuzz the identity-TLV parser. The TLV rides as the (encrypted)
//! payload of Noise handshake msg1 and carries the client identity
//! that drives PSK selection on the daemon side (AGENTS.md invariant
//! #7); the daemon parses it from the decrypted payload bytes, which
//! the peer fully controls.
//! When parsing succeeds, this harness asserts post-conditions:
//!
//! - `consumed >= 6 && consumed <= input.len()` (parser never reads
//!   past the buffer it was given).
//! - The returned identity matches the strict charset `[A-Za-z0-9._-]+`
//!   (no CR/LF/NUL/whitespace — same defence as the git-credential
//!   parser's CR/LF rejection).
//! - The returned identity length is 1..=64.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((identity, consumed)) = symbolon::parse_identity_tlv(data) {
        assert!(consumed >= 6, "consumed {consumed} < 6-byte minimum TLV");
        assert!(
            consumed <= data.len(),
            "consumed {consumed} > input len {}",
            data.len(),
        );
        let id = identity.as_str();
        let id_bytes = id.as_bytes();
        assert!(
            !id_bytes.is_empty() && id_bytes.len() <= 64,
            "identity length {} outside [1,64]: {id:?}",
            id_bytes.len(),
        );
        for &b in id_bytes {
            assert!(
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'),
                "identity byte 0x{b:02x} outside charset in {id:?}",
            );
        }
    }
});
