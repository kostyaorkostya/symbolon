//! 32-byte pre-shared key newtype shared by `psk_store` (collection,
//! file format) and `transport` (Noise handshake input).
//!
//! Lives in its own module rather than `psk_store` because `Psk` is a
//! primitive value type with no store semantics — both the collection
//! and the lower-level Noise plumbing want it.

use derive_more::From;
use serde::{Deserialize, Serialize};

/// 32-byte pre-shared key with a deliberately redacted `Debug` impl.
/// Without the newtype, the raw `[u8; 32]` inside `PskStore` (which
/// derives `Debug`) would print every byte whenever an operator-side
/// log line dumped the store, even though the operator-side
/// mitigation (mlockall + LimitCORE=0) only covers swap and
/// coredumps — not deliberate `Debug` formatting.
///
/// Construction is open (any 32 bytes is a valid PSK); the type just
/// proves the length invariant the Noise handshake requires.
///
/// `Serialize`/`Deserialize` go through `#[serde(transparent)]` to
/// the inner `[u8; LEN]` — that's a JSON array of numbers on the
/// admin wire. The admin protocol is internal (UDS, UID-gated) so
/// wire ergonomics don't justify a hex-string adapter. The on-disk
/// PSK file uses hex, but that path goes through `to_hex` /
/// `hex::FromHex` explicitly, not serde.
#[derive(Clone, Copy, PartialEq, Eq, From, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Psk([u8; Self::LEN]);

impl std::fmt::Debug for Psk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Psk(<redacted>)")
    }
}

/// Hex *output* via the standard `{:x}` formatter. Hex is the on-disk
/// file format (see `psk_store::render`) and the CLI's enroll-success
/// JSON field; both go through `format!("{:x}", psk)` /
/// `write!(out, "{:x}", psk)`. The corresponding `Display` (`{}`) is
/// deliberately NOT implemented so a stray `{}` formatter can't
/// leak the secret — `{:x}` is the opt-in form.
impl std::fmt::LowerHex for Psk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut buf = [0u8; Self::HEX_LEN];
        hex::encode_to_slice(self.0, &mut buf).expect("output buffer sized for 2× input length");
        // SAFETY: `hex::encode_to_slice` writes only ASCII bytes in the
        // sets `b'0'..=b'9'` and `b'a'..=b'f'`, each of which is valid
        // single-byte UTF-8. Skipping `from_utf8`'s validation pass over
        // 64 known-ASCII bytes is the only reason to reach for `unsafe`
        // here — the alternative `expect("ascii")` is morally identical
        // but pays for a redundant scan on every PSK render.
        f.write_str(unsafe { std::str::from_utf8_unchecked(&buf) })
    }
}

/// Hex *input* via the standard `hex::FromHex` trait. Callers need
/// `use hex::FromHex;` in scope to invoke `Psk::from_hex(...)`. The
/// input is `T: AsRef<[u8]>` — accepts `&str`, `&[u8]`, `String`, etc.
impl hex::FromHex for Psk {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut out = [0u8; Self::LEN];
        hex::decode_to_slice(hex, &mut out)?;
        Ok(Self(out))
    }
}

impl Psk {
    /// Byte length of a Noise NKpsk2 pre-shared key. Fixed by the
    /// protocol — see `NOISE_PATTERN` in `transport.rs`.
    pub const LEN: usize = 32;

    /// Length of the ASCII hex rendering produced by `{:x}` (two
    /// chars per byte). Exported so callers sizing buffers can
    /// express their capacity as a sum of named constants instead of
    /// hardcoding `64`.
    pub const HEX_LEN: usize = Self::LEN * 2;

    /// Borrow the raw bytes. Use when handing the PSK to a lower-level
    /// API (e.g. snow's `Builder::psk`) that doesn't need ownership.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Fresh PSK from the OS RNG.
    pub fn random() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; Self::LEN];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }
}
