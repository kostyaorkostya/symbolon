//! 32-byte pre-shared key newtype shared by `psk_store` (collection,
//! file format) and `transport` (Noise handshake input).
//!
//! Lives in its own module rather than `psk_store` because `Psk` is a
//! primitive value type with no store semantics — both the collection
//! and the lower-level Noise plumbing want it.

use derive_more::From;

/// 32-byte pre-shared key with a deliberately redacted `Debug` impl.
/// Without the newtype, the raw `[u8; 32]` inside `PskStore` (which
/// derives `Debug`) would print every byte whenever an operator-side
/// log line dumped the store, even though the operator-side
/// mitigation (mlockall + LimitCORE=0) only covers swap and
/// coredumps — not deliberate `Debug` formatting.
///
/// Construction is open (any 32 bytes is a valid PSK); the type just
/// proves the length invariant the Noise handshake requires.
#[derive(Clone, Copy, PartialEq, Eq, From)]
pub struct Psk([u8; Self::LEN]);

impl std::fmt::Debug for Psk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Psk(<redacted>)")
    }
}

impl Psk {
    /// Byte length of a Noise NNpsk0 pre-shared key. Fixed by the
    /// protocol — see `NOISE_PATTERN` in `transport.rs`.
    pub const LEN: usize = 32;

    /// Borrow the raw bytes. Use when handing the PSK to a lower-level
    /// API (e.g. snow's `Builder::psk`) that doesn't need ownership.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Consume and return the raw bytes. Use when the receiver wants
    /// owned `[u8; 32]` and the caller has no further need for the Psk.
    pub fn into_bytes(self) -> [u8; Self::LEN] {
        self.0
    }

    /// Decode a 64-char ASCII hex string into a 32-byte `Psk`. Errors
    /// propagate `hex::FromHexError` verbatim so callers can attach
    /// their own context (line number, source path) at the boundary
    /// that has it.
    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        let mut out = [0u8; Self::LEN];
        hex::decode_to_slice(hex_str, &mut out)?;
        Ok(Self(out))
    }

    /// Render to the 64-byte ASCII hex form used by the on-disk PSK
    /// file. Returns a fixed-size array (no heap allocation) since
    /// the output length is statically known. Callers that need a
    /// `&str` convert via `std::str::from_utf8(&out).expect("ascii")`
    /// — the bytes are ASCII by construction (`[0-9a-f]`).
    ///
    /// The explicit method (rather than `impl Display`) keeps the
    /// secret bytes from accidentally leaking through `{}`
    /// formatters. `self` by value because `Psk` is `Copy`; clippy's
    /// `wrong_self_convention` expects this for `to_*` on Copy types.
    pub fn to_hex(self) -> [u8; Self::LEN * 2] {
        let mut out = [0u8; Self::LEN * 2];
        hex::encode_to_slice(self.0, &mut out).expect("output buffer sized for 2× input length");
        out
    }
}
