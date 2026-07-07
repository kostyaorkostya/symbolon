//! Broker static X25519 keypair newtypes for the Noise NKpsk2
//! transport.
//!
//! The private key is 32 raw bytes read from `[listen]
//! static_key_file` (64 hex chars; generate with `openssl rand -hex
//! 32`). Any 32-byte value is a valid X25519 private key — RFC 7748
//! clamping is applied inside every scalar multiplication, both here
//! (`mul_base_clamped`) and in snow's DH — so no keygen tool is
//! needed.
//!
//! The public key is derived, not stored: the daemon computes it at
//! startup and surfaces it via the `pubkey` admin op and the
//! `startup` log event. Clients pin it in their key file
//! (`broker_pub_hex:psk_hex`).

use curve25519_dalek::montgomery::MontgomeryPoint;

/// Broker static X25519 private key. Redacted `Debug`; no `Display`
/// or `LowerHex` — unlike [`crate::psk::Psk`] this value is never
/// rendered back out (the daemon only reads it from disk and the
/// operator generated the file themselves).
#[derive(Clone)]
pub struct BrokerPrivateKey([u8; Self::LEN]);

impl std::fmt::Debug for BrokerPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BrokerPrivateKey(<redacted>)")
    }
}

impl From<[u8; Self::LEN]> for BrokerPrivateKey {
    fn from(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }
}

impl hex::FromHex for BrokerPrivateKey {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut out = [0u8; Self::LEN];
        hex::decode_to_slice(hex, &mut out)?;
        Ok(Self(out))
    }
}

impl BrokerPrivateKey {
    /// X25519 private-key length, fixed by the `25519` DH function in
    /// `NOISE_PATTERN` (see `transport.rs`).
    pub const LEN: usize = 32;

    /// Borrow the raw bytes for snow's `Builder::local_private_key`.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Derive the public key: clamped scalar multiplication of the
    /// X25519 basepoint. `mul_base_clamped` is the exact call snow's
    /// default resolver uses in `Dh25519::derive_pubkey`, so this
    /// derivation is bit-identical to what the handshake computes.
    pub fn derive_public(&self) -> BrokerPublicKey {
        BrokerPublicKey(MontgomeryPoint::mul_base_clamped(self.0).to_bytes())
    }
}

/// Broker static X25519 public key. Not a secret — clients pin it,
/// logs print it — so `Display` renders lowercase hex directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrokerPublicKey([u8; BrokerPrivateKey::LEN]);

impl std::fmt::Display for BrokerPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut buf = [0u8; BrokerPrivateKey::LEN * 2];
        hex::encode_to_slice(self.0, &mut buf).expect("output buffer sized for 2x input length");
        f.write_str(std::str::from_utf8(&buf).expect("hex output is ASCII"))
    }
}

impl From<[u8; BrokerPrivateKey::LEN]> for BrokerPublicKey {
    fn from(bytes: [u8; BrokerPrivateKey::LEN]) -> Self {
        Self(bytes)
    }
}

impl hex::FromHex for BrokerPublicKey {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut out = [0u8; BrokerPrivateKey::LEN];
        hex::decode_to_slice(hex, &mut out)?;
        Ok(Self(out))
    }
}

impl BrokerPublicKey {
    /// Borrow the raw bytes for snow's `Builder::remote_public_key`.
    pub fn as_bytes(&self) -> &[u8; BrokerPrivateKey::LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn debug_is_redacted() {
        let key = BrokerPrivateKey::from([0x42u8; 32]);
        assert_eq!(format!("{key:?}"), "BrokerPrivateKey(<redacted>)");
    }

    #[test]
    fn public_key_display_round_trips_hex() {
        let key = BrokerPrivateKey::from([7u8; 32]);
        let public = key.derive_public();
        let rendered = public.to_string();
        assert_eq!(rendered.len(), 64);
        let reparsed = BrokerPublicKey::from_hex(&rendered).unwrap();
        assert_eq!(reparsed, public);
    }

    /// Pin the derivation against an independent implementation:
    /// vector computed with python `cryptography` (OpenSSL X25519,
    /// private bytes = 32 x 0x42). Catches both a broken
    /// `mul_base_clamped` call and any future dalek regression.
    #[test]
    fn derive_public_known_vector() {
        let key = BrokerPrivateKey::from([0x42u8; 32]);
        let public = key.derive_public();
        assert_eq!(
            public.to_string(),
            "132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f472"
        );
    }
}
