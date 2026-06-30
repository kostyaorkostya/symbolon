//! Minimal RS256 JWS signer: RSASSA-PKCS1-v1_5 with SHA-256, JWA
//! `alg = "RS256"`. The only JOSE algorithm the GitHub provider
//! uses. Header format is fixed at `{"typ":"JWT","alg":"RS256"}`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use serde::Serialize;
use sha2::Sha256;

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("PEM is not valid UTF-8")]
    PemUtf8,
    #[error("PEM parse failed — not a recognised PKCS#1 or PKCS#8 RSA private key")]
    PemParse,
    #[error("claims serialization failed")]
    SerializeClaims(#[source] serde_json::Error),
}

/// Base64url-no-pad encoding of the fixed JWT header
/// `{"typ":"JWT","alg":"RS256"}`. The bytes never change, so the
/// JSON-serialise + base64-encode work is moved to compile time.
/// Cross-verified by the `known_vector_round_trip` test below.
const HEADER_B64: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9";

/// Pre-built RS256 signing key. Construction parses the PEM and
/// precomputes the inner state; subsequent `sign` calls are
/// allocation-light (the RSA bignum work dominates).
pub struct JwtSigningKey(SigningKey<Sha256>);

impl JwtSigningKey {
    /// Load an RSA private key from PEM. Tries PKCS#8 first
    /// (`-----BEGIN PRIVATE KEY-----`, which our test fixture
    /// uses), then PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`,
    /// which is what GitHub's downloadable App keys carry).
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, JwtError> {
        let pem = std::str::from_utf8(pem_bytes).map_err(|_| JwtError::PemUtf8)?;
        let pkey = RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|_| JwtError::PemParse)?;
        Ok(Self(SigningKey::<Sha256>::new(pkey)))
    }

    /// Produce a compact JWS:
    /// `base64url(header).base64url(payload).base64url(signature)`.
    /// `claims` is serialised to JSON via serde; the header is
    /// fixed at `{"typ":"JWT","alg":"RS256"}` and precomputed as
    /// [`HEADER_B64`]. RSASSA-PKCS1-v1_5 is deterministic, so the
    /// output is reproducible for any given (claims, key) pair.
    ///
    /// The whole token is built in one `String` buffer: the
    /// `header.payload` prefix doubles as the RS256 signing input,
    /// so no intermediate `Vec` / `String` allocations are needed
    /// per call beyond `payload_json` and the boxed signature bytes
    /// `rsa`'s `SignatureEncoding::to_bytes` returns.
    pub fn sign_rs256<C: Serialize>(&self, claims: &C) -> Result<String, JwtError> {
        let payload_json = serde_json::to_vec(claims).map_err(JwtError::SerializeClaims)?;
        // Rough upper bound: header + '.' + b64(payload) + '.' + b64(sig).
        // For 2048-bit RS256 the signature is 256 bytes → 342 base64 chars.
        let payload_b64_len = payload_json.len().div_ceil(3) * 4;
        let mut token = String::with_capacity(HEADER_B64.len() + 1 + payload_b64_len + 1 + 350);
        token.push_str(HEADER_B64);
        token.push('.');
        URL_SAFE_NO_PAD.encode_string(&payload_json, &mut token);
        // `header_b64.payload_b64` IS the RS256 signing input.
        let signature = self.0.sign(token.as_bytes());
        token.push('.');
        URL_SAFE_NO_PAD.encode_string(signature.to_bytes(), &mut token);
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use std::path::PathBuf;

    fn fixture_pem_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test_app_key.pem")
    }

    fn fixture_pem_bytes() -> Vec<u8> {
        std::fs::read(fixture_pem_path()).unwrap()
    }

    #[derive(Serialize)]
    struct TestClaims {
        iss: String,
        iat: u64,
        exp: u64,
    }

    fn test_claims() -> TestClaims {
        // Same shape and values as `build_claims(t(1_700_000_000),
        // "Iv1.test42")` in github.rs, so the byte-equivalence
        // test below can be cross-checked against that path.
        TestClaims {
            iss: "Iv1.test42".to_string(),
            iat: 1_699_999_940,
            exp: 1_700_000_540,
        }
    }

    #[test]
    fn from_pem_accepts_pkcs8_fixture() {
        let key = JwtSigningKey::from_pem(&fixture_pem_bytes());
        assert!(key.is_ok(), "PKCS#8 fixture should parse");
    }

    #[test]
    fn from_pem_rejects_garbage() {
        let res = JwtSigningKey::from_pem(b"not a PEM");
        assert!(matches!(res, Err(JwtError::PemParse)));
    }

    #[test]
    fn sign_produces_three_dot_separated_segments() {
        let key = JwtSigningKey::from_pem(&fixture_pem_bytes()).unwrap();
        let token = key.sign_rs256(&test_claims()).unwrap();
        assert_eq!(token.split('.').count(), 3);
    }

    /// Pin the exact signed token. RSASSA-PKCS1-v1_5 is
    /// deterministic — given the same claims + key, the token is
    /// fully reproducible. If this fails, our serialisation
    /// drifted (claim ordering, header shape) or `rsa`/`sha2`
    /// upstream changed the signature output.
    #[test]
    fn known_vector_round_trip() {
        let expected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJJdjEudGVzdDQyIiwiaWF0IjoxNjk5OTk5OTQwLCJleHAiOjE3MDAwMDA1NDB9.yPTDonwO4souVu_3nk7Aq8ZbiAq3PBVLHRJ5J6B67JHmUxVh-yvIoXdQ8O_EAqj-H57GKRAo_b0nu6hQT_keD9-wB_ah8DC_ZqtV42S3jHACWAdEG066W1XdKUftU82QkdSM5hrpdg9OvFN6i7m0ObCJi3uJMWXYb8lY1LYJew0SWajBzLKQjw47Qmbq-AYiTgkdBoRfK5TrD64u6wd0aQCathxELkaiEacilUtU6ZH8jOQ_W5hYjjwxjTF7wbNWdx-v7M3yUSUn_01Sn9w2bTLeimsP4e81ydchLhIeJED4iF-j-QG_uBlhp0auwTPYqPaG6Zh-qhbkE0DJaV-log";
        let key = JwtSigningKey::from_pem(&fixture_pem_bytes()).unwrap();
        let got = key.sign_rs256(&test_claims()).unwrap();
        assert_eq!(got, expected, "RS256 signature must be reproducible");
    }
}
