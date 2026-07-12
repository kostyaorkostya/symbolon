//! TPM2 wire marshaling for the two commands the signing backend
//! needs: `TPM2_ReadPublic` (startup key-shape check) and `TPM2_Sign`
//! (per-JWT RSASSA signature).
//!
//! Command construction and response-code decoding go through the
//! `tpm2-protocol` crate. The two response *parameters* we consume —
//! an RSASSA signature and a TPMT_PUBLIC — have fully determined
//! layouts for an RSA-2048 signing key, so they are parsed by hand
//! against the TCG "Structures" spec rather than through the crate's
//! zero-copy view machinery; the hermetic golden-vector tests below —
//! fixtures captured from a live swtpm — pin the result.

use tpm2_protocol::TpmWriter;
use tpm2_protocol::basic::TpmHandle;
use tpm2_protocol::data::{
    Tpm2bDigest, TpmAlgId, TpmRh, TpmSt, TpmaSession, TpmsAuthCommand, TpmsSchemeHash,
    TpmtSigScheme, TpmtTkHashcheck, TpmuSigScheme,
};
use tpm2_protocol::frame::{TpmReadPublicCommand, TpmSignCommand, tpm_marshal_command};

/// `TPM_RS_PW`: the password authorization session, used with empty
/// auth (the imported key has no authValue).
const TPM_RS_PW: u32 = 0x4000_0009;

/// TCG algorithm identifiers we assert against parsed responses.
const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_RSASSA: u16 = 0x0014;

fn marshal(
    cmd_bytes: &dyn Fn(&mut TpmWriter) -> Result<(), tpm2_protocol::TpmError>,
) -> Result<Vec<u8>, String> {
    let mut buf = [0u8; 4096];
    let mut writer = TpmWriter::new(&mut buf);
    cmd_bytes(&mut writer).map_err(|e| format!("marshal: {e:?}"))?;
    Ok(writer.as_bytes().to_vec())
}

/// `TPM2_ReadPublic(persistent_handle)`, NO_SESSIONS.
pub fn read_public_command(handle: u32) -> Result<Vec<u8>, String> {
    let cmd = TpmReadPublicCommand {
        handles: [TpmHandle::new(handle)],
    };
    marshal(&|w| tpm_marshal_command(&cmd, TpmSt::NoSessions, &[], w))
}

/// `TPM2_Sign(persistent_handle, digest)` with scheme RSASSA+SHA-256
/// and a null hashcheck ticket (the digest was computed outside the
/// TPM), authorized by a `TPM_RS_PW` session with empty auth.
pub fn sign_command(handle: u32, digest: &[u8; 32]) -> Result<Vec<u8>, String> {
    let cmd = TpmSignCommand {
        handles: [TpmHandle::new(handle)],
        digest: Tpm2bDigest::try_from(digest.as_slice()).map_err(|e| format!("digest: {e:?}"))?,
        in_scheme: TpmtSigScheme {
            scheme: TpmAlgId::Rsassa,
            details: TpmuSigScheme::Hash(TpmsSchemeHash {
                hash_alg: TpmAlgId::Sha256,
            }),
        },
        // Null ticket: the key is imported unrestricted, so a
        // TPM_ST_HASHCHECK / TPM_RH_NULL / empty-digest ticket is
        // accepted for an externally-computed digest.
        validation: TpmtTkHashcheck {
            tag: TpmSt::HashCheck,
            hierarchy: TpmRh::Null,
            digest: Tpm2bDigest::default(),
        },
    };
    let auth = TpmsAuthCommand {
        session_handle: TpmHandle::new(TPM_RS_PW),
        nonce: Default::default(),
        session_attributes: TpmaSession::default(),
        hmac: Default::default(),
    };
    marshal(&|w| tpm_marshal_command(&cmd, TpmSt::Sessions, &[auth], w))
}

/// Decode the 10-byte response header: `(tag, response_size, rc)`.
/// Returns an error unless `rc` is `TPM_RC_SUCCESS`. The `rc` is
/// decoded as the spec bitfield by the crate, so a format-1 (parameter
/// index) failure reports precisely.
fn response_ok(resp: &[u8]) -> Result<(), String> {
    use tpm2_protocol::data::{TpmRc, TpmRcBase};
    use tpm2_protocol::frame::TpmResponse;
    let response = TpmResponse::cast(resp).map_err(|e| format!("bad response: {e:?}"))?;
    let rc = response.rc().map_err(|e| format!("bad rc: {e:?}"))?;
    if matches!(rc, TpmRc::Fmt0(TpmRcBase::Success)) {
        Ok(())
    } else {
        Err(format!("TPM returned {rc:?}"))
    }
}

/// A minimal big-endian cursor over response bytes.
struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    fn u16(&mut self) -> Result<u16, String> {
        let end = self.i + 2;
        let s = self.b.get(self.i..end).ok_or("truncated u16")?;
        self.i = end;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, String> {
        let end = self.i + 4;
        let s = self.b.get(self.i..end).ok_or("truncated u32")?;
        self.i = end;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    /// A TPM2B: 2-byte size then that many bytes.
    fn tpm2b(&mut self) -> Result<&'a [u8], String> {
        let n = self.u16()? as usize;
        let end = self.i + n;
        let s = self.b.get(self.i..end).ok_or("truncated TPM2B")?;
        self.i = end;
        Ok(s)
    }
}

/// Parse a `TPM2_Sign` response into the raw RSASSA signature bytes.
/// The response is SESSIONS-tagged, so the body after the header is
/// `parameterSize(u32) || TPMT_SIGNATURE || authArea`. TPMT_SIGNATURE
/// for RSASSA is `sigAlg(u16=RSASSA) || hashAlg(u16) || TPM2B sig`.
pub fn parse_sign(resp: &[u8]) -> Result<Vec<u8>, String> {
    response_ok(resp)?;
    let body = resp.get(10..).ok_or("no body")?;
    let mut c = Cursor::new(body);
    let _param_size = c.u32()?;
    let sig_alg = c.u16()?;
    if sig_alg != TPM_ALG_RSASSA {
        return Err(format!("unexpected signature alg 0x{sig_alg:04x}"));
    }
    let _hash_alg = c.u16()?;
    let sig = c.tpm2b()?;
    Ok(sig.to_vec())
}

/// Parse a `TPM2_ReadPublic` response and verify the key is an
/// RSA-2048 asymmetric key. NO_SESSIONS response: body after the
/// header is `TPM2B_PUBLIC || TPM2B_NAME || TPM2B_QUALIFIED_NAME`.
/// TPM2B_PUBLIC wraps TPMT_PUBLIC:
/// `type(u16) || nameAlg(u16) || objectAttributes(u32) ||
///  authPolicy(TPM2B) || TPMS_RSA_PARMS || unique(TPM2B)`.
/// TPMS_RSA_PARMS: `symmetric(TPMT_SYM_DEF_OBJECT) ||
///  scheme(TPMT_RSA_SCHEME) || keyBits(u16) || exponent(u32)`.
/// For an unrestricted signing key `symmetric` is TPM_ALG_NULL (no
/// trailing fields) and `scheme` is NULL or RSASSA(+hash).
pub fn verify_rsa2048_signing_key(resp: &[u8]) -> Result<(), String> {
    response_ok(resp)?;
    let body = resp.get(10..).ok_or("no body")?;
    let mut outer = Cursor::new(body);
    let public = outer.tpm2b()?; // TPM2B_PUBLIC → TPMT_PUBLIC bytes
    let mut c = Cursor::new(public);
    let obj_type = c.u16()?;
    if obj_type != TPM_ALG_RSA {
        return Err(format!("key is not RSA (type 0x{obj_type:04x})"));
    }
    let _name_alg = c.u16()?;
    let _attrs = c.u32()?;
    let _auth_policy = c.tpm2b()?;
    // TPMT_SYM_DEF_OBJECT: algorithm; NULL means no keyBits/mode follow.
    let sym_alg = c.u16()?;
    if sym_alg != TPM_ALG_NULL {
        // A restricted/decrypt key carries a symmetric block we don't
        // model — the signing key must be unrestricted (sym = NULL).
        return Err(format!(
            "key symmetric alg 0x{sym_alg:04x} != NULL (not an unrestricted signing key)"
        ));
    }
    // TPMT_RSA_SCHEME: scheme; if not NULL, a hash alg follows.
    let scheme = c.u16()?;
    if scheme != TPM_ALG_NULL {
        let _scheme_hash = c.u16()?;
    }
    let key_bits = c.u16()?;
    if key_bits != 2048 {
        return Err(format!("key is RSA-{key_bits}, expected RSA-2048"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HANDLE: u32 = 0x8101_0001;

    // === Golden vectors captured from a live swtpm exchange ===
    //
    // Provisioned an RSA-2048 unrestricted signing key at persistent
    // handle 0x81010001, then recorded the exact command bytes we sent
    // and the exact response bytes swtpm returned, plus the key's public
    // part. Frozen here so the marshaling and BOTH response parsers are
    // pinned against a real TPM implementation with no external process
    // at test time. The gated end-to-end test in `tests/tpm_backend.rs`
    // re-runs the live exchange; re-capture from there if the fixtures
    // ever need refreshing (its header documents how).

    /// `TPM2_Sign` command — the exact bytes swtpm accepted and signed,
    /// for the digest of [`golden_signing_input`].
    const SIGN_COMMAND: &str = "8002000000490000015d810100010000000940000009000000000000200cc561b958b54213a57db59a406b7c747f25c04660d3c4396f93d78e6f5477a30014000b8024400000070000";

    /// `TPM2_ReadPublic` response for the key (TPM2B_PUBLIC wrapping the
    /// TPMT_PUBLIC, then name + qualified name).
    const READ_PUBLIC_RESPONSE: &str = "80010000016a0000000001160001000b0004007200000010001008000000000001009a2696410128f3296b5582f4465086e1ddab9c58f921c9132eec8d8518c182b24367c62d655c6d093c65d62954b1579ec8ec740a5713075c8282aa999627ad04eb84ef210d1f229f3f4a9b89d39e9324209fcd632219f838c2602cc3b1909ce2925c62bee396637da71e76d9e5ba8754be8b740de43c130ed11fd5fdbf0a3225e5c43f47162ac397e402216c6ad7086d5a3456d99645030c8d32fceaced72ae13d6dca729c061ef21c44ddee00ea508dc28f1a3cc697de6409ea36b407f8e55db125d30533e58393eff8bf3799372f36bc6e9dcc92ba230d0a7703512376edc6e8f39696fd03ad02c2256bde112ebff7e81cb41ad597749023b92605054e68a10022000b75897f26f10bb395375d3efe56d287f1439cb69225b522f4281f217b0af7dd6c0022000b36f3b4c80c68df5a47481c6d4845ef869777c601f4add92d64d8914db17e9bc0";

    /// `TPM2_Sign` response (TPMT_SIGNATURE) for the same digest, signed
    /// by the key below.
    const SIGN_RESPONSE: &str = "80020000011900000000000001060014000b010013b68d0957ea5ba66a7ef24c15ccd38d49131ff2790dc1a450bda6bfffcb2e034c09d2d12388c1ee589bd122703442bd7edef5340b2813856e7636a26e9629cee76134da9054f00b3aaadda1803ea36bf1adc50e31d68418c5e468411928be22e445c1f8033227aa9ef10cd56c3159f3403784340c5ad9db0856d37cd7f6ec5807415c0a6bee4cfe55d7a9b6a9d230cff467bf70cb90f1f3edbb4e29e2458b3d23c5a299cc5d0579df55d9ab4d6024a7df3cb058ab6189fd3ec0d3b44365ddc922badad42ad447c1ad6c138b7029692ad898a0bc4ba80caa417a2460160a129b0e2503b3d0d3813fd1ad3f0417f27395734765da129e41262c68453998db80990000010000";

    /// The signing key's public part, exported by `tpm2_readpublic` in
    /// the same run. Used to prove the parsed signature is genuine.
    const PUBLIC_KEY_PEM: &str = "\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmiaWQQEo8ylrVYL0RlCG
4d2rnFj5IckTLuyNhRjBgrJDZ8YtZVxtCTxl1ilUsVeeyOx0ClcTB1yCgqqZliet
BOuE7yENHyKfP0qbidOekyQgn81jIhn4OMJgLMOxkJziklxivuOWY32nHnbZ5bqH
VL6LdA3kPBMO0R/V/b8KMiXlxD9HFirDl+QCIWxq1whtWjRW2ZZFAwyNMvzqztcq
4T1tynKcBh7yHETd7gDqUI3Cjxo8xpfeZAnqNrQH+OVdsSXTBTPlg5Pv+L83mTcv
NrxuncySuiMNCncDUSN27cbo85aW/QOtAsIla94RLr/36By0GtWXdJAjuSYFBU5o
oQIDAQAB
-----END PUBLIC KEY-----
";

    /// Rebuild the exact JWS signing input the live exchange signed:
    /// the fixed test claims that `tests/tpm_backend.rs` uses. Its
    /// SHA-256 is the digest embedded in [`SIGN_COMMAND`] and signed in
    /// [`SIGN_RESPONSE`].
    fn golden_signing_input() -> String {
        use crate::providers::jwt_backend::JwtClaims;
        use std::time::{Duration, UNIX_EPOCH};
        let claims = JwtClaims::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            "Iv1.tpm-test",
        );
        crate::providers::jwt_rs256::signing_input(&claims).unwrap()
    }

    fn golden_digest() -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(golden_signing_input().as_bytes()).into()
    }

    #[test]
    fn read_public_command_kat() {
        let bytes = read_public_command(HANDLE).unwrap();
        // tag=8001(NO_SESSIONS) size=0000000e cc=00000173(ReadPublic)
        // handle=81010001
        assert_eq!(hex::encode(&bytes), "80010000000e0000017381010001");
    }

    #[test]
    fn sign_command_matches_live_capture() {
        // Byte-exact: the digest, RSASSA+SHA256 scheme, null hashcheck
        // ticket, and TPM_RS_PW session area must marshal to precisely
        // the command a real swtpm accepted. Any drift changes the hex.
        let bytes = sign_command(HANDLE, &golden_digest()).unwrap();
        assert_eq!(hex::encode(bytes), SIGN_COMMAND);
    }

    #[test]
    fn verify_rsa2048_accepts_live_read_public() {
        let resp = hex::decode(READ_PUBLIC_RESPONSE).unwrap();
        verify_rsa2048_signing_key(&resp).expect("live RSA-2048 key must pass");
    }

    #[test]
    fn verify_rsa2048_rejects_truncated() {
        // Chop the trailing name fields: the TPMT_PUBLIC walk must run
        // out of bytes and error rather than mis-read.
        let resp = hex::decode(READ_PUBLIC_RESPONSE).unwrap();
        assert!(verify_rsa2048_signing_key(&resp[..resp.len() - 48]).is_err());
    }

    #[test]
    fn parse_sign_extracts_verifiable_signature_from_live_response() {
        use rsa::RsaPublicKey;
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::pkcs8::DecodePublicKey;
        use rsa::signature::Verifier;
        use sha2::Sha256;

        let resp = hex::decode(SIGN_RESPONSE).unwrap();
        let sig = parse_sign(&resp).unwrap();
        assert_eq!(sig.len(), 256, "RSA-2048 signature is 256 bytes");

        // The extracted bytes must be a genuine RSASSA-PKCS1v1.5 SHA-256
        // signature over the signing input, under the key the same run
        // exported — proving the parse located the real signature, not
        // just some plausible TPM2B.
        let public = RsaPublicKey::from_public_key_pem(PUBLIC_KEY_PEM).unwrap();
        let vk = VerifyingKey::<Sha256>::new(public);
        let signature = Signature::try_from(sig.as_slice()).unwrap();
        vk.verify(golden_signing_input().as_bytes(), &signature)
            .expect("signature parsed from the live TPM response must verify");
    }

    #[test]
    fn parse_sign_rejects_error_rc() {
        // A response header with a non-success RC must be rejected.
        // tag=8001 size=0000000a rc=00000101 (TPM_RC_FAILURE)
        let resp = hex::decode("80010000000a00000101").unwrap();
        assert!(parse_sign(&resp).is_err());
    }
}
