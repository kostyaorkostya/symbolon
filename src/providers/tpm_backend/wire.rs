//! TPM2 wire marshaling for the two commands the signing backend
//! needs: `TPM2_ReadPublic` (startup key-shape check) and `TPM2_Sign`
//! (per-JWT RSASSA signature).
//!
//! Command construction and response-code decoding go through the
//! `tpm2-protocol` crate. The two response *parameters* we consume —
//! an RSASSA signature and a TPMT_PUBLIC — have fully determined
//! layouts for an RSA-2048 signing key, so they are parsed by hand
//! against the TCG "Structures" spec rather than through the crate's
//! zero-copy view machinery; the swtpm smoke test pins the result.

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

    // A fixed persistent handle + digest for byte-exact KATs. These
    // pin the command encoding without a TPM; if the marshaling drifts
    // (field order, scheme bytes, session area) the hex changes.
    const HANDLE: u32 = 0x8101_0001;

    #[test]
    fn read_public_command_kat() {
        let bytes = read_public_command(HANDLE).unwrap();
        // tag=8001(NO_SESSIONS) size=0000000e cc=00000173(ReadPublic)
        // handle=81010001
        assert_eq!(hex::encode(&bytes), "80010000000e0000017381010001");
    }

    #[test]
    fn sign_command_kat() {
        let digest = [0xABu8; 32];
        let bytes = sign_command(HANDLE, &digest).unwrap();
        let round = TpmResponseHeaderless::check(&bytes);
        // Structural assertions (exact hex is pinned once observed):
        // tag=8002 (SESSIONS), commandCode=0000015d (Sign), handle,
        // then auth area + params.
        assert_eq!(&bytes[0..2], &[0x80, 0x02], "SESSIONS tag");
        assert_eq!(&bytes[6..10], &[0x00, 0x00, 0x01, 0x5d], "TPM_CC_Sign");
        assert_eq!(&bytes[10..14], &[0x81, 0x01, 0x00, 0x01], "signing handle");
        assert!(round, "command size field matches actual length");
    }

    /// Helper: confirm the command's `commandSize` header field equals
    /// the actual buffer length (a common marshaling bug).
    struct TpmResponseHeaderless;
    impl TpmResponseHeaderless {
        fn check(bytes: &[u8]) -> bool {
            if bytes.len() < 10 {
                return false;
            }
            let size = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
            size == bytes.len()
        }
    }

    #[test]
    fn parse_sign_rejects_error_rc() {
        // A response header with a non-success RC must be rejected.
        // tag=8001 size=0000000a rc=00000101 (TPM_RC_FAILURE)
        let resp = hex::decode("80010000000a00000101").unwrap();
        assert!(parse_sign(&resp).is_err());
    }

    #[test]
    fn parse_sign_extracts_signature() {
        // Craft a minimal SESSIONS Sign response:
        // header(10) paramSize(4) sigAlg(2=RSASSA) hashAlg(2=SHA256)
        // TPM2B sig(size=4, bytes=DEADBEEF) authArea(ignored)
        let mut resp = Vec::new();
        resp.extend_from_slice(&hex::decode("8002").unwrap()); // tag SESSIONS
        resp.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
        resp.extend_from_slice(&[0, 0, 0, 0]); // rc success
        let params_and_auth = {
            let mut p = Vec::new();
            p.extend_from_slice(&0x0014u16.to_be_bytes()); // RSASSA
            p.extend_from_slice(&0x000Bu16.to_be_bytes()); // SHA256
            p.extend_from_slice(&4u16.to_be_bytes()); // TPM2B size
            p.extend_from_slice(&hex::decode("deadbeef").unwrap());
            p
        };
        let param_size = params_and_auth.len() as u32;
        resp.extend_from_slice(&param_size.to_be_bytes());
        resp.extend_from_slice(&params_and_auth);
        let total = resp.len() as u32;
        resp[2..6].copy_from_slice(&total.to_be_bytes());
        let sig = parse_sign(&resp).unwrap();
        assert_eq!(hex::encode(sig), "deadbeef");
    }
}
