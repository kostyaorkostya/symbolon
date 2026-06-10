// Allowed until Phase 4 wires this module into the daemon's accept loop and
// Phase 2 adds the client binary that drives it from the initiator side.
#![allow(dead_code)]

//! Noise NNpsk0 transport: identity prelude, framing, and snow handshake
//! orchestration. I/O-agnostic — callers supply bytes; this module owns the
//! `HandshakeState` / `TransportState` machinery.
//!
//! Two callers:
//! - daemon (compio async): drives the responder side after accepting a TCP
//!   connection.
//! - `git-credential-symbolon` client binary (sync std::net): drives the
//!   initiator side.
//!
//! Wire shape:
//! ```text
//! Identity prelude (sent once, before the Noise handshake):
//!   +--------+---+---+----------------+
//!   | "SBLN" | V | L | identity bytes |
//!   +--------+---+---+----------------+
//!      4      1   1       L (1..=64)
//!
//! Per-message framing (used for the Noise handshake messages AND post-handshake
//! transport messages):
//!   +-----------+--------------------+
//!   | len (u16) | message body bytes |
//!   +-----------+--------------------+
//!        2              len
//! ```
//!
//! The identity prelude is cleartext — an attacker on the wire learns which
//! client identity is being used, but without the PSK they can't impersonate
//! or decrypt anything.

use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};

/// `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`. NN (no static keys), `psk0` mixes
/// the pre-shared key before the handshake; 1-RTT.
pub const NOISE_PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";

/// Snow constrains a single Noise message to at most 65535 bytes, which fits
/// in our u16 length prefix exactly. Buffers sized to this allow any valid
/// message to be processed in-place.
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Identity prelude magic bytes. Picked to be invalid as a Noise message and
/// distinctive in tcpdump.
pub const PRELUDE_MAGIC: [u8; 4] = *b"SBLN";

/// Identity prelude format version. Incremented if the prelude layout ever
/// changes; daemon rejects unknown versions.
pub const PRELUDE_VERSION: u8 = 0x01;

/// Maximum identity byte length. Matches the practical-name range; chosen so
/// a malformed prelude can never exceed `6 + MAX_IDENTITY_LEN` bytes.
pub const MAX_IDENTITY_LEN: usize = 64;

/// Errors raised when parsing or validating the identity prelude.
#[derive(Debug, thiserror::Error)]
pub enum PreludeError {
    #[error("prelude is incomplete: need {needed} more bytes")]
    Incomplete { needed: usize },
    #[error("prelude magic mismatch (got {got:?}, expected {:?})", PRELUDE_MAGIC)]
    BadMagic { got: [u8; 4] },
    #[error("prelude version {got} not supported (expected {PRELUDE_VERSION})")]
    BadVersion { got: u8 },
    #[error("prelude identity length {got} out of range (1..={MAX_IDENTITY_LEN})")]
    BadIdentityLen { got: u8 },
    #[error(
        "prelude identity byte 0x{byte:02x} at offset {offset} is outside the allowed \
         charset [A-Za-z0-9._-]"
    )]
    InvalidCharset { offset: usize, byte: u8 },
}

/// Errors raised when constructing or driving the Noise handshake.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("constructing Noise handshake parameters failed")]
    Params(#[source] snow::Error),
    #[error("PSK must be exactly 32 bytes; got {got}")]
    BadPskLen { got: usize },
    #[error("Noise handshake step failed")]
    Handshake(#[source] snow::Error),
    #[error("Noise transport mode transition failed")]
    Transition(#[source] snow::Error),
    #[error("Noise transport read/write failed")]
    Transport(#[source] snow::Error),
    #[error("framed message length {got} exceeds maximum {MAX_MESSAGE_SIZE}")]
    OversizedFrame { got: usize },
}

/// Parsed identity prelude. Borrows the identity bytes from the input buffer;
/// callers can clone into an owned `String` via [`Identity::to_string`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity<'a>(&'a str);

impl<'a> Identity<'a> {
    /// The raw identity string. Guaranteed to match `[A-Za-z0-9._-]+` and to
    /// be between 1 and `MAX_IDENTITY_LEN` bytes long.
    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl std::fmt::Display for Identity<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Validate the identity charset: ASCII alphanumeric or one of `.`, `_`, `-`.
/// Rejects CR/LF/NUL/whitespace by construction. Same rule as the
/// git-credential value rule (AGENTS.md invariant #12 in spirit).
fn identity_byte_ok(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
}

/// Total prelude byte length given an identity length.
pub const fn prelude_size(identity_len: usize) -> usize {
    6 + identity_len
}

/// Encode an identity into prelude bytes. Returns `None` if the identity
/// length or charset is invalid (so the client can fail-fast rather than send
/// bytes the server will reject).
pub fn encode_prelude(identity: &str) -> Option<Vec<u8>> {
    let bytes = identity.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_IDENTITY_LEN {
        return None;
    }
    if !bytes.iter().all(|b| identity_byte_ok(*b)) {
        return None;
    }
    let mut out = Vec::with_capacity(prelude_size(bytes.len()));
    out.extend_from_slice(&PRELUDE_MAGIC);
    out.push(PRELUDE_VERSION);
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
    Some(out)
}

/// Parse a prelude from `input`. On success returns the borrowed identity and
/// the byte length consumed. The caller slices `input[consumed..]` to find
/// the first Noise framed message.
pub fn parse_prelude(input: &[u8]) -> Result<(Identity<'_>, usize), PreludeError> {
    if input.len() < 6 {
        return Err(PreludeError::Incomplete {
            needed: 6 - input.len(),
        });
    }
    let magic: [u8; 4] = input[0..4].try_into().expect("slice of length 4");
    if magic != PRELUDE_MAGIC {
        return Err(PreludeError::BadMagic { got: magic });
    }
    let version = input[4];
    if version != PRELUDE_VERSION {
        return Err(PreludeError::BadVersion { got: version });
    }
    let id_len = input[5];
    if id_len == 0 || (id_len as usize) > MAX_IDENTITY_LEN {
        return Err(PreludeError::BadIdentityLen { got: id_len });
    }
    let total = prelude_size(id_len as usize);
    if input.len() < total {
        return Err(PreludeError::Incomplete {
            needed: total - input.len(),
        });
    }
    let id_bytes = &input[6..total];
    for (offset, &b) in id_bytes.iter().enumerate() {
        if !identity_byte_ok(b) {
            return Err(PreludeError::InvalidCharset { offset, byte: b });
        }
    }
    // SAFETY: identity_byte_ok only accepts ASCII bytes, so the slice is valid UTF-8.
    let id_str = std::str::from_utf8(id_bytes).expect("ascii-only by construction");
    Ok((Identity(id_str), total))
}

/// Build the responder (server) side of `NOISE_PATTERN` with the given 32-byte PSK.
pub fn responder(psk: &[u8]) -> Result<HandshakeState, TransportError> {
    build_handshake(psk, /* initiator */ false)
}

/// Build the initiator (client) side of `NOISE_PATTERN` with the given 32-byte PSK.
pub fn initiator(psk: &[u8]) -> Result<HandshakeState, TransportError> {
    build_handshake(psk, /* initiator */ true)
}

fn build_handshake(psk: &[u8], initiator: bool) -> Result<HandshakeState, TransportError> {
    let psk_array: &[u8; 32] = psk
        .try_into()
        .map_err(|_| TransportError::BadPskLen { got: psk.len() })?;
    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|e: snow::Error| TransportError::Params(e))?;
    let builder = Builder::new(params)
        .psk(0, psk_array)
        .map_err(TransportError::Handshake)?;
    if initiator {
        builder.build_initiator().map_err(TransportError::Handshake)
    } else {
        builder.build_responder().map_err(TransportError::Handshake)
    }
}

/// Transition a completed handshake into transport mode.
pub fn into_transport(hs: HandshakeState) -> Result<TransportState, TransportError> {
    hs.into_transport_mode().map_err(TransportError::Transition)
}

/// Encode `payload` for the wire: 2-byte big-endian length prefix followed by the
/// payload bytes. Suitable for both Noise handshake messages and post-handshake
/// transport messages.
pub fn frame(payload: &[u8]) -> Result<Vec<u8>, TransportError> {
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(TransportError::OversizedFrame { got: payload.len() });
    }
    let len = payload.len() as u16;
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Read the 2-byte BE length prefix from the head of `buf`. Returns the
/// declared payload length on success.
pub fn read_frame_length(buf: &[u8; 2]) -> Result<usize, TransportError> {
    let len = u16::from_be_bytes(*buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(TransportError::OversizedFrame { got: len });
    }
    Ok(len)
}

/// Apply the Noise handshake responder transform to one inbound message.
/// `out` must be at least `MAX_MESSAGE_SIZE` long. Returns the number of plaintext
/// bytes written into `out` (always 0 for NNpsk0 — no static payloads).
pub fn handshake_read(
    hs: &mut HandshakeState,
    msg: &[u8],
    out: &mut [u8],
) -> Result<usize, TransportError> {
    hs.read_message(msg, out).map_err(TransportError::Handshake)
}

/// Produce the next Noise handshake message into `out`. Returns the number of
/// bytes written.
pub fn handshake_write(
    hs: &mut HandshakeState,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, TransportError> {
    hs.write_message(payload, out)
        .map_err(TransportError::Handshake)
}

/// Decrypt a post-handshake transport message into `out`. Returns the number of
/// plaintext bytes written.
pub fn transport_read(
    ts: &mut TransportState,
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<usize, TransportError> {
    ts.read_message(ciphertext, out)
        .map_err(TransportError::Transport)
}

/// Encrypt a post-handshake transport message into `out`. Returns the number of
/// ciphertext bytes written.
pub fn transport_write(
    ts: &mut TransportState,
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, TransportError> {
    ts.write_message(plaintext, out)
        .map_err(TransportError::Transport)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_identity() -> &'static str {
        "dev-vm-1.test_03"
    }

    #[test]
    fn prelude_round_trip() {
        let id = good_identity();
        let bytes = encode_prelude(id).expect("identity is valid");
        assert_eq!(bytes.len(), prelude_size(id.len()));
        let (parsed, consumed) = parse_prelude(&bytes).expect("round-trip parse");
        assert_eq!(parsed.as_str(), id);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn prelude_rejects_short_buffer() {
        for prefix_len in 0..6 {
            let bytes = vec![0u8; prefix_len];
            match parse_prelude(&bytes) {
                Err(PreludeError::Incomplete { needed }) => {
                    assert_eq!(needed, 6 - prefix_len);
                }
                other => panic!("expected Incomplete, got {other:?}"),
            }
        }
    }

    #[test]
    fn prelude_rejects_bad_magic() {
        let mut bytes = encode_prelude("foo").unwrap();
        bytes[0] = b'X';
        assert!(matches!(
            parse_prelude(&bytes),
            Err(PreludeError::BadMagic { .. })
        ));
    }

    #[test]
    fn prelude_rejects_bad_version() {
        let mut bytes = encode_prelude("foo").unwrap();
        bytes[4] = 0x99;
        assert!(matches!(
            parse_prelude(&bytes),
            Err(PreludeError::BadVersion { got: 0x99 })
        ));
    }

    #[test]
    fn prelude_rejects_zero_length() {
        // Hand-build a malformed prelude with id_len = 0.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PRELUDE_MAGIC);
        bytes.push(PRELUDE_VERSION);
        bytes.push(0);
        assert!(matches!(
            parse_prelude(&bytes),
            Err(PreludeError::BadIdentityLen { got: 0 })
        ));
    }

    #[test]
    fn prelude_rejects_oversized_id_len() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PRELUDE_MAGIC);
        bytes.push(PRELUDE_VERSION);
        bytes.push((MAX_IDENTITY_LEN as u8) + 1);
        bytes.resize(bytes.len() + MAX_IDENTITY_LEN + 1, b'a');
        assert!(matches!(
            parse_prelude(&bytes),
            Err(PreludeError::BadIdentityLen { .. })
        ));
    }

    #[test]
    fn prelude_rejects_incomplete_identity() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PRELUDE_MAGIC);
        bytes.push(PRELUDE_VERSION);
        bytes.push(10);
        // ...but only 3 identity bytes follow
        bytes.extend_from_slice(b"abc");
        match parse_prelude(&bytes) {
            Err(PreludeError::Incomplete { needed }) => assert_eq!(needed, 7),
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }

    #[test]
    fn prelude_rejects_invalid_charset() {
        // CR is the canonical Clone2Leak-class injection byte we defend against
        // in git_credential too.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PRELUDE_MAGIC);
        bytes.push(PRELUDE_VERSION);
        bytes.push(3);
        bytes.extend_from_slice(b"a\rb");
        assert!(matches!(
            parse_prelude(&bytes),
            Err(PreludeError::InvalidCharset {
                offset: 1,
                byte: b'\r'
            })
        ));
    }

    #[test]
    fn encode_rejects_empty_identity() {
        assert!(encode_prelude("").is_none());
    }

    #[test]
    fn encode_rejects_too_long() {
        let id = "a".repeat(MAX_IDENTITY_LEN + 1);
        assert!(encode_prelude(&id).is_none());
    }

    #[test]
    fn encode_rejects_bad_charset() {
        assert!(encode_prelude("foo bar").is_none()); // space
        assert!(encode_prelude("foo/bar").is_none()); // slash
        assert!(encode_prelude("foo\nbar").is_none()); // LF
    }

    /// End-to-end Noise NNpsk0 handshake + a transport-mode message round-trip,
    /// driven entirely in-memory.
    #[test]
    fn noise_handshake_round_trip() {
        let psk = [0x42u8; 32];

        let mut initiator_hs = initiator(&psk).expect("build initiator");
        let mut responder_hs = responder(&psk).expect("build responder");

        let mut buf_i_to_r = [0u8; MAX_MESSAGE_SIZE];
        let mut buf_r_to_i = [0u8; MAX_MESSAGE_SIZE];
        let mut out = [0u8; MAX_MESSAGE_SIZE];

        // -> psk, e
        let n = handshake_write(&mut initiator_hs, &[], &mut buf_i_to_r).unwrap();
        let _ = handshake_read(&mut responder_hs, &buf_i_to_r[..n], &mut out).unwrap();

        // <- e, ee
        let n = handshake_write(&mut responder_hs, &[], &mut buf_r_to_i).unwrap();
        let _ = handshake_read(&mut initiator_hs, &buf_r_to_i[..n], &mut out).unwrap();

        assert!(initiator_hs.is_handshake_finished());
        assert!(responder_hs.is_handshake_finished());

        let mut initiator_ts = into_transport(initiator_hs).unwrap();
        let mut responder_ts = into_transport(responder_hs).unwrap();

        // Initiator -> responder
        let plaintext = b"hello noise";
        let mut ct = [0u8; MAX_MESSAGE_SIZE];
        let n = transport_write(&mut initiator_ts, plaintext, &mut ct).unwrap();
        let mut pt = [0u8; MAX_MESSAGE_SIZE];
        let m = transport_read(&mut responder_ts, &ct[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], plaintext);

        // Responder -> initiator
        let n = transport_write(&mut responder_ts, b"hi back", &mut ct).unwrap();
        let m = transport_read(&mut initiator_ts, &ct[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], b"hi back");
    }

    /// Wrong-PSK handshake must fail at the responder's read of message 1
    /// (the psk0 mix means the binder check fails).
    #[test]
    fn noise_wrong_psk_rejected() {
        let mut initiator_hs = initiator(&[0xaa; 32]).unwrap();
        let mut responder_hs = responder(&[0xbb; 32]).unwrap();

        let mut buf = [0u8; MAX_MESSAGE_SIZE];
        let mut out = [0u8; MAX_MESSAGE_SIZE];
        let n = handshake_write(&mut initiator_hs, &[], &mut buf).unwrap();
        let res = handshake_read(&mut responder_hs, &buf[..n], &mut out);
        assert!(res.is_err(), "responder must reject mismatched PSK");
    }

    #[test]
    fn builder_rejects_short_psk() {
        assert!(matches!(
            initiator(&[0u8; 31]),
            Err(TransportError::BadPskLen { got: 31 })
        ));
        assert!(matches!(
            responder(&[0u8; 33]),
            Err(TransportError::BadPskLen { got: 33 })
        ));
    }

    #[test]
    fn frame_round_trip() {
        let payload = b"hello world";
        let framed = frame(payload).unwrap();
        assert_eq!(framed.len(), 2 + payload.len());
        let len_buf: [u8; 2] = framed[0..2].try_into().unwrap();
        assert_eq!(read_frame_length(&len_buf).unwrap(), payload.len());
        assert_eq!(&framed[2..], payload);
    }

    #[test]
    fn frame_rejects_oversized() {
        let huge = vec![0u8; MAX_MESSAGE_SIZE + 1];
        assert!(matches!(
            frame(&huge),
            Err(TransportError::OversizedFrame { .. })
        ));
    }
}
