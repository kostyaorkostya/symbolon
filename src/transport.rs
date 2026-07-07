//! Noise NKpsk2 transport: encrypted identity TLV, framing, and snow
//! handshake orchestration. I/O-agnostic — callers supply bytes; this
//! module owns the `HandshakeState` / `TransportState` machinery.
//!
//! Two callers:
//! - daemon (compio async): drives the [`Responder`] state machine after
//!   accepting a TCP connection.
//! - `git-credential-symbolon` client binary (sync std::net): drives the
//!   [`Initiator`] state machine.
//!
//! The state machines own protocol lifecycle and emit [`Step`] events
//! telling the I/O driver what to do next (read N bytes, write these
//! bytes, look up a PSK for this identity, process this plaintext).
//! The driver does only I/O; the machine owns all state. The bag of
//! free functions below (`parse_identity_tlv`, `responder`,
//! `initiator`, `handshake_read`, `frame`, etc.) is the lower layer
//! the state machines call into; the fuzz harness targets them
//! directly.
//!
//! Wire shape:
//! ```text
//! Handshake (NK: broker static key known to the client; psk2: PSK
//! mixed at the end of message 2):
//!   -> msg1: e, es    payload = SBLN identity TLV (encrypted)
//!   <- msg2: e, ee, psk
//!
//! SBLN identity TLV (msg1 payload plaintext):
//!   +--------+---+---+----------------+
//!   | "SBLN" | V | L | identity bytes |
//!   +--------+---+---+----------------+
//!      4      1   1       L (1..=64)
//!
//! Per-message framing (used for the Noise handshake messages AND
//! post-handshake transport messages):
//!   +-----------+--------------------+
//!   | len (u16) | message body bytes |
//!   +-----------+--------------------+
//!        2              len
//! ```
//!
//! The client identity travels TLS-ECH-style inside the encrypted
//! msg1 payload (`es` key: client ephemeral x broker static), so a
//! passive observer — or any active attacker not holding the broker
//! static private key — learns nothing about which identity connects.
//! msg1 is replayable, but a replay cannot complete the handshake:
//! message 2 onward requires the identity's PSK.
//!
//! The responder decrypts msg1 with only its static key, parses the
//! TLV, and selects the PSK *after* reading msg1 — that is why the
//! pattern is `psk2` (PSK token at the end of message 2) rather than
//! `psk0`: a PSK mixed before msg1 could not depend on an identity
//! carried inside msg1.

use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};

use crate::broker_key::{BrokerPrivateKey, BrokerPublicKey};
use crate::identity::{Identity, IdentityError};
use crate::psk::Psk;

/// `Noise_NKpsk2_25519_ChaChaPoly_BLAKE2s`. NK: the client knows the
/// broker's static X25519 public key and encrypts to it from msg1;
/// `psk2` mixes the per-client pre-shared key at the end of message 2.
/// 1-RTT.
pub const NOISE_PATTERN: &str = "Noise_NKpsk2_25519_ChaChaPoly_BLAKE2s";

/// PSK slot in `NOISE_PATTERN` — the `2` in `psk2`. Single source for
/// the responder's `set_psk` call and the initiator's builder-time
/// `psk()` so the two sides can't drift.
pub const PSK_SLOT: u8 = 2;

/// Snow constrains a single Noise message to at most 65535 bytes, which fits
/// in our u16 length prefix exactly. Buffers sized to this allow any valid
/// message to be processed in-place.
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Identity TLV magic bytes. Distinctive when a decrypted msg1
/// payload is inspected in logs or a debugger; never appears on the
/// wire in cleartext.
pub const TLV_MAGIC: [u8; 4] = *b"SBLN";

/// Identity TLV format version. Version 1 was the cleartext prelude
/// of the NNpsk0 wire protocol; version 2 moved the same bytes inside
/// the encrypted msg1 payload. The layout is unchanged, but the bump
/// keeps a mixed-era client loudly rejected instead of half-working.
pub const TLV_VERSION: u8 = 0x02;

/// The TLV carries `id_len` as a `u8`; `Identity::MAX_LEN` must fit
/// in that byte. Mirrors the `_WIRE_BUDGET_FITS_PARSER` pattern in
/// `daemon.rs` — catch at compile time, not via `debug_assert!`.
const _IDENTITY_FITS_TLV_LEN: () = assert!(Identity::MAX_LEN <= u8::MAX as usize);

/// Errors raised when parsing or validating the identity TLV
/// (decrypted msg1 payload).
#[derive(Debug, thiserror::Error)]
pub enum TlvError {
    #[error("identity TLV is incomplete: need {needed} more bytes")]
    Incomplete { needed: usize },
    #[error("identity TLV magic mismatch (got {got:?}, expected {:?})", TLV_MAGIC)]
    BadMagic { got: [u8; 4] },
    #[error("identity TLV version {got} not supported (expected {TLV_VERSION})")]
    BadVersion { got: u8 },
    #[error(
        "identity TLV identity length {got} out of range (1..={})",
        Identity::MAX_LEN
    )]
    BadIdentityLen { got: u8 },
    #[error(
        "identity TLV byte 0x{byte:02x} at offset {offset} is outside the allowed \
         charset [A-Za-z0-9._-]"
    )]
    InvalidCharset { offset: usize, byte: u8 },
    #[error("identity TLV followed by {extra} unexpected trailing bytes")]
    TrailingBytes { extra: usize },
}

/// Lift identity validation errors from `Identity::parse` (used by the
/// wire-side body parser) into the wire-error vocabulary. `BadLen.got`
/// is `usize`; the wire reports `u8`. Saturate — the wire parser can't
/// produce > 255 because `parse_tlv_head` already validated id_len
/// fits in a single byte.
impl From<IdentityError> for TlvError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::BadLen { got } => Self::BadIdentityLen {
                got: got.min(u8::MAX as usize) as u8,
            },
            IdentityError::BadCharset { offset, byte } => Self::InvalidCharset { offset, byte },
        }
    }
}

/// Errors raised when constructing or driving the Noise handshake.
/// The `Handshake*` and `Transport*` variants carry the direction
/// (Read vs Write) of the failing call. The producing function
/// always knows the direction, so splitting at the source lets
/// `From<TransportError> for SessionError` lift everything via `?`
/// without per-call-site directional mappers.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("constructing Noise handshake parameters failed")]
    Params(#[source] snow::Error),
    #[error("Noise handshake read failed")]
    HandshakeRead(#[source] snow::Error),
    #[error("Noise handshake write failed")]
    HandshakeWrite(#[source] snow::Error),
    #[error("Noise transport mode transition failed")]
    Transition(#[source] snow::Error),
    #[error("Noise transport decrypt failed")]
    TransportRead(#[source] snow::Error),
    #[error("Noise transport encrypt failed")]
    TransportWrite(#[source] snow::Error),
    #[error("framed message length {got} exceeds maximum {MAX_MESSAGE_SIZE}")]
    OversizedFrame { got: usize },
}

/// Total identity-TLV byte length given an identity length.
pub const fn identity_tlv_size(identity_len: usize) -> usize {
    6 + identity_len
}

/// Encode an `Identity` into TLV bytes (the msg1 payload plaintext).
/// Infallible: `Identity`'s constructor already enforces
/// `1..=Identity::MAX_LEN` length and the `[A-Za-z0-9._-]` charset,
/// which is exactly what the wire requires.
pub fn encode_identity_tlv(identity: &Identity) -> Vec<u8> {
    // `Identity::parse` bounds `bytes.len()` to `1..=Identity::MAX_LEN`,
    // and `_IDENTITY_FITS_PRELUDE_LEN` proves at compile time that
    // `Identity::MAX_LEN <= u8::MAX`, so the cast is statically lossless.
    let bytes = identity.as_str().as_bytes();
    let mut out = Vec::with_capacity(identity_tlv_size(bytes.len()));
    out.extend_from_slice(&TLV_MAGIC);
    out.push(TLV_VERSION);
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
    out
}

/// Validate the 6-byte TLV head: magic, version, and identity length.
/// Returns the declared identity length on success.
fn parse_tlv_head(head: &[u8; 6]) -> Result<u8, TlvError> {
    let &[m0, m1, m2, m3, version, id_len] = head;
    match ([m0, m1, m2, m3], version, id_len) {
        (m, _, _) if m != TLV_MAGIC => Err(TlvError::BadMagic { got: m }),
        (_, v, _) if v != TLV_VERSION => Err(TlvError::BadVersion { got: v }),
        (_, _, l) if l == 0 || l as usize > Identity::MAX_LEN => {
            Err(TlvError::BadIdentityLen { got: l })
        }
        (_, _, l) => Ok(l),
    }
}

/// Validate the identity body charset and return the parsed [`Identity`].
/// Caller has already validated the head (so `body.len()` matches the
/// declared `id_len`).
///
/// Non-UTF-8 input falls through `Identity::parse` indirectly: we
/// first try a fast `from_utf8` and on failure surface the bad byte
/// at the first invalid offset via `InvalidCharset`. That keeps the
/// "first bad byte" reporting the wire layer wants while letting
/// `Identity::parse` own the actual charset rule.
fn parse_tlv_body(body: &[u8]) -> Result<Identity, TlvError> {
    match std::str::from_utf8(body) {
        Ok(s) => Ok(Identity::parse(s)?),
        Err(e) => {
            // `valid_up_to()` is the offset of the first byte that
            // broke UTF-8; that byte also fails the ASCII-only
            // identity charset rule, so reporting it as
            // `InvalidCharset` matches what `Identity::parse` would
            // say if the bytes happened to be valid UTF-8.
            let offset = e.valid_up_to();
            Err(TlvError::InvalidCharset {
                offset,
                byte: body[offset],
            })
        }
    }
}

/// Parse an identity TLV from `input`. On success returns the parsed
/// identity and the byte length consumed. The fuzz harness targets
/// this function.
///
/// The [`Responder`] applies this to a decrypted msg1 payload and
/// additionally requires `consumed == payload.len()` (no trailing
/// bytes); this function itself tolerates them so callers with
/// concatenated input can slice.
pub fn parse_identity_tlv(input: &[u8]) -> Result<(Identity, usize), TlvError> {
    let head = input
        .first_chunk::<6>()
        .ok_or_else(|| TlvError::Incomplete {
            needed: 6 - input.len(),
        })?;
    let id_len = parse_tlv_head(head)?;
    let total = identity_tlv_size(id_len as usize);
    let body = input.get(6..total).ok_or_else(|| TlvError::Incomplete {
        needed: total - input.len(),
    })?;
    let identity = parse_tlv_body(body)?;
    Ok((identity, total))
}

/// Build the responder (server) side of `NOISE_PATTERN` with the
/// broker's static private key. The PSK is NOT supplied here: the
/// responder learns the client identity only after decrypting msg1,
/// then injects the PSK via `HandshakeState::set_psk(PSK_SLOT, …)`
/// before writing msg2. snow validates PSK presence when the `psk`
/// token is processed (message 2), not at build time, so the
/// two-phase construction is safe.
pub fn responder(broker_key: &BrokerPrivateKey) -> Result<HandshakeState, TransportError> {
    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|e: snow::Error| TransportError::Params(e))?;
    Builder::new(params)
        .local_private_key(broker_key.as_bytes())
        .map_err(TransportError::Params)?
        .build_responder()
        .map_err(TransportError::Params)
}

/// Build the initiator (client) side of `NOISE_PATTERN` with the
/// client's PSK and the pinned broker static public key. Both are
/// known up front on the client, so unlike [`responder`] the PSK is
/// supplied at build time.
pub fn initiator(
    psk: &Psk,
    broker_pub: &BrokerPublicKey,
) -> Result<HandshakeState, TransportError> {
    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|e: snow::Error| TransportError::Params(e))?;
    Builder::new(params)
        .remote_public_key(broker_pub.as_bytes())
        .map_err(TransportError::Params)?
        .psk(PSK_SLOT, psk.as_bytes())
        .map_err(TransportError::Params)?
        .build_initiator()
        .map_err(TransportError::Params)
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
/// `out` must be at least `MAX_MESSAGE_SIZE` long. Returns the number of
/// plaintext bytes written into `out` — for msg1 that is the decrypted
/// identity TLV; for msg2 it is 0.
pub fn handshake_read(
    hs: &mut HandshakeState,
    msg: &[u8],
    out: &mut [u8],
) -> Result<usize, TransportError> {
    hs.read_message(msg, out)
        .map_err(TransportError::HandshakeRead)
}

/// Produce the next Noise handshake message into `out`. Returns the number of
/// bytes written.
pub fn handshake_write(
    hs: &mut HandshakeState,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, TransportError> {
    hs.write_message(payload, out)
        .map_err(TransportError::HandshakeWrite)
}

/// Decrypt a post-handshake transport message into `out`. Returns the number of
/// plaintext bytes written.
pub fn transport_read(
    ts: &mut TransportState,
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<usize, TransportError> {
    ts.read_message(ciphertext, out)
        .map_err(TransportError::TransportRead)
}

/// Encrypt a post-handshake transport message into `out`. Returns the number of
/// ciphertext bytes written.
pub fn transport_write(
    ts: &mut TransportState,
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, TransportError> {
    ts.write_message(plaintext, out)
        .map_err(TransportError::TransportWrite)
}

// =========================================================================
// Sans-IO session state machines.
//
// `Responder` and `Initiator` own the full Noise NKpsk2 lifecycle
// (msg1-with-identity-TLV → PSK selection → msg2 → encrypted
// request/response) as an explicit state machine. They emit `Step`
// values telling the I/O driver what to do next; the driver does the
// I/O and feeds bytes back. Same machine drives the async compio
// daemon and the sync std::net client, so protocol changes happen in
// one place.
// =========================================================================

/// Side-agnostic event the I/O driver must service before calling
/// `step()` again.
#[derive(Debug)]
pub enum Step {
    /// Read exactly `n` bytes from the wire and feed them via `recv`.
    /// `n` is bounded by `MAX_MESSAGE_SIZE`.
    ReadExact { n: usize },
    /// Look up the PSK for `identity` (decrypted out of msg1). Caller
    /// calls `set_psk(psk)`. For an unknown identity the caller MUST
    /// substitute a freshly random PSK and continue rather than drop —
    /// the handshake then dies at the first transport-frame decrypt,
    /// indistinguishable (to the peer) from an enrolled identity with
    /// a wrong PSK. Dropping early would let an attacker enumerate
    /// enrolled identities by observing whether msg2 arrives.
    NeedPsk { identity: Identity },
    /// Write these bytes to the wire, then call `wrote()`.
    Write(Vec<u8>),
    /// Decrypted plaintext request the responder just received. Caller
    /// processes it and calls `set_response(plaintext)`.
    Request(Vec<u8>),
    /// Session is complete. Caller closes the wire. `Initiator` callers
    /// retrieve the decrypted response via `take_response()`.
    Done,
}

/// The protocol phase a [`Responder`] or [`Initiator`] is currently in.
/// Drivers use this to format EOF log reasons (the state machine
/// doesn't see the underlying socket, so a clean EOF needs to be
/// attributed to a phase by the driver).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Waiting for (or mid-read of) handshake msg1.
    Msg1,
    AwaitingPsk,
    /// msg2 in flight (responder writing / initiator reading).
    Handshake,
    Transport,
    Done,
}

/// Errors raised by the state machine. Driver maps these directly to
/// log-event `reason=` strings; the variants are chosen to match the
/// catalog in `docs/PROTOCOLS.md`.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("identity TLV bad magic: got {got:?}")]
    TlvBadMagic { got: [u8; 4] },
    #[error("identity TLV bad version: got {got}")]
    TlvBadVersion { got: u8 },
    #[error("identity TLV bad identity length: got {got}")]
    TlvBadIdentityLen { got: u8 },
    #[error("identity TLV byte 0x{byte:02x} at offset {offset} is outside [A-Za-z0-9._-]")]
    TlvInvalidCharset { offset: usize, byte: u8 },
    #[error("identity TLV followed by {extra} unexpected trailing bytes in msg1 payload")]
    TlvTrailingBytes { extra: usize },
    #[error("identity TLV truncated: msg1 payload is {needed} bytes short of the declared length")]
    TlvIncomplete { needed: usize },
    #[error("noise handshake read failed")]
    HandshakeRead(#[source] snow::Error),
    #[error("noise handshake write failed")]
    HandshakeWrite(#[source] snow::Error),
    #[error("noise transport-mode transition failed")]
    IntoTransport(#[source] snow::Error),
    #[error("noise transport decrypt failed")]
    TransportRead(#[source] snow::Error),
    #[error("noise transport encrypt failed")]
    TransportWrite(#[source] snow::Error),
    #[error("frame body length {got} exceeds maximum {MAX_MESSAGE_SIZE}")]
    FrameTooBig { got: usize },
    #[error("recv length mismatch: expected {expected}, got {got}")]
    RecvLen { expected: usize, got: usize },
    #[error("{method} called in wrong state ({state})")]
    WrongState {
        method: &'static str,
        state: &'static str,
    },
}

impl From<TlvError> for SessionError {
    fn from(e: TlvError) -> Self {
        match e {
            TlvError::BadMagic { got } => SessionError::TlvBadMagic { got },
            TlvError::BadVersion { got } => SessionError::TlvBadVersion { got },
            TlvError::BadIdentityLen { got } => SessionError::TlvBadIdentityLen { got },
            TlvError::InvalidCharset { offset, byte } => {
                SessionError::TlvInvalidCharset { offset, byte }
            }
            TlvError::TrailingBytes { extra } => SessionError::TlvTrailingBytes { extra },
            TlvError::Incomplete { needed } => SessionError::TlvIncomplete { needed },
        }
    }
}

impl From<TransportError> for SessionError {
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::OversizedFrame { got } => Self::FrameTooBig { got },
            TransportError::HandshakeRead(s) => Self::HandshakeRead(s),
            TransportError::HandshakeWrite(s) => Self::HandshakeWrite(s),
            TransportError::Transition(s) => Self::IntoTransport(s),
            TransportError::TransportRead(s) => Self::TransportRead(s),
            TransportError::TransportWrite(s) => Self::TransportWrite(s),
            // Construction-time error (e.g. JSON Noise params); both
            // initiator and responder paths surface it during the
            // very first handshake step, so HandshakeRead is the
            // direction the driver always observes.
            TransportError::Params(s) => Self::HandshakeRead(s),
        }
    }
}

impl SessionError {
    /// Guard the state machine's `read_exact` returns: the driver
    /// promised `expected` bytes but handed us `got`. Anything other
    /// than equality is a driver bug, surfaced as `RecvLen`.
    fn check_recv_len(expected: usize, got: usize) -> Result<(), Self> {
        if expected == got {
            Ok(())
        } else {
            Err(Self::RecvLen { expected, got })
        }
    }

    /// Const-length variant: returns the bytes as an owned `[u8; N]`
    /// so the caller skips the `try_into().expect(...)` dance. Use
    /// when the expected length is a compile-time constant (the
    /// frame-length prefix = 2).
    fn recv_chunk<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Self> {
        bytes.try_into().map_err(|_| Self::RecvLen {
            expected: N,
            got: bytes.len(),
        })
    }
}

// --- Responder -----------------------------------------------------------

#[derive(strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
enum RState {
    /// Terminal failure state. `step` and friends return WrongState.
    Failed,
    /// Identity parsed out of msg1; ask the driver to look up the
    /// PSK. `hs` is mid-handshake (msg1 consumed, msg2 not yet
    /// written — it needs the PSK).
    NeedPsk {
        hs: HandshakeState,
        identity: Identity,
    },
    /// `Step::NeedPsk` has been emitted (identity moved out).
    /// Caller must invoke `set_psk` next; another `step()` here is
    /// a contract violation (`WrongState`).
    AwaitingPsk {
        hs: HandshakeState,
    },
    /// Initial state. Ask for the 2-byte handshake-msg-1 length.
    WantHsLen {
        hs: HandshakeState,
    },
    /// Length known; ask for `body_len` handshake-msg-1 bytes.
    WantHsBody {
        hs: HandshakeState,
        body_len: usize,
    },
    /// Handshake msg 1 consumed; emit framed handshake msg 2.
    WriteHs {
        hs: HandshakeState,
        out: Vec<u8>,
    },
    /// Driver has hs msg 2 in hand. Awaiting `wrote()` ack.
    WroteHsPending {
        hs: HandshakeState,
    },
    /// In transport mode. Ask for the 2-byte request-frame length.
    WantReqLen {
        ts: TransportState,
    },
    /// Length known; ask for `body_len` request-frame bytes.
    WantReqBody {
        ts: TransportState,
        body_len: usize,
    },
    /// Decrypted plaintext ready; emit to driver for processing.
    HaveRequest {
        ts: TransportState,
        plaintext: Vec<u8>,
    },
    /// Plaintext emitted to driver; awaiting `set_response`.
    AwaitingResponse {
        ts: TransportState,
    },
    /// Encrypted+framed response ready; emit to driver.
    WriteResp {
        out: Vec<u8>,
    },
    /// Driver has the response bytes. Awaiting `wrote()` ack → Done.
    WroteRespPending,
    Done,
}

impl RState {
    fn phase(&self) -> Phase {
        match self {
            RState::WantHsLen { .. } | RState::WantHsBody { .. } => Phase::Msg1,
            RState::NeedPsk { .. } | RState::AwaitingPsk { .. } => Phase::AwaitingPsk,
            RState::WriteHs { .. } | RState::WroteHsPending { .. } => Phase::Handshake,
            RState::WantReqLen { .. }
            | RState::WantReqBody { .. }
            | RState::HaveRequest { .. }
            | RState::AwaitingResponse { .. }
            | RState::WriteResp { .. }
            | RState::WroteRespPending => Phase::Transport,
            RState::Done | RState::Failed => Phase::Done,
        }
    }
}

/// Responder-side Noise NKpsk2 session state machine.
///
/// Drive it like:
/// ```ignore
/// let mut sess = Responder::new(&broker_key)?;
/// loop {
///     match sess.step()? {
///         Step::ReadExact { n } => sess.recv(&read_n_bytes(n).await?)?,
///         Step::NeedPsk { identity } => sess.set_psk(lookup_or_random(&identity))?,
///         Step::Write(bytes) => { write_all(&bytes).await?; sess.wrote()?; }
///         Step::Request(plaintext) => sess.set_response(&handle(plaintext))?,
///         Step::Done => break,
///     }
/// }
/// ```
pub struct Responder {
    state: RState,
    /// One per-session scratch buffer reused across handshake-step
    /// and transport-mode reads/writes. Snow needs an `out` slice
    /// of at least `MAX_MESSAGE_SIZE` for both directions; the
    /// session only ever uses it inside a single `recv` /
    /// `set_response` call, never across `.await` boundaries, so a
    /// single buffer suffices.
    scratch: Box<[u8; MAX_MESSAGE_SIZE]>,
}

impl Responder {
    /// Build a responder around the broker's static private key. The
    /// snow `HandshakeState` is constructed here (fallible: pattern
    /// parse + key install); the PSK arrives later via `set_psk`
    /// after msg1 reveals the client identity.
    pub fn new(broker_key: &BrokerPrivateKey) -> Result<Self, SessionError> {
        let hs = responder(broker_key)?;
        Ok(Self {
            state: RState::WantHsLen { hs },
            scratch: Box::new([0u8; MAX_MESSAGE_SIZE]),
        })
    }

    /// Current protocol phase. Used by the driver to attribute clean
    /// EOFs to the right log reason.
    pub fn phase(&self) -> Phase {
        self.state.phase()
    }

    /// Inspect what the session wants next.
    ///
    /// Reading states (`ReadExact`, `NeedPsk`) are idempotent — repeated
    /// calls return the same `Step` until a mutation method advances
    /// the state. Emitting states (`Write`, `Request`) consume their
    /// payload on emission; calling `step()` a second time before
    /// `wrote()` / `set_response()` returns `WrongState`.
    pub fn step(&mut self) -> Result<Step, SessionError> {
        let state_name: &str = (&self.state).into();
        match std::mem::replace(&mut self.state, RState::Failed) {
            RState::NeedPsk { hs, identity } => {
                // Move the identity into the Step (zero clone). The
                // contract is: caller MUST call `set_psk` next. A
                // second `step()` before that returns WrongState
                // via the catch-all below. `hs` is parked in
                // AwaitingPsk mid-handshake (msg1 read, msg2 pending
                // on the PSK).
                self.state = RState::AwaitingPsk { hs };
                Ok(Step::NeedPsk { identity })
            }
            RState::WantHsLen { hs } => {
                self.state = RState::WantHsLen { hs };
                Ok(Step::ReadExact { n: 2 })
            }
            RState::WantHsBody { hs, body_len } => {
                self.state = RState::WantHsBody { hs, body_len };
                Ok(Step::ReadExact { n: body_len })
            }
            RState::WriteHs { hs, out } => {
                self.state = RState::WroteHsPending { hs };
                Ok(Step::Write(out))
            }
            RState::WantReqLen { ts } => {
                self.state = RState::WantReqLen { ts };
                Ok(Step::ReadExact { n: 2 })
            }
            RState::WantReqBody { ts, body_len } => {
                self.state = RState::WantReqBody { ts, body_len };
                Ok(Step::ReadExact { n: body_len })
            }
            RState::HaveRequest { ts, plaintext } => {
                self.state = RState::AwaitingResponse { ts };
                Ok(Step::Request(plaintext))
            }
            RState::WriteResp { out } => {
                self.state = RState::WroteRespPending;
                Ok(Step::Write(out))
            }
            RState::Done => {
                self.state = RState::Done;
                Ok(Step::Done)
            }
            other @ (RState::Failed
            | RState::AwaitingPsk { .. }
            | RState::WroteHsPending { .. }
            | RState::AwaitingResponse { .. }
            | RState::WroteRespPending) => {
                self.state = other;
                Err(SessionError::WrongState {
                    method: "step",
                    state: state_name,
                })
            }
        }
    }

    /// Feed bytes for the most recent `Step::ReadExact`.
    pub fn recv(&mut self, bytes: &[u8]) -> Result<(), SessionError> {
        let state_name: &str = (&self.state).into();
        match std::mem::replace(&mut self.state, RState::Failed) {
            RState::WantHsLen { hs } => {
                let len_buf = SessionError::recv_chunk::<2>(bytes)?;
                let body_len = read_frame_length(&len_buf)?;
                self.state = RState::WantHsBody { hs, body_len };
                Ok(())
            }
            RState::WantHsBody { mut hs, body_len } => {
                SessionError::check_recv_len(body_len, bytes.len())?;
                // Decrypt msg1; the payload plaintext is the identity
                // TLV. Decryption needs only the broker static key —
                // the PSK enters the transcript at msg2 (`psk2`).
                let n = handshake_read(&mut hs, bytes, &mut self.scratch[..])?;
                let (identity, consumed) = parse_identity_tlv(&self.scratch[..n])?;
                // The payload must be exactly one TLV. Trailing bytes
                // mean a peer speaking some extended dialect we never
                // specified — reject rather than silently ignore.
                if consumed != n {
                    return Err(SessionError::TlvTrailingBytes {
                        extra: n - consumed,
                    });
                }
                self.state = RState::NeedPsk { hs, identity };
                Ok(())
            }
            RState::WantReqLen { ts } => {
                let len_buf = SessionError::recv_chunk::<2>(bytes)?;
                let body_len = read_frame_length(&len_buf)?;
                self.state = RState::WantReqBody { ts, body_len };
                Ok(())
            }
            RState::WantReqBody { mut ts, body_len } => {
                SessionError::check_recv_len(body_len, bytes.len())?;
                let n = transport_read(&mut ts, bytes, &mut self.scratch[..])?;
                self.state = RState::HaveRequest {
                    ts,
                    plaintext: self.scratch[..n].to_vec(),
                };
                Ok(())
            }
            other => {
                self.state = other;
                Err(SessionError::WrongState {
                    method: "recv",
                    state: state_name,
                })
            }
        }
    }

    /// Provide the PSK requested by the previous `Step::NeedPsk`
    /// (the real one, or a random substitute for unknown identities —
    /// see the `Step::NeedPsk` doc). Injects it into slot `PSK_SLOT`
    /// and immediately produces framed handshake msg2.
    pub fn set_psk(&mut self, psk: Psk) -> Result<(), SessionError> {
        let state_name: &str = (&self.state).into();
        match std::mem::replace(&mut self.state, RState::Failed) {
            RState::AwaitingPsk { mut hs } => {
                // `Error::Input` here means a wrong-length key or an
                // out-of-range slot — both impossible by construction
                // (Psk is 32 bytes; PSK_SLOT matches NOISE_PATTERN).
                // Surfaced as HandshakeWrite since it aborts msg2
                // production.
                hs.set_psk(usize::from(PSK_SLOT), psk.as_bytes())
                    .map_err(SessionError::HandshakeWrite)?;
                let n = handshake_write(&mut hs, &[], &mut self.scratch[..])?;
                let out = frame(&self.scratch[..n])?;
                self.state = RState::WriteHs { hs, out };
                Ok(())
            }
            other => {
                self.state = other;
                Err(SessionError::WrongState {
                    method: "set_psk",
                    state: state_name,
                })
            }
        }
    }

    /// Acknowledge that the bytes from the most recent `Step::Write`
    /// were flushed to the wire.
    pub fn wrote(&mut self) -> Result<(), SessionError> {
        let state_name: &str = (&self.state).into();
        match std::mem::replace(&mut self.state, RState::Failed) {
            RState::WroteHsPending { hs } => {
                // Handshake msg 2 is on the wire; transition to transport mode.
                let ts = into_transport(hs)?;
                self.state = RState::WantReqLen { ts };
                Ok(())
            }
            RState::WroteRespPending => {
                self.state = RState::Done;
                Ok(())
            }
            other => {
                self.state = other;
                Err(SessionError::WrongState {
                    method: "wrote",
                    state: state_name,
                })
            }
        }
    }

    /// Provide the plaintext response to encrypt and send.
    pub fn set_response(&mut self, plaintext: &[u8]) -> Result<(), SessionError> {
        let state_name: &str = (&self.state).into();
        match std::mem::replace(&mut self.state, RState::Failed) {
            RState::AwaitingResponse { mut ts } => {
                let n = transport_write(&mut ts, plaintext, &mut self.scratch[..])?;
                let out = frame(&self.scratch[..n])?;
                self.state = RState::WriteResp { out };
                Ok(())
            }
            other => {
                self.state = other;
                Err(SessionError::WrongState {
                    method: "set_response",
                    state: state_name,
                })
            }
        }
    }
}

// --- Initiator -----------------------------------------------------------

#[derive(strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
enum IState {
    Failed,
    /// Emit framed handshake msg 1 (identity TLV as encrypted payload).
    WriteHs1 {
        hs: HandshakeState,
        msg1: Vec<u8>,
        request: Vec<u8>,
    },
    /// Hs msg 1 handed to driver; awaiting `wrote()`.
    WroteHs1Pending {
        hs: HandshakeState,
        request: Vec<u8>,
    },
    /// Ask for the 2-byte hs-msg-2 length.
    WantHs2Len {
        hs: HandshakeState,
        request: Vec<u8>,
    },
    /// Ask for `body_len` hs-msg-2 bytes.
    WantHs2Body {
        hs: HandshakeState,
        body_len: usize,
        request: Vec<u8>,
    },
    /// Hs done; emit the framed encrypted request.
    WriteReq {
        ts: TransportState,
        out: Vec<u8>,
    },
    /// Request bytes handed to driver; awaiting `wrote()`.
    WroteReqPending {
        ts: TransportState,
    },
    /// Ask for the 2-byte response-frame length.
    WantRespLen {
        ts: TransportState,
    },
    /// Ask for `body_len` response-frame bytes.
    WantRespBody {
        ts: TransportState,
        body_len: usize,
    },
    /// All done; plaintext response is available via `take_response`.
    Done {
        plaintext: Vec<u8>,
    },
    /// `take_response` already consumed the plaintext.
    Drained,
}

impl IState {
    fn phase(&self) -> Phase {
        match self {
            IState::WriteHs1 { .. } | IState::WroteHs1Pending { .. } => Phase::Msg1,
            IState::WantHs2Len { .. } | IState::WantHs2Body { .. } => Phase::Handshake,
            IState::WriteReq { .. }
            | IState::WroteReqPending { .. }
            | IState::WantRespLen { .. }
            | IState::WantRespBody { .. } => Phase::Transport,
            IState::Done { .. } | IState::Drained | IState::Failed => Phase::Done,
        }
    }
}

/// Initiator-side Noise NKpsk2 session state machine.
///
/// Identity, PSK, broker public key, and request bytes are known up
/// front (the client binary reads stdin before opening the socket),
/// so they're consumed by `Initiator::new`. The driver pumps `step()`
/// until `Step::Done`, then calls `take_response()` to recover the
/// decrypted plaintext.
pub struct Initiator {
    state: IState,
    /// One per-session scratch buffer reused across handshake-step
    /// and transport-mode reads/writes. See `Responder::scratch`.
    scratch: Box<[u8; MAX_MESSAGE_SIZE]>,
}

impl Initiator {
    pub fn new(
        identity: Identity,
        psk: Psk,
        broker_pub: &BrokerPublicKey,
        request: Vec<u8>,
    ) -> Result<Self, SessionError> {
        let mut hs = initiator(&psk, broker_pub)?;
        // msg1 carries the identity TLV as its (encrypted) payload;
        // everything needed to produce it is in hand, so compute it
        // here and start the machine at the write step.
        let tlv = encode_identity_tlv(&identity);
        let mut scratch = Box::new([0u8; MAX_MESSAGE_SIZE]);
        let n = handshake_write(&mut hs, &tlv, &mut scratch[..])?;
        let msg1 = frame(&scratch[..n])?;
        Ok(Self {
            state: IState::WriteHs1 { hs, msg1, request },
            scratch,
        })
    }

    pub fn phase(&self) -> Phase {
        self.state.phase()
    }

    pub fn step(&mut self) -> Result<Step, SessionError> {
        let state_name: &str = (&self.state).into();
        match std::mem::replace(&mut self.state, IState::Failed) {
            IState::WriteHs1 { hs, msg1, request } => {
                self.state = IState::WroteHs1Pending { hs, request };
                Ok(Step::Write(msg1))
            }
            IState::WantHs2Len { hs, request } => {
                self.state = IState::WantHs2Len { hs, request };
                Ok(Step::ReadExact { n: 2 })
            }
            IState::WantHs2Body {
                hs,
                body_len,
                request,
            } => {
                self.state = IState::WantHs2Body {
                    hs,
                    body_len,
                    request,
                };
                Ok(Step::ReadExact { n: body_len })
            }
            IState::WriteReq { ts, out } => {
                self.state = IState::WroteReqPending { ts };
                Ok(Step::Write(out))
            }
            IState::WantRespLen { ts } => {
                self.state = IState::WantRespLen { ts };
                Ok(Step::ReadExact { n: 2 })
            }
            IState::WantRespBody { ts, body_len } => {
                self.state = IState::WantRespBody { ts, body_len };
                Ok(Step::ReadExact { n: body_len })
            }
            IState::Done { plaintext } => {
                self.state = IState::Done { plaintext };
                Ok(Step::Done)
            }
            other => {
                self.state = other;
                Err(SessionError::WrongState {
                    method: "step",
                    state: state_name,
                })
            }
        }
    }

    pub fn recv(&mut self, bytes: &[u8]) -> Result<(), SessionError> {
        let state_name: &str = (&self.state).into();
        match std::mem::replace(&mut self.state, IState::Failed) {
            IState::WantHs2Len { hs, request } => {
                let len_buf = SessionError::recv_chunk::<2>(bytes)?;
                let body_len = read_frame_length(&len_buf)?;
                self.state = IState::WantHs2Body {
                    hs,
                    body_len,
                    request,
                };
                Ok(())
            }
            IState::WantHs2Body {
                mut hs,
                body_len,
                request,
            } => {
                SessionError::check_recv_len(body_len, bytes.len())?;
                handshake_read(&mut hs, bytes, &mut self.scratch[..])?;
                let mut ts = into_transport(hs)?;
                // Encrypt + frame the request now that we're in transport mode.
                let n = transport_write(&mut ts, &request, &mut self.scratch[..])?;
                let out = frame(&self.scratch[..n])?;
                self.state = IState::WriteReq { ts, out };
                Ok(())
            }
            IState::WantRespLen { ts } => {
                let len_buf = SessionError::recv_chunk::<2>(bytes)?;
                let body_len = read_frame_length(&len_buf)?;
                self.state = IState::WantRespBody { ts, body_len };
                Ok(())
            }
            IState::WantRespBody { mut ts, body_len } => {
                SessionError::check_recv_len(body_len, bytes.len())?;
                let n = transport_read(&mut ts, bytes, &mut self.scratch[..])?;
                self.state = IState::Done {
                    plaintext: self.scratch[..n].to_vec(),
                };
                Ok(())
            }
            other => {
                self.state = other;
                Err(SessionError::WrongState {
                    method: "recv",
                    state: state_name,
                })
            }
        }
    }

    pub fn wrote(&mut self) -> Result<(), SessionError> {
        let state_name: &str = (&self.state).into();
        match std::mem::replace(&mut self.state, IState::Failed) {
            IState::WroteHs1Pending { hs, request } => {
                self.state = IState::WantHs2Len { hs, request };
                Ok(())
            }
            IState::WroteReqPending { ts } => {
                self.state = IState::WantRespLen { ts };
                Ok(())
            }
            other => {
                self.state = other;
                Err(SessionError::WrongState {
                    method: "wrote",
                    state: state_name,
                })
            }
        }
    }

    /// Consume the session and return the decrypted plaintext response.
    /// Valid only after `step()` has returned `Step::Done`.
    pub fn take_response(mut self) -> Result<Vec<u8>, SessionError> {
        let state_name: &str = (&self.state).into();
        match std::mem::replace(&mut self.state, IState::Drained) {
            IState::Done { plaintext } => Ok(plaintext),
            other => {
                self.state = other;
                Err(SessionError::WrongState {
                    method: "take_response",
                    state: state_name,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_identity() -> Identity {
        Identity::parse("dev-vm-1.test_03").unwrap()
    }

    fn broker_key() -> BrokerPrivateKey {
        BrokerPrivateKey::from([7u8; 32])
    }

    fn broker_pub() -> BrokerPublicKey {
        broker_key().derive_public()
    }

    /// The pattern string is the protocol contract; snow must parse it.
    #[test]
    fn noise_pattern_parses() {
        let params: Result<NoiseParams, _> = NOISE_PATTERN.parse();
        assert!(params.is_ok(), "snow rejected {NOISE_PATTERN}");
    }

    #[test]
    fn tlv_round_trip() {
        let id = good_identity();
        let bytes = encode_identity_tlv(&id);
        assert_eq!(bytes.len(), identity_tlv_size(id.as_str().len()));
        let (parsed, consumed) = parse_identity_tlv(&bytes).expect("round-trip parse");
        assert_eq!(parsed, id);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn tlv_rejects_short_buffer() {
        for prefix_len in 0..6 {
            let bytes = vec![0u8; prefix_len];
            match parse_identity_tlv(&bytes) {
                Err(TlvError::Incomplete { needed }) => {
                    assert_eq!(needed, 6 - prefix_len);
                }
                other => panic!("expected Incomplete, got {other:?}"),
            }
        }
    }

    #[test]
    fn tlv_rejects_bad_magic() {
        let mut bytes = encode_identity_tlv(&Identity::parse("foo").unwrap());
        bytes[0] = b'X';
        assert!(matches!(
            parse_identity_tlv(&bytes),
            Err(TlvError::BadMagic { .. })
        ));
    }

    #[test]
    fn tlv_rejects_bad_version() {
        let mut bytes = encode_identity_tlv(&Identity::parse("foo").unwrap());
        bytes[4] = 0x99;
        assert!(matches!(
            parse_identity_tlv(&bytes),
            Err(TlvError::BadVersion { got: 0x99 })
        ));
    }

    /// Version 1 is the retired cleartext-prelude wire format; a v2
    /// broker must reject it, not half-work.
    #[test]
    fn tlv_rejects_version_1() {
        let mut bytes = encode_identity_tlv(&Identity::parse("foo").unwrap());
        bytes[4] = 0x01;
        assert!(matches!(
            parse_identity_tlv(&bytes),
            Err(TlvError::BadVersion { got: 0x01 })
        ));
    }

    #[test]
    fn tlv_rejects_zero_length() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TLV_MAGIC);
        bytes.push(TLV_VERSION);
        bytes.push(0);
        assert!(matches!(
            parse_identity_tlv(&bytes),
            Err(TlvError::BadIdentityLen { got: 0 })
        ));
    }

    #[test]
    fn tlv_rejects_oversized_id_len() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TLV_MAGIC);
        bytes.push(TLV_VERSION);
        bytes.push((Identity::MAX_LEN as u8) + 1);
        bytes.resize(bytes.len() + Identity::MAX_LEN + 1, b'a');
        assert!(matches!(
            parse_identity_tlv(&bytes),
            Err(TlvError::BadIdentityLen { .. })
        ));
    }

    #[test]
    fn tlv_rejects_incomplete_identity() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TLV_MAGIC);
        bytes.push(TLV_VERSION);
        bytes.push(10);
        // ...but only 3 identity bytes follow
        bytes.extend_from_slice(b"abc");
        match parse_identity_tlv(&bytes) {
            Err(TlvError::Incomplete { needed }) => assert_eq!(needed, 7),
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }

    #[test]
    fn tlv_rejects_invalid_charset() {
        // CR is the canonical Clone2Leak-class injection byte we defend against
        // in git_credential too.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TLV_MAGIC);
        bytes.push(TLV_VERSION);
        bytes.push(3);
        bytes.extend_from_slice(b"a\rb");
        assert!(matches!(
            parse_identity_tlv(&bytes),
            Err(TlvError::InvalidCharset {
                offset: 1,
                byte: b'\r'
            })
        ));
    }

    /// End-to-end Noise NKpsk2 handshake + a transport-mode message
    /// round-trip, driven entirely in-memory through the free
    /// functions (the state machines get their own test below).
    #[test]
    fn noise_handshake_round_trip() {
        let psk = Psk::from([0x42u8; 32]);
        let tlv = encode_identity_tlv(&good_identity());

        let mut initiator_hs = initiator(&psk, &broker_pub()).expect("build initiator");
        let mut responder_hs = responder(&broker_key()).expect("build responder");

        let mut buf_i_to_r = [0u8; MAX_MESSAGE_SIZE];
        let mut buf_r_to_i = [0u8; MAX_MESSAGE_SIZE];
        let mut out = [0u8; MAX_MESSAGE_SIZE];

        // -> e, es (identity TLV as encrypted payload)
        let n = handshake_write(&mut initiator_hs, &tlv, &mut buf_i_to_r).unwrap();
        let m = handshake_read(&mut responder_hs, &buf_i_to_r[..n], &mut out).unwrap();
        assert_eq!(&out[..m], &tlv[..], "responder must recover the TLV");

        // PSK selected from the decrypted identity, then <- e, ee, psk
        responder_hs
            .set_psk(usize::from(PSK_SLOT), psk.as_bytes())
            .unwrap();
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

    /// With psk2 a PSK mismatch surfaces at the INITIATOR's read of
    /// msg2 (the psk token is mixed at the end of message 2). The
    /// responder's msg2 write succeeds — its side fails later, at the
    /// first transport read. Both halves asserted here; together they
    /// are the mechanism behind the anti-enumeration property.
    #[test]
    fn noise_wrong_psk_fails_at_msg2_read_and_transport() {
        let tlv = encode_identity_tlv(&good_identity());
        let mut initiator_hs = initiator(&Psk::from([0xaa; 32]), &broker_pub()).unwrap();
        let mut responder_hs = responder(&broker_key()).unwrap();

        let mut wire = [0u8; MAX_MESSAGE_SIZE];
        let mut out = [0u8; MAX_MESSAGE_SIZE];
        let n = handshake_write(&mut initiator_hs, &tlv, &mut wire).unwrap();
        let _ = handshake_read(&mut responder_hs, &wire[..n], &mut out).unwrap();

        // Responder substitutes a different PSK (e.g. the random
        // anti-enumeration substitute) — msg2 production MUST succeed.
        responder_hs
            .set_psk(usize::from(PSK_SLOT), Psk::from([0xbb; 32]).as_bytes())
            .unwrap();
        let n = handshake_write(&mut responder_hs, &[], &mut wire).unwrap();

        // Initiator side: msg2 tag check fails.
        assert!(
            handshake_read(&mut initiator_hs, &wire[..n], &mut out).is_err(),
            "initiator must reject msg2 built with a different PSK"
        );

        // Responder side: handshake "completed" from its view; the
        // mismatch surfaces only when a transport frame arrives.
        let mut responder_ts = into_transport(responder_hs).unwrap();
        assert!(
            transport_read(&mut responder_ts, b"any bytes at all!", &mut out).is_err(),
            "responder must fail at first transport decrypt"
        );
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

    // ---- State machine round-trip & regression tests --------------------

    /// Pump a `Responder` and `Initiator` against each other entirely
    /// in memory. Two `Vec<u8>` "wires" carry the bytes between them.
    /// This is the spec test for the sans-IO design: if it fails, the
    /// daemon ↔ client wire is broken.
    #[test]
    fn responder_initiator_round_trip() {
        let psk = Psk::from([0x42u8; 32]);
        let request = b"protocol=https\nhost=github.com\npath=foo/bar\n\n".to_vec();
        let response_plain = b"username=x-access-token\npassword=ghs_abc\n\n".to_vec();

        let mut server = Responder::new(&broker_key()).expect("build responder");
        let mut client = Initiator::new(
            Identity::parse("dev-vm-1.test_03").unwrap(),
            psk,
            &broker_pub(),
            request.clone(),
        )
        .expect("build initiator");

        let mut c_to_s: Vec<u8> = Vec::new();
        let mut s_to_c: Vec<u8> = Vec::new();

        let mut got_request_at_server: Option<Vec<u8>> = None;
        let mut server_done = false;
        let mut client_done = false;

        for _ in 0..32 {
            // -- server side --
            match server.step().expect("server step") {
                Step::ReadExact { n } => {
                    if c_to_s.len() >= n {
                        let bytes: Vec<u8> = c_to_s.drain(..n).collect();
                        server.recv(&bytes).expect("server recv");
                    }
                }
                Step::NeedPsk { identity } => {
                    assert_eq!(identity.as_str(), "dev-vm-1.test_03");
                    server.set_psk(psk).expect("server set_psk");
                }
                Step::Write(bytes) => {
                    s_to_c.extend_from_slice(&bytes);
                    server.wrote().expect("server wrote");
                }
                Step::Request(plaintext) => {
                    got_request_at_server = Some(plaintext);
                    server
                        .set_response(&response_plain)
                        .expect("server set_response");
                }
                Step::Done => server_done = true,
            }
            // -- client side --
            match client.step().expect("client step") {
                Step::ReadExact { n } => {
                    if s_to_c.len() >= n {
                        let bytes: Vec<u8> = s_to_c.drain(..n).collect();
                        client.recv(&bytes).expect("client recv");
                    }
                }
                Step::Write(bytes) => {
                    c_to_s.extend_from_slice(&bytes);
                    client.wrote().expect("client wrote");
                }
                Step::Done => client_done = true,
                other => panic!("initiator should not emit {other:?}"),
            }
            if server_done && client_done {
                break;
            }
        }

        assert!(server_done, "server never reached Done");
        assert!(client_done, "client never reached Done");
        assert_eq!(
            got_request_at_server.expect("server received request"),
            request,
            "server-decrypted request must match",
        );
        let resp = client.take_response().expect("take_response");
        assert_eq!(resp, response_plain, "client-decrypted response must match");
    }

    /// Craft a framed msg1 whose (validly encrypted) payload is an
    /// arbitrary byte string — the vehicle for feeding malformed TLVs
    /// through a real handshake to the responder state machine.
    fn framed_msg1_with_payload(payload: &[u8]) -> Vec<u8> {
        let mut hs = initiator(&Psk::from([0x42u8; 32]), &broker_pub()).unwrap();
        let mut buf = [0u8; MAX_MESSAGE_SIZE];
        let n = handshake_write(&mut hs, payload, &mut buf).unwrap();
        frame(&buf[..n]).unwrap()
    }

    /// Feed one framed message through the Responder's two-read
    /// (length, body) sequence and return the second recv's result.
    fn feed_framed(sess: &mut Responder, framed: &[u8]) -> Result<(), SessionError> {
        assert!(matches!(sess.step().unwrap(), Step::ReadExact { n: 2 }));
        sess.recv(&framed[..2])?;
        let n = match sess.step().unwrap() {
            Step::ReadExact { n } => n,
            other => panic!("expected body read, got {other:?}"),
        };
        assert_eq!(n, framed.len() - 2);
        sess.recv(&framed[2..])
    }

    #[test]
    fn responder_rejects_bad_magic_in_msg1_payload() {
        let mut sess = Responder::new(&broker_key()).unwrap();
        let mut tlv = encode_identity_tlv(&good_identity());
        tlv[0] = b'X';
        let err = feed_framed(&mut sess, &framed_msg1_with_payload(&tlv))
            .expect_err("must reject bad magic");
        assert!(
            matches!(err, SessionError::TlvBadMagic { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn responder_rejects_bad_version_in_msg1_payload() {
        let mut sess = Responder::new(&broker_key()).unwrap();
        let mut tlv = encode_identity_tlv(&good_identity());
        tlv[4] = 0x99;
        let err = feed_framed(&mut sess, &framed_msg1_with_payload(&tlv))
            .expect_err("must reject bad version");
        assert!(
            matches!(err, SessionError::TlvBadVersion { got: 0x99 }),
            "got {err:?}"
        );
    }

    #[test]
    fn responder_rejects_bad_id_len_in_msg1_payload() {
        let mut sess = Responder::new(&broker_key()).unwrap();
        let mut tlv = encode_identity_tlv(&good_identity());
        tlv[5] = 0;
        // Truncate to head-only so the declared len (0) drives parse.
        tlv.truncate(6);
        let err = feed_framed(&mut sess, &framed_msg1_with_payload(&tlv))
            .expect_err("must reject zero id_len");
        assert!(
            matches!(err, SessionError::TlvBadIdentityLen { got: 0 }),
            "got {err:?}"
        );
    }

    #[test]
    fn responder_rejects_invalid_charset_in_msg1_payload() {
        let mut sess = Responder::new(&broker_key()).unwrap();
        let mut bad = Vec::new();
        bad.extend_from_slice(&TLV_MAGIC);
        bad.push(TLV_VERSION);
        bad.push(3);
        // CR byte = Clone2Leak-class injection attempt.
        bad.extend_from_slice(b"a\rb");
        let err = feed_framed(&mut sess, &framed_msg1_with_payload(&bad))
            .expect_err("charset must reject CR");
        assert!(
            matches!(
                err,
                SessionError::TlvInvalidCharset {
                    offset: 1,
                    byte: b'\r'
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn responder_rejects_trailing_bytes_in_msg1_payload() {
        let mut sess = Responder::new(&broker_key()).unwrap();
        let mut tlv = encode_identity_tlv(&good_identity());
        tlv.extend_from_slice(b"extra");
        let err = feed_framed(&mut sess, &framed_msg1_with_payload(&tlv))
            .expect_err("must reject trailing bytes");
        assert!(
            matches!(err, SessionError::TlvTrailingBytes { extra: 5 }),
            "got {err:?}"
        );
    }

    /// The anti-enumeration walk: a responder given a random
    /// substitute PSK for an unknown identity still produces msg2
    /// (same shape as the real one) and only fails at the first
    /// transport frame. This is the state-machine mirror of
    /// `noise_wrong_psk_fails_at_msg2_read_and_transport`.
    #[test]
    fn responder_with_substitute_psk_dies_at_transport_frame() {
        let mut sess = Responder::new(&broker_key()).unwrap();
        let tlv = encode_identity_tlv(&good_identity());
        feed_framed(&mut sess, &framed_msg1_with_payload(&tlv)).expect("msg1 accepted");

        let identity = match sess.step().unwrap() {
            Step::NeedPsk { identity } => identity,
            other => panic!("expected NeedPsk, got {other:?}"),
        };
        assert_eq!(identity, good_identity());

        // Substitute PSK (the initiator used 0x42; this is not it).
        sess.set_psk(Psk::from([0xbb; 32])).expect("set_psk");

        // msg2 is produced normally.
        let msg2 = match sess.step().unwrap() {
            Step::Write(bytes) => bytes,
            other => panic!("expected Write(msg2), got {other:?}"),
        };
        assert!(!msg2.is_empty());
        sess.wrote().expect("wrote");

        // First transport frame fails to decrypt — that is the
        // designed failure point.
        let garbage = frame(b"not a valid noise transport message").unwrap();
        let err = feed_framed(&mut sess, &garbage).expect_err("decrypt must fail");
        assert!(matches!(err, SessionError::TransportRead(_)), "got {err:?}");
    }
}
