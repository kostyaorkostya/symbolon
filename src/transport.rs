//! Noise NNpsk0 transport: identity prelude, framing, and snow handshake
//! orchestration. I/O-agnostic — callers supply bytes; this module owns the
//! `HandshakeState` / `TransportState` machinery.
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
//! free functions below (`parse_prelude`, `responder`, `initiator`,
//! `handshake_read`, `frame`, etc.) is the lower layer the state
//! machines call into; the fuzz harness targets them directly.
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

use crate::identity::{Identity, IdentityError};
use crate::psk::Psk;

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

/// Prelude carries `id_len` as a `u8`; `Identity::MAX_LEN` must fit
/// in that byte. Mirrors the `_WIRE_BUDGET_FITS_PARSER` pattern in
/// `daemon.rs` — catch at compile time, not via `debug_assert!`.
const _IDENTITY_FITS_PRELUDE_LEN: () = assert!(Identity::MAX_LEN <= u8::MAX as usize);

/// Errors raised when parsing or validating the identity prelude.
#[derive(Debug, thiserror::Error)]
pub enum PreludeError {
    #[error("prelude is incomplete: need {needed} more bytes")]
    Incomplete { needed: usize },
    #[error("prelude magic mismatch (got {got:?}, expected {:?})", PRELUDE_MAGIC)]
    BadMagic { got: [u8; 4] },
    #[error("prelude version {got} not supported (expected {PRELUDE_VERSION})")]
    BadVersion { got: u8 },
    #[error(
        "prelude identity length {got} out of range (1..={})",
        Identity::MAX_LEN
    )]
    BadIdentityLen { got: u8 },
    #[error(
        "prelude identity byte 0x{byte:02x} at offset {offset} is outside the allowed \
         charset [A-Za-z0-9._-]"
    )]
    InvalidCharset { offset: usize, byte: u8 },
}

/// Lift identity validation errors from `Identity::parse` (used by the
/// wire-side body parser) into the wire-error vocabulary. `BadLen.got`
/// is `usize`; the wire reports `u8`. Saturate — the wire parser can't
/// produce > 255 because `parse_prelude_head` already validated id_len
/// fits in a single byte.
impl From<IdentityError> for PreludeError {
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

/// Total prelude byte length given an identity length.
pub const fn prelude_size(identity_len: usize) -> usize {
    6 + identity_len
}

/// Encode an `Identity` into prelude bytes. Infallible: `Identity`'s
/// constructor already enforces `1..=Identity::MAX_LEN` length and the
/// `[A-Za-z0-9._-]` charset, which is exactly what the wire requires.
pub fn encode_prelude(identity: &Identity) -> Vec<u8> {
    // `Identity::parse` bounds `bytes.len()` to `1..=Identity::MAX_LEN`,
    // and `_IDENTITY_FITS_PRELUDE_LEN` proves at compile time that
    // `Identity::MAX_LEN <= u8::MAX`, so the cast is statically lossless.
    let bytes = identity.as_str().as_bytes();
    let mut out = Vec::with_capacity(prelude_size(bytes.len()));
    out.extend_from_slice(&PRELUDE_MAGIC);
    out.push(PRELUDE_VERSION);
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
    out
}

/// Validate the 6-byte prelude head: magic, version, and identity length.
/// Returns the declared identity length on success. Used by the streaming
/// state machine to reject `bad_magic` / `bad_version` / `bad_identity_len`
/// after the first 6 bytes, before pulling the identity body off the wire.
fn parse_prelude_head(head: &[u8; 6]) -> Result<u8, PreludeError> {
    let &[m0, m1, m2, m3, version, id_len] = head;
    match ([m0, m1, m2, m3], version, id_len) {
        (m, _, _) if m != PRELUDE_MAGIC => Err(PreludeError::BadMagic { got: m }),
        (_, v, _) if v != PRELUDE_VERSION => Err(PreludeError::BadVersion { got: v }),
        (_, _, l) if l == 0 || l as usize > Identity::MAX_LEN => {
            Err(PreludeError::BadIdentityLen { got: l })
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
fn parse_prelude_body(body: &[u8]) -> Result<Identity, PreludeError> {
    match std::str::from_utf8(body) {
        Ok(s) => Ok(Identity::parse(s)?),
        Err(e) => {
            // `valid_up_to()` is the offset of the first byte that
            // broke UTF-8; that byte also fails the ASCII-only
            // identity charset rule, so reporting it as
            // `InvalidCharset` matches what `Identity::parse` would
            // say if the bytes happened to be valid UTF-8.
            let offset = e.valid_up_to();
            Err(PreludeError::InvalidCharset {
                offset,
                byte: body[offset],
            })
        }
    }
}

/// Parse a prelude from `input`. On success returns the parsed
/// identity and the byte length consumed. The caller slices
/// `input[consumed..]` to find the first Noise framed message. The
/// fuzz harness targets this function.
///
/// Streaming callers should use [`Responder`] instead; it sees bytes
/// as they arrive and validates the head before reading the body.
pub fn parse_prelude(input: &[u8]) -> Result<(Identity, usize), PreludeError> {
    let head = input
        .first_chunk::<6>()
        .ok_or_else(|| PreludeError::Incomplete {
            needed: 6 - input.len(),
        })?;
    let id_len = parse_prelude_head(head)?;
    let total = prelude_size(id_len as usize);
    let body = input
        .get(6..total)
        .ok_or_else(|| PreludeError::Incomplete {
            needed: total - input.len(),
        })?;
    let identity = parse_prelude_body(body)?;
    Ok((identity, total))
}

/// Build the responder (server) side of `NOISE_PATTERN` with the given
/// PSK. `prologue` must be the same bytes both peers observed
/// out-of-band before the handshake (for us, the cleartext SBLN
/// identity prelude). It is mixed into the handshake transcript hash;
/// if the two sides disagree on prologue, the first handshake MAC
/// check fails. See snow `Builder::prologue` docs.
pub fn responder(psk: &Psk, prologue: &[u8]) -> Result<HandshakeState, TransportError> {
    build_handshake(psk, prologue, /* initiator */ false)
}

/// Build the initiator (client) side of `NOISE_PATTERN` with the given
/// PSK and shared prologue bytes (see [`responder`] for the prologue
/// contract).
pub fn initiator(psk: &Psk, prologue: &[u8]) -> Result<HandshakeState, TransportError> {
    build_handshake(psk, prologue, /* initiator */ true)
}

fn build_handshake(
    psk: &Psk,
    prologue: &[u8],
    initiator: bool,
) -> Result<HandshakeState, TransportError> {
    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|e: snow::Error| TransportError::Params(e))?;
    let builder = Builder::new(params)
        .prologue(prologue)
        .map_err(TransportError::Params)?
        .psk(0, psk.as_bytes())
        .map_err(TransportError::Params)?;
    if initiator {
        builder.build_initiator().map_err(TransportError::Params)
    } else {
        builder.build_responder().map_err(TransportError::Params)
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
// `Responder` and `Initiator` own the full Noise NNpsk0 lifecycle
// (prelude → handshake → encrypted request/response) as an explicit
// state machine. They emit `Step` values telling the I/O driver what to
// do next; the driver does the I/O and feeds bytes back. Same machine
// drives the async compio daemon and the sync std::net client, so
// protocol changes happen in one place.
// =========================================================================

/// Side-agnostic event the I/O driver must service before calling
/// `step()` again.
#[derive(Debug)]
pub enum Step {
    /// Read exactly `n` bytes from the wire and feed them via `recv`.
    /// `n` is bounded by `MAX_MESSAGE_SIZE`.
    ReadExact { n: usize },
    /// Look up the PSK for `identity`. Caller calls `set_psk(psk)`;
    /// dropping the session is how a "not enrolled" lookup ends.
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
    PreludeHead,
    PreludeBody,
    AwaitingPsk,
    Handshake,
    Transport,
    Done,
}

/// Errors raised by the state machine. Driver maps these directly to
/// log-event `reason=` strings; the variants are chosen to match the
/// catalog in `docs/PROTOCOLS.md`.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("prelude bad magic: got {got:?}")]
    PreludeBadMagic { got: [u8; 4] },
    #[error("prelude bad version: got {got}")]
    PreludeBadVersion { got: u8 },
    #[error("prelude bad identity length: got {got}")]
    PreludeBadIdentityLen { got: u8 },
    #[error("prelude identity byte 0x{byte:02x} at offset {offset} is outside [A-Za-z0-9._-]")]
    PreludeInvalidCharset { offset: usize, byte: u8 },
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

impl From<PreludeError> for SessionError {
    fn from(e: PreludeError) -> Self {
        match e {
            PreludeError::BadMagic { got } => SessionError::PreludeBadMagic { got },
            PreludeError::BadVersion { got } => SessionError::PreludeBadVersion { got },
            PreludeError::BadIdentityLen { got } => SessionError::PreludeBadIdentityLen { got },
            PreludeError::InvalidCharset { offset, byte } => {
                SessionError::PreludeInvalidCharset { offset, byte }
            }
            PreludeError::Incomplete { .. } => {
                // The state machine reads exact byte counts, so a
                // partial-buffer error from the parsers should be
                // unreachable. Surface as WrongState if it ever fires.
                SessionError::WrongState {
                    method: "parse_prelude",
                    state: "incomplete_buffer",
                }
            }
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
    /// when the expected length is a compile-time constant (prelude
    /// head = 6, frame-length prefix = 2).
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
    /// Initial state. Ask the driver for 6 prelude head bytes.
    WantPreludeHead,
    /// Head validated; ask for `head[5]` identity body bytes.
    WantPreludeBody {
        head: [u8; 6],
    },
    /// Identity parsed; ask the driver to look up the PSK. The
    /// `prelude` bytes (head + identity body) are carried forward to
    /// be mixed into the Noise handshake transcript via
    /// `Builder::prologue` once the PSK arrives.
    NeedPsk {
        identity: Identity,
        prelude: Vec<u8>,
    },
    /// `Step::NeedPsk` has been emitted (identity moved out).
    /// Caller must invoke `set_psk` next; another `step()` here is
    /// a contract violation (`WrongState`).
    AwaitingPsk {
        prelude: Vec<u8>,
    },
    /// PSK provided; ask for the 2-byte handshake-msg-1 length.
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
            RState::WantPreludeHead => Phase::PreludeHead,
            RState::WantPreludeBody { .. } => Phase::PreludeBody,
            RState::NeedPsk { .. } | RState::AwaitingPsk { .. } => Phase::AwaitingPsk,
            RState::WantHsLen { .. }
            | RState::WantHsBody { .. }
            | RState::WriteHs { .. }
            | RState::WroteHsPending { .. } => Phase::Handshake,
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

/// Responder-side Noise NNpsk0 session state machine.
///
/// Drive it like:
/// ```ignore
/// let mut sess = Responder::new();
/// loop {
///     match sess.step()? {
///         Step::ReadExact { n } => sess.recv(&read_n_bytes(n).await?)?,
///         Step::NeedPsk { identity } => sess.set_psk(lookup(&identity))?,
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

impl Default for Responder {
    fn default() -> Self {
        Self::new()
    }
}

impl Responder {
    pub fn new() -> Self {
        Self {
            state: RState::WantPreludeHead,
            scratch: Box::new([0u8; MAX_MESSAGE_SIZE]),
        }
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
            RState::WantPreludeHead => {
                self.state = RState::WantPreludeHead;
                Ok(Step::ReadExact { n: 6 })
            }
            RState::WantPreludeBody { head } => {
                let n = head[5] as usize;
                self.state = RState::WantPreludeBody { head };
                Ok(Step::ReadExact { n })
            }
            RState::NeedPsk { identity, prelude } => {
                // Move the identity into the Step (zero clone). The
                // contract is: caller MUST call `set_psk` next. A
                // second `step()` before that returns WrongState
                // via the catch-all below. `prelude` is held in
                // AwaitingPsk so `set_psk` can mix it into the Noise
                // handshake transcript.
                self.state = RState::AwaitingPsk { prelude };
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
            RState::WantPreludeHead => {
                let head = SessionError::recv_chunk::<6>(bytes)?;
                // Validate magic+version+id_len BEFORE asking for the
                // body. A hostile peer can't make us pull `id_len` more
                // bytes unless the head is well-formed.
                let _ = parse_prelude_head(&head)?;
                self.state = RState::WantPreludeBody { head };
                Ok(())
            }
            RState::WantPreludeBody { head } => {
                let id_len = head[5] as usize;
                SessionError::check_recv_len(id_len, bytes.len())?;
                let identity = parse_prelude_body(bytes)?;
                // Stash the full prelude (head + body) so `set_psk`
                // can pass it as the Noise prologue. Both peers
                // independently re-derive these bytes and so agree on
                // the transcript hash.
                let mut prelude = Vec::with_capacity(prelude_size(id_len));
                prelude.extend_from_slice(&head);
                prelude.extend_from_slice(bytes);
                self.state = RState::NeedPsk { identity, prelude };
                Ok(())
            }
            RState::WantHsLen { hs } => {
                let len_buf = SessionError::recv_chunk::<2>(bytes)?;
                let body_len = read_frame_length(&len_buf)?;
                self.state = RState::WantHsBody { hs, body_len };
                Ok(())
            }
            RState::WantHsBody { mut hs, body_len } => {
                SessionError::check_recv_len(body_len, bytes.len())?;
                handshake_read(&mut hs, bytes, &mut self.scratch[..])?;
                // Produce handshake msg 2 immediately so the driver can emit it.
                let n = handshake_write(&mut hs, &[], &mut self.scratch[..])?;
                let out = frame(&self.scratch[..n])?;
                self.state = RState::WriteHs { hs, out };
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

    /// Provide the PSK requested by the previous `Step::NeedPsk`.
    pub fn set_psk(&mut self, psk: Psk) -> Result<(), SessionError> {
        let state_name: &str = (&self.state).into();
        match std::mem::replace(&mut self.state, RState::Failed) {
            RState::AwaitingPsk { prelude } => {
                let hs = responder(&psk, &prelude)?;
                self.state = RState::WantHsLen { hs };
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
    /// Emit the prelude bytes.
    WritePrelude {
        hs: HandshakeState,
        prelude: Vec<u8>,
        request: Vec<u8>,
    },
    /// Prelude bytes handed to driver; awaiting `wrote()`.
    WrotePreludePending {
        hs: HandshakeState,
        request: Vec<u8>,
    },
    /// Emit framed handshake msg 1.
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
            IState::WritePrelude { .. } | IState::WrotePreludePending { .. } => Phase::PreludeHead,
            IState::WriteHs1 { .. }
            | IState::WroteHs1Pending { .. }
            | IState::WantHs2Len { .. }
            | IState::WantHs2Body { .. } => Phase::Handshake,
            IState::WriteReq { .. }
            | IState::WroteReqPending { .. }
            | IState::WantRespLen { .. }
            | IState::WantRespBody { .. } => Phase::Transport,
            IState::Done { .. } | IState::Drained | IState::Failed => Phase::Done,
        }
    }
}

/// Initiator-side Noise NNpsk0 session state machine.
///
/// Identity, PSK, and request bytes are known up front (the client
/// binary reads stdin before opening the socket), so they're consumed
/// by `Initiator::new`. The driver pumps `step()` until `Step::Done`,
/// then calls `take_response()` to recover the decrypted plaintext.
pub struct Initiator {
    state: IState,
    /// One per-session scratch buffer reused across handshake-step
    /// and transport-mode reads/writes. See `Responder::scratch`.
    scratch: Box<[u8; MAX_MESSAGE_SIZE]>,
}

impl Initiator {
    pub fn new(identity: Identity, psk: Psk, request: Vec<u8>) -> Result<Self, SessionError> {
        let prelude = encode_prelude(&identity);
        // The cleartext prelude is the only out-of-band data both
        // peers agree on; bind it into the Noise handshake transcript
        // so an in-flight tamper of magic/version/identity bytes
        // surfaces as a handshake failure rather than silently.
        let hs = initiator(&psk, &prelude)?;
        Ok(Self {
            state: IState::WritePrelude {
                hs,
                prelude,
                request,
            },
            scratch: Box::new([0u8; MAX_MESSAGE_SIZE]),
        })
    }

    pub fn phase(&self) -> Phase {
        self.state.phase()
    }

    pub fn step(&mut self) -> Result<Step, SessionError> {
        let state_name: &str = (&self.state).into();
        match std::mem::replace(&mut self.state, IState::Failed) {
            IState::WritePrelude {
                hs,
                prelude,
                request,
            } => {
                self.state = IState::WrotePreludePending { hs, request };
                Ok(Step::Write(prelude))
            }
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
            IState::WrotePreludePending { mut hs, request } => {
                // Compute handshake msg 1 now that the prelude is on the wire.
                let n = handshake_write(&mut hs, &[], &mut self.scratch[..])?;
                let msg1 = frame(&self.scratch[..n])?;
                self.state = IState::WriteHs1 { hs, msg1, request };
                Ok(())
            }
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

    #[test]
    fn prelude_round_trip() {
        let id = good_identity();
        let bytes = encode_prelude(&id);
        assert_eq!(bytes.len(), prelude_size(id.as_str().len()));
        let (parsed, consumed) = parse_prelude(&bytes).expect("round-trip parse");
        assert_eq!(parsed, id);
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
        let mut bytes = encode_prelude(&Identity::parse("foo").unwrap());
        bytes[0] = b'X';
        assert!(matches!(
            parse_prelude(&bytes),
            Err(PreludeError::BadMagic { .. })
        ));
    }

    #[test]
    fn prelude_rejects_bad_version() {
        let mut bytes = encode_prelude(&Identity::parse("foo").unwrap());
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
        bytes.push((Identity::MAX_LEN as u8) + 1);
        bytes.resize(bytes.len() + Identity::MAX_LEN + 1, b'a');
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

    // encode_prelude rejection tests removed: validation now lives in
    // `Identity::parse`, covered by `identity::tests::parse_rejects_*`.

    /// End-to-end Noise NNpsk0 handshake + a transport-mode message round-trip,
    /// driven entirely in-memory.
    #[test]
    fn noise_handshake_round_trip() {
        let psk = Psk::from([0x42u8; 32]);

        let mut initiator_hs = initiator(&psk, &[]).expect("build initiator");
        let mut responder_hs = responder(&psk, &[]).expect("build responder");

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
        let mut initiator_hs = initiator(&Psk::from([0xaa; 32]), &[]).unwrap();
        let mut responder_hs = responder(&Psk::from([0xbb; 32]), &[]).unwrap();

        let mut buf = [0u8; MAX_MESSAGE_SIZE];
        let mut out = [0u8; MAX_MESSAGE_SIZE];
        let n = handshake_write(&mut initiator_hs, &[], &mut buf).unwrap();
        let res = handshake_read(&mut responder_hs, &buf[..n], &mut out);
        assert!(res.is_err(), "responder must reject mismatched PSK");
    }

    // `builder_rejects_short_psk` removed: `responder`/`initiator`
    // now take `&Psk`, which enforces the 32-byte invariant by type.

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

        let mut server = Responder::new();
        let mut client = Initiator::new(
            Identity::parse("dev-vm-1.test_03").unwrap(),
            psk,
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

    /// Regression test for the double-parse_prelude bug: a bad-magic
    /// head must surface from the FIRST `recv` (after 6 bytes), not
    /// after the second body read. Pulls `id_len` more bytes from a
    /// hostile peer only if the head is well-formed.
    #[test]
    fn responder_rejects_bad_magic_after_first_read() {
        let mut sess = Responder::new();
        assert!(matches!(sess.step().unwrap(), Step::ReadExact { n: 6 }));
        // Feed 6 bytes with wrong magic.
        let bad = b"XXXX\x01\x05";
        let err = sess.recv(bad).expect_err("must reject bad magic");
        assert!(
            matches!(err, SessionError::PreludeBadMagic { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn responder_rejects_bad_version_after_first_read() {
        let mut sess = Responder::new();
        assert!(matches!(sess.step().unwrap(), Step::ReadExact { n: 6 }));
        let mut head = [0u8; 6];
        head[0..4].copy_from_slice(&PRELUDE_MAGIC);
        head[4] = 0x99; // wrong version
        head[5] = 5;
        let err = sess.recv(&head).expect_err("must reject bad version");
        assert!(
            matches!(err, SessionError::PreludeBadVersion { got: 0x99 }),
            "got {err:?}"
        );
    }

    #[test]
    fn responder_rejects_bad_id_len_after_first_read() {
        let mut sess = Responder::new();
        assert!(matches!(sess.step().unwrap(), Step::ReadExact { n: 6 }));
        let mut head = [0u8; 6];
        head[0..4].copy_from_slice(&PRELUDE_MAGIC);
        head[4] = PRELUDE_VERSION;
        head[5] = 0; // bad id_len
        let err = sess.recv(&head).expect_err("must reject zero id_len");
        assert!(
            matches!(err, SessionError::PreludeBadIdentityLen { got: 0 }),
            "got {err:?}"
        );
    }

    #[test]
    fn responder_rejects_invalid_charset_after_body_read() {
        let mut sess = Responder::new();
        assert!(matches!(sess.step().unwrap(), Step::ReadExact { n: 6 }));
        let mut head = [0u8; 6];
        head[0..4].copy_from_slice(&PRELUDE_MAGIC);
        head[4] = PRELUDE_VERSION;
        head[5] = 3;
        sess.recv(&head).expect("head ok");
        assert!(matches!(sess.step().unwrap(), Step::ReadExact { n: 3 }));
        // CR byte = Clone2Leak-class injection attempt.
        let body = b"a\rb";
        let err = sess.recv(body).expect_err("charset must reject CR");
        assert!(
            matches!(
                err,
                SessionError::PreludeInvalidCharset {
                    offset: 1,
                    byte: b'\r'
                }
            ),
            "got {err:?}"
        );
    }

    // Bad-identity rejection at Initiator::new is impossible by
    // construction now — the parameter is `Identity`, validated at
    // `Identity::parse` (see `identity::tests::parse_rejects_*`).
}
