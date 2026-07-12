//! Wire protocol between the daemon and the `file`-backend signing
//! agent, spoken over a `SOCK_SEQPACKET` socketpair. SEQPACKET
//! preserves message boundaries, so each request and each response is
//! exactly one datagram — no length framing needed, just a bounded
//! read buffer.
//!
//! Messages are JSON (serde_json is already in the graph; the payloads
//! are tiny and the human-readable form eases debugging a key-custody
//! path). The bodies never carry the private key — only claims in and
//! a finished JWT out.

use serde::{Deserialize, Serialize};

use crate::providers::jwt_backend::JwtClaims;

/// Environment variable carrying the agent's end of the socketpair as
/// a raw fd number. Set by the daemon on the child; read once by the
/// agent at startup.
pub const AGENT_FD_ENV: &str = "SYMBOLON_AGENT_FD";

/// Upper bound on a single datagram. An RSA-2048 JWT is ~800 bytes and
/// the claims are smaller; 8 KiB is comfortable headroom and bounds
/// the agent's read buffer against a hostile-but-in-process peer.
pub const MAX_MESSAGE: usize = 8 * 1024;

/// Cap on the operator-facing string in [`AgentResponse::Error`] — the
/// only variable-length field in any message either side sends. Bounding
/// it at construction ([`AgentResponse::error`]) is what makes every
/// datagram provably fit [`MAX_MESSAGE`]: JSON escaping can expand a byte
/// at most 6× (`\uXXXX`), so 1 KiB raw → ≤6 KiB encoded, still under the
/// limit with headroom. The peer reads into a `MAX_MESSAGE` buffer and an
/// over-long SEQPACKET datagram is silently truncated, so this bound is
/// enforced, not hoped for.
pub const MAX_ERROR_LEN: usize = 1024;

/// Daemon → agent.
#[derive(Debug, Serialize, Deserialize)]
pub enum AgentRequest {
    /// Sign these claims into a complete RS256 JWT.
    SignJwt { claims: JwtClaims },
    /// Liveness probe used by `self_check`. The agent echoes `Pong`.
    Ping,
}

/// Agent → daemon.
#[derive(Debug, Serialize, Deserialize)]
pub enum AgentResponse {
    /// A complete compact JWS.
    Jwt(String),
    /// Reply to `Ping`.
    Pong,
    /// The agent could not satisfy the request (e.g. the claims failed
    /// to decode, or signing failed). The string is operator-facing and
    /// must not carry key material. Construct via [`Self::error`], which
    /// caps the length so the datagram cannot exceed [`MAX_MESSAGE`].
    Error(String),
}

impl AgentResponse {
    /// Build an `Error` response, capping the message to [`MAX_ERROR_LEN`]
    /// bytes (on a UTF-8 boundary) so the encoded datagram always fits
    /// [`MAX_MESSAGE`]. This is the sole way an over-long field can enter
    /// a message, so capping here makes [`encode`] provably infallible for
    /// every response.
    pub fn error(msg: impl Into<String>) -> Self {
        let mut s = msg.into();
        if s.len() > MAX_ERROR_LEN {
            let mut end = MAX_ERROR_LEN;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            s.truncate(end);
        }
        Self::Error(s)
    }
}

/// Serialise `msg` to a single JSON datagram. Fails only if the value
/// exceeds [`MAX_MESSAGE`] (which would be a bug — claims and JWTs are
/// small).
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(msg).map_err(|e| format!("encode: {e}"))?;
    if bytes.len() > MAX_MESSAGE {
        return Err(format!(
            "message {} bytes exceeds {MAX_MESSAGE}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// Parse one JSON datagram.
pub fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("decode: {e}"))
}
