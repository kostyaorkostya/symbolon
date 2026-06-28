//! Admin Unix-domain socket and CLI dispatch.
//!
//! Two halves: a daemon-side accept loop ([`run_admin_loop`]) and a
//! CLI-side dispatcher ([`cli_dispatch`]) that opens the same socket
//! as a client. Both ends share the wire types so they stay in
//! lockstep.
//!
//! Wire protocol: line-delimited JSON. One request per connection,
//! one response, daemon closes. Request: `{"op":"…", …args}\n`.
//! Response: `{"ok":true, …fields}\n` or `{"ok":false,"error":"…",
//! "code":"…"}\n`. CR or embedded LF in any string field is rejected
//! the same way the git-credential parser rejects them
//! (Clone2Leak-class defense applied to the admin path too).
//!
//! State writes are atomic per PROTOCOLS.md § "Atomic writes":
//! tempfile → fsync → rename → fsync parent. `clients.json` lands
//! with mode `0o640`, the symbolon-owned `psks` file with `0o600`.
//! The daemon owns the PSK store directly — atomic write to disk
//! and in-memory swap happen in the same enroll/revoke handler.

use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use compio::BufResult;
use compio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use compio::net::{UnixListener, UnixStream};
use futures_util::FutureExt;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::connection_tracker::ConnectionTracker;
use crate::daemon::{SharedState, StateMutationError};
use crate::events::EventKind;
use crate::identity::Identity;
use crate::ids::{OutReqId, ReqId};
use crate::note::Note;
use crate::providers::{ProviderError, ProviderKind, ProviderReqId, SelfcheckOutcome};
use crate::psk::Psk;

/// Admin requests are operator-driven JSON, not adversarial
/// throughput; the budget stays at 64 KiB to comfortably fit
/// human-typed enroll/revoke payloads. The daemon's wire path
/// uses a tighter 8 KiB budget for its slow-loris exposure.
const WIRE_READ_BUDGET: usize = 64 * 1024;
const PER_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, strum::IntoStaticStr)]
#[serde(tag = "op", rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub(crate) enum Request {
    Status,
    List,
    Enroll {
        provider: ProviderKind,
        client: Identity,
        psk: Psk,
        #[serde(default)]
        note: Option<Note>,
    },
    Revoke {
        provider: ProviderKind,
        client: Identity,
    },
    Mint {
        provider: ProviderKind,
        client: Identity,
        path: String,
    },
    Selfcheck {
        provider: ProviderKind,
    },
}

// ---------------------------------------------------------------------------
// Wire responses
// ---------------------------------------------------------------------------
//
// Each op has a typed success shape; the wire `{"ok": true, ...fields}` is
// formed by flattening into [`OkEnvelope`]. Errors carry their own
// `{"ok": false, "code", "error"}` shape via [`ErrorResponse`]. Handlers
// return `Result<TypedResponse, ErrorResponse>`; the top of `dispatch`
// turns either side into wire bytes.

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StatusResponse {
    uptime_sec: u64,
    providers: Vec<ProviderKind>,
    client_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ListResponse {
    clients: Vec<ListEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ListEntry {
    name: Identity,
    providers: Vec<ProviderKind>,
    #[serde(with = "time::serde::rfc3339")]
    enrolled_at: time::OffsetDateTime,
    note: Option<Note>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MintResponse {
    username: String,
    password: String,
    expires_at_unix: u64,
    out_req_id: OutReqId,
    provider_req_id: Option<ProviderReqId>,
}

/// Serializes to `{}`; combined with [`OkEnvelope`] yields the bare
/// `{"ok": true}` ack used by `enroll` and `revoke`.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Ack {}

/// `{"ok": false, "error": "…"}`. No `code` tag — operators key on
/// the human-readable `error` message (or follow the matching log
/// line via `req_id`); the wire isn't a programmatic-discrimination
/// surface.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ErrorResponse {
    ok: bool,
    error: String,
}

impl ErrorResponse {
    fn new(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: error.into(),
        }
    }

    fn unknown_provider(provider: ProviderKind) -> Self {
        Self::new(format!("provider '{provider}' not configured"))
    }
}

impl From<StateMutationError> for ErrorResponse {
    fn from(e: StateMutationError) -> Self {
        Self::new(e.to_string())
    }
}

impl From<ProviderError> for ErrorResponse {
    fn from(e: ProviderError) -> Self {
        Self::new(crate::logging::ErrorChain(&e).to_string())
    }
}

/// Wraps a typed success payload in the `{"ok": true, …}` envelope
/// via `#[serde(flatten)]`. `ok` is always true at construction.
#[derive(Debug, Serialize)]
struct OkEnvelope<T> {
    ok: bool,
    #[serde(flatten)]
    data: T,
}

impl<T> OkEnvelope<T> {
    fn new(data: T) -> Self {
        Self { ok: true, data }
    }
}

#[derive(Debug, Clone)]
pub enum CliCommand {
    Status,
    List,
    GithubEnroll {
        client: Identity,
        note: Option<Note>,
        psk: Psk,
    },
    GithubRevoke {
        client: Identity,
    },
    GithubMint {
        client: Identity,
        path: String,
    },
    GithubSelfcheck,
}

impl CliCommand {
    fn to_request(&self) -> Request {
        match self {
            CliCommand::Status => Request::Status,
            CliCommand::List => Request::List,
            CliCommand::GithubEnroll { client, note, psk } => Request::Enroll {
                provider: ProviderKind::Github,
                client: client.clone(),
                note: note.clone(),
                psk: *psk,
            },
            CliCommand::GithubRevoke { client } => Request::Revoke {
                provider: ProviderKind::Github,
                client: client.clone(),
            },
            CliCommand::GithubMint { client, path } => Request::Mint {
                provider: ProviderKind::Github,
                client: client.clone(),
                path: path.clone(),
            },
            CliCommand::GithubSelfcheck => Request::Selfcheck {
                provider: ProviderKind::Github,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("admin socket bind failed at {}", path.display())]
    Bind {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("admin accept failed")]
    Accept(#[source] std::io::Error),
    #[error("failed to connect to admin socket at {}", path.display())]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("admin I/O error")]
    Io(#[source] std::io::Error),
    #[error("malformed admin request")]
    RequestParse(#[source] serde_json::Error),
    #[error("malformed admin response")]
    ResponseParse(#[source] serde_json::Error),
    #[error("admin response carried an error: {0}")]
    RemoteError(String),
    #[error("atomic write of {} failed", path.display())]
    AtomicWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

// ---------------------------------------------------------------------------
// Daemon-side: accept loop
// ---------------------------------------------------------------------------

pub(crate) async fn run_admin_loop(
    listener: UnixListener,
    state: Rc<SharedState>,
) -> Result<(), AdminError> {
    // Cache effective UID once. Peer connections from this UID or
    // root are admitted; everything else is rejected with
    // evt=admin_denied. AGENTS.md invariant #9: the admin socket is
    // the sole admin surface, so this is the choke point.
    let my_uid = rustix::process::geteuid();

    let tracker = ConnectionTracker::new(PER_CONNECTION_TIMEOUT, Duration::from_secs(5));
    loop {
        // `select_biased!` with shutdown listed first: when both arms
        // are ready in the same iteration, shutdown wins. Closes the
        // "accept already ready + shutdown just fired" race without an
        // explicit `is_cancelled()` post-check inside the accept arm.
        futures_util::select_biased! {
            _ = state.shutdown.clone().wait().fuse() => break,
            accept_res = listener.accept().fuse() => {
                let (stream, _peer) = accept_res.map_err(AdminError::Accept)?;
                if !check_peer_uid(&stream, my_uid) {
                    continue;
                }
                let state = state.clone();
                let span = tracing::info_span!("admin", req_id = %ReqId::new());
                tracker.spawn(async move || {
                    use tracing::Instrument;
                    handle_admin(stream, state).instrument(span).await;
                });
            }
        }
    }
    let _ = tracker.drain().await;
    Ok(())
}

async fn handle_admin(mut stream: UnixStream, state: Rc<SharedState>) {
    let raw = match read_line(&mut stream).await {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => return,
    };
    let parsed: Result<Request, _> = serde_json::from_slice(&raw);
    let request = match parsed {
        Ok(r) => r,
        Err(e) => {
            info!(evt = %EventKind::AdminRequest, ok = false, error = %e);
            let resp: Result<Ack, _> =
                Err(ErrorResponse::new(format!("request parse failed: {e}")));
            let _ = write_response(&mut stream, resp).await;
            return;
        }
    };
    info!(evt = %EventKind::AdminRequest, op = <&str>::from(&request));
    let _ = dispatch_and_write(&request, &state, &mut stream).await;
}

async fn dispatch_and_write(
    request: &Request,
    state: &Rc<SharedState>,
    stream: &mut UnixStream,
) -> std::io::Result<()> {
    match request {
        Request::Status => write_response::<StatusResponse>(stream, Ok(handle_status(state))).await,
        Request::List => write_response::<ListResponse>(stream, Ok(handle_list(state))).await,
        Request::Enroll {
            provider,
            client,
            note,
            psk,
        } => {
            write_response(
                stream,
                handle_enroll(state, *provider, client.clone(), note.clone(), *psk).await,
            )
            .await
        }
        Request::Revoke { provider, client } => {
            write_response(stream, handle_revoke(state, *provider, client).await).await
        }
        Request::Mint {
            provider,
            client,
            path,
        } => write_response(stream, handle_mint(state, *provider, client, path).await).await,
        Request::Selfcheck { provider } => {
            write_response(stream, handle_selfcheck(state, *provider).await).await
        }
    }
}

// ---------------------------------------------------------------------------
// Per-op handlers
// ---------------------------------------------------------------------------

fn handle_status(state: &SharedState) -> StatusResponse {
    StatusResponse {
        uptime_sec: state.start_time.elapsed().as_secs(),
        providers: state.providers.keys().copied().collect(),
        client_count: state.clients.borrow().len(),
    }
}

fn handle_list(state: &SharedState) -> ListResponse {
    ListResponse {
        clients: state
            .clients
            .borrow()
            .iter()
            .map(|(id, c)| ListEntry {
                name: id.clone(),
                providers: c.providers.clone(),
                enrolled_at: c.enrolled_at,
                note: c.note.clone(),
            })
            .collect(),
    }
}

async fn handle_enroll(
    state: &SharedState,
    provider: ProviderKind,
    client: Identity,
    note: Option<Note>,
    psk: Psk,
) -> Result<Ack, ErrorResponse> {
    state
        .enroll_client(client.clone(), psk, provider, note)
        .await?;
    info!(evt = %EventKind::Enroll, provider = %provider, client = %client);
    Ok(Ack {})
}

async fn handle_revoke(
    state: &SharedState,
    provider: ProviderKind,
    client: &Identity,
) -> Result<Ack, ErrorResponse> {
    if state.lookup_provider(provider).is_none() {
        return Err(ErrorResponse::unknown_provider(provider));
    }
    state.revoke_client(client.as_str()).await?;
    Ok(Ack {})
}

async fn handle_mint(
    state: &Rc<SharedState>,
    provider: ProviderKind,
    client: &Identity,
    path: &str,
) -> Result<MintResponse, ErrorResponse> {
    if !state.clients.borrow().contains_key(client) {
        return Err(StateMutationError::UnknownClient(client.to_string()).into());
    }
    let outcome = state
        .lookup_provider(provider)
        .ok_or_else(|| ErrorResponse::unknown_provider(provider))?
        .mint(path)
        .await?;
    Ok(MintResponse {
        expires_at_unix: outcome.response.password_expiry_unix_secs(),
        username: outcome.response.username,
        password: outcome.response.password,
        out_req_id: outcome.out_req_id,
        provider_req_id: outcome.provider_req_id,
    })
}

async fn handle_selfcheck(
    state: &Rc<SharedState>,
    provider: ProviderKind,
) -> Result<SelfcheckOutcome, ErrorResponse> {
    Ok(state
        .lookup_provider(provider)
        .ok_or_else(|| ErrorResponse::unknown_provider(provider))?
        .selfcheck()
        .await?)
}

// ---------------------------------------------------------------------------
// CLI-side: dispatch
// ---------------------------------------------------------------------------

pub async fn cli_dispatch(socket_path: &Path, command: CliCommand) -> Result<i32, AdminError> {
    let request = command.to_request();
    let mut payload = serde_json::to_vec(&request).map_err(AdminError::RequestParse)?;
    payload.push(b'\n');

    let mut stream =
        UnixStream::connect(socket_path)
            .await
            .map_err(|source| AdminError::Connect {
                path: socket_path.to_path_buf(),
                source,
            })?;
    let BufResult(write_res, _) = stream.write_all(payload).await;
    write_res.map_err(AdminError::Io)?;
    let _ = stream.flush().await;

    let response_bytes = read_line(&mut stream).await.map_err(AdminError::Io)?;
    let is_ok = is_ok_response(&response_bytes)?;
    if !is_ok {
        // Echo the full error JSON to stderr verbatim. Operators
        // wanting structured access pipe stderr through jq; humans
        // get the same JSON that machines do.
        let mut bytes = response_bytes;
        bytes.push(b'\n');
        let _ = std::io::Write::write_all(&mut std::io::stderr(), &bytes);
        return Ok(1);
    }

    // Success path. Default: write the daemon's JSON response
    // verbatim to stdout. Enroll is the one case where the CLI owns
    // data the daemon doesn't (the PSK we generated locally), so we
    // synthesize a `{ok, psk_hex}` JSON object instead of echoing
    // the daemon's `{"ok": true}` ack.
    match &command {
        CliCommand::GithubEnroll { psk, .. } => {
            let synth = OkEnvelope::new(serde_json::json!({ "psk_hex": format!("{psk:x}") }));
            let mut bytes = serde_json::to_vec(&synth).map_err(AdminError::ResponseParse)?;
            bytes.push(b'\n');
            std::io::Write::write_all(&mut std::io::stdout(), &bytes).map_err(AdminError::Io)?;
        }
        _ => {
            let mut bytes = response_bytes;
            bytes.push(b'\n');
            std::io::Write::write_all(&mut std::io::stdout(), &bytes).map_err(AdminError::Io)?;
        }
    }
    Ok(0)
}

/// Minimal-allocation discriminator: read just the `ok` field off the
/// daemon response without materialising the full payload. The body is
/// echoed verbatim downstream, so we never need the parsed structure.
fn is_ok_response(bytes: &[u8]) -> Result<bool, AdminError> {
    #[derive(Deserialize)]
    struct OkField {
        ok: bool,
    }
    let f: OkField = serde_json::from_slice(bytes).map_err(AdminError::ResponseParse)?;
    Ok(f.ok)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Returns false (denial) only on a definitive non-root, non-self UID.
// On `socket_peercred` syscall failure we admit the connection and
// log; refusing on syscall error would be a denial-of-service
// against the operator if the kernel ever returns a transient EINVAL
// or similar.
fn check_peer_uid(stream: &UnixStream, my_uid: rustix::process::Uid) -> bool {
    use std::os::fd::AsFd;
    match rustix::net::sockopt::socket_peercred(stream.as_fd()) {
        Ok(cred) => {
            if cred.uid.is_root() || cred.uid == my_uid {
                true
            } else {
                tracing::warn!(
                    evt = %EventKind::AdminDenied,
                    peer_uid = %cred.uid,
                    peer_pid = %cred.pid,
                );
                false
            }
        }
        Err(e) => {
            tracing::warn!(
                evt = %EventKind::AdminPeercredFailed,
                error = %e,
                "admitting connection; peer credentials unavailable",
            );
            true
        }
    }
}

async fn read_line(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut accumulated = Vec::new();
    let mut chunk: Vec<u8> = Vec::with_capacity(1024);
    loop {
        if let Some(pos) = accumulated.iter().position(|&b| b == b'\n') {
            accumulated.truncate(pos);
            return Ok(accumulated);
        }
        if accumulated.len() >= WIRE_READ_BUDGET {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "admin request exceeds size cap",
            ));
        }
        chunk.clear();
        let BufResult(res, returned) = stream.read(chunk).await;
        chunk = returned;
        match res {
            Ok(0) => {
                // EOF without a trailing `\n`. Caller treats this as a
                // bad request rather than an empty line.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "admin connection closed mid-request",
                ));
            }
            Ok(_) => accumulated.extend_from_slice(&chunk),
            Err(e) => return Err(e),
        }
    }
}

async fn write_response<T: Serialize>(
    stream: &mut UnixStream,
    result: Result<T, ErrorResponse>,
) -> std::io::Result<()> {
    let mut payload = match &result {
        Ok(data) => serde_json::to_vec(&OkEnvelope::new(data)),
        Err(err) => serde_json::to_vec(err),
    }
    .map_err(std::io::Error::other)?;
    payload.push(b'\n');
    let BufResult(res, _) = stream.write_all(payload).await;
    res?;
    let _ = stream.flush().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = Request::Enroll {
            provider: ProviderKind::Github,
            client: Identity::parse("vm-1").unwrap(),
            note: None,
            psk: crate::psk::Psk::from([0xAAu8; 32]),
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: Request = serde_json::from_str(&s).unwrap();
        match back {
            Request::Enroll {
                provider, client, ..
            } => {
                assert_eq!(provider, ProviderKind::Github);
                assert_eq!(client.as_str(), "vm-1");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn status_request_serializes_to_op_field() {
        let s = serde_json::to_string(&Request::Status).unwrap();
        assert!(s.contains("\"op\":\"status\""));
    }

    #[test]
    fn error_response_serializes_with_ok_false() {
        let e = ErrorResponse::new("nope");
        let s = serde_json::to_string(&e).unwrap();
        assert_eq!(s, r#"{"ok":false,"error":"nope"}"#);
    }

    #[test]
    fn ok_envelope_flattens_payload() {
        let env = OkEnvelope::new(StatusResponse {
            uptime_sec: 3,
            providers: vec![ProviderKind::Github],
            client_count: 0,
        });
        let v = serde_json::to_value(&env).unwrap();
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(v["uptime_sec"], 3);
        assert_eq!(v["providers"], serde_json::json!(["github"]));
        assert_eq!(v["client_count"], 0);
    }

    #[test]
    fn ok_envelope_with_ack_yields_bare_ok() {
        let env = OkEnvelope::new(Ack {});
        let s = serde_json::to_string(&env).unwrap();
        assert_eq!(s, r#"{"ok":true}"#);
    }
}
