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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use compio::BufResult;
use compio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use compio::net::{UnixListener, UnixStream};
use futures_util::FutureExt;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::daemon::{ResolvedClient, SharedState};
use crate::events::EventKind;
use crate::providers::github::GithubError;

const CLIENTS_FILE_MODE: u32 = 0o640;
const PSK_FILE_MODE: u32 = 0o600;
/// Admin requests are operator-driven JSON, not adversarial
/// throughput; the budget stays at 64 KiB to comfortably fit
/// human-typed enroll/revoke payloads. The daemon's wire path
/// uses a tighter 8 KiB budget for its slow-loris exposure.
const WIRE_READ_BUDGET: usize = 64 * 1024;
const PER_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const PROVIDER_GITHUB: &str = "github";

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum Request {
    Status,
    List,
    Enroll {
        provider: String,
        client: String,
        #[serde(default)]
        note: Option<String>,
    },
    Revoke {
        provider: String,
        client: String,
    },
    Mint {
        provider: String,
        client: String,
        path: String,
    },
    Selfcheck {
        provider: String,
    },
}

impl Request {
    fn op_name(&self) -> &'static str {
        match self {
            Request::Status => "status",
            Request::List => "list",
            Request::Enroll { .. } => "enroll",
            Request::Revoke { .. } => "revoke",
            Request::Mint { .. } => "mint",
            Request::Selfcheck { .. } => "selfcheck",
        }
    }
}

#[derive(Debug, Clone)]
pub enum CliCommand {
    Status,
    List,
    GithubEnroll {
        client: String,
        note: Option<String>,
    },
    GithubRevoke {
        client: String,
    },
    GithubMint {
        client: String,
        path: String,
    },
    GithubSelfcheck,
}

impl CliCommand {
    fn to_request(&self) -> Request {
        match self {
            CliCommand::Status => Request::Status,
            CliCommand::List => Request::List,
            CliCommand::GithubEnroll { client, note } => Request::Enroll {
                provider: PROVIDER_GITHUB.to_string(),
                client: client.clone(),
                note: note.clone(),
            },
            CliCommand::GithubRevoke { client } => Request::Revoke {
                provider: PROVIDER_GITHUB.to_string(),
                client: client.clone(),
            },
            CliCommand::GithubMint { client, path } => Request::Mint {
                provider: PROVIDER_GITHUB.to_string(),
                client: client.clone(),
                path: path.clone(),
            },
            CliCommand::GithubSelfcheck => Request::Selfcheck {
                provider: PROVIDER_GITHUB.to_string(),
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
    let my_uid = rustix::process::geteuid().as_raw();

    let tracker = crate::connection_tracker::ConnectionTracker::new(
        PER_CONNECTION_TIMEOUT,
        Duration::from_secs(5),
    );
    loop {
        futures_util::select! {
            accept_res = listener.accept().fuse() => {
                let (stream, _peer) = accept_res.map_err(AdminError::Accept)?;
                if state.shutdown.is_cancelled() {
                    drop(stream);
                    continue;
                }
                if !check_peer_uid(&stream, my_uid) {
                    drop(stream);
                    continue;
                }
                let state = state.clone();
                tracker.spawn(async move || {
                    handle_admin(stream, state).await;
                });
            }
            _ = state.shutdown.clone().wait().fuse() => break,
        }
    }
    let _ = tracker.drain().await;
    Ok(())
}

async fn handle_admin(mut stream: UnixStream, state: Rc<SharedState>) {
    let req_id = ulid::Ulid::new().to_string();
    let raw = match read_line(&mut stream).await {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => return,
    };
    let request: Request = match serde_json::from_slice(&raw) {
        Ok(r) => r,
        Err(e) => {
            info!(evt = %EventKind::AdminRequest, req_id = %req_id, ok = false, error = %e);
            let resp = error_response("bad_request", &format!("request parse failed: {e}"));
            let _ = write_response(&mut stream, &resp).await;
            return;
        }
    };
    info!(evt = %EventKind::AdminRequest, req_id = %req_id, op = %request.op_name());
    let resp_value = match dispatch(&req_id, &request, &state).await {
        Ok(v) => v,
        Err(e) => e,
    };
    let _ = write_response(&mut stream, &resp_value).await;
}

async fn dispatch(
    req_id: &str,
    request: &Request,
    state: &Rc<SharedState>,
) -> Result<serde_json::Value, serde_json::Value> {
    match request {
        Request::Status => Ok(handle_status(state)),
        Request::List => Ok(handle_list(state)),
        Request::Enroll {
            provider,
            client,
            note,
        } => handle_enroll(req_id, state, provider, client, note.clone()).await,
        Request::Revoke { provider, client } => {
            handle_revoke(req_id, state, provider, client).await
        }
        Request::Mint {
            provider,
            client,
            path,
        } => handle_mint(req_id, state, provider, client, path).await,
        Request::Selfcheck { provider } => handle_selfcheck(req_id, state, provider).await,
    }
}

// ---------------------------------------------------------------------------
// Per-op handlers
// ---------------------------------------------------------------------------

fn handle_status(state: &SharedState) -> serde_json::Value {
    let uptime_sec = SystemTime::now()
        .duration_since(state.start_time)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut providers: Vec<&str> = state.providers.keys().map(String::as_str).collect();
    providers.sort();
    let client_count = state.clients.borrow().len();
    serde_json::json!({
        "ok": true,
        "uptime_sec": uptime_sec,
        "providers": providers,
        "client_count": client_count,
    })
}

fn handle_list(state: &SharedState) -> serde_json::Value {
    let borrowed = state.clients.borrow();
    let mut clients: Vec<&ResolvedClient> = borrowed.values().collect();
    clients.sort_by_key(|c| c.name.as_str());
    let entries: Vec<serde_json::Value> = clients
        .into_iter()
        .map(|c| {
            let mut provs: Vec<&str> = c.providers.iter().map(String::as_str).collect();
            provs.sort();
            serde_json::json!({
                "name": c.name,
                "providers": provs,
                "enrolled_at": c.enrolled_at,
                "note": c.note,
            })
        })
        .collect();
    serde_json::json!({ "ok": true, "clients": entries })
}

/// RAII rollback for `handle_enroll`. The PSK is inserted into the
/// in-memory store BEFORE we attempt the on-disk writes; on any
/// failure between then and `commit()`, Drop rolls the in-memory
/// insert back so memory and disk stay coherent. Same pattern as
/// `InFlightGuard` in `providers::github` — default Drop is the
/// rollback path; `commit(self)` consumes the guard to disarm it.
struct EnrollRollback<'a> {
    state: &'a SharedState,
    client: String,
    armed: bool,
}

impl<'a> EnrollRollback<'a> {
    fn new(state: &'a SharedState, client: &str) -> Self {
        Self {
            state,
            client: client.to_string(),
            armed: true,
        }
    }

    fn commit(mut self) {
        self.armed = false;
    }
}

impl Drop for EnrollRollback<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.state.psks.borrow_mut().remove(&self.client);
        }
    }
}

async fn handle_enroll(
    req_id: &str,
    state: &SharedState,
    provider: &str,
    client: &str,
    note: Option<String>,
) -> Result<serde_json::Value, serde_json::Value> {
    let _ = req_id; // logged at handle_admin entry; not threaded further today
    if provider != PROVIDER_GITHUB {
        return Err(error_response(
            "unknown_provider",
            &format!("provider '{provider}' not configured"),
        ));
    }
    if !is_valid_client_name(client) {
        return Err(error_response(
            "bad_request",
            "client name must be non-empty ASCII without ':' or whitespace",
        ));
    }
    // PROTOCOLS.md "CR or embedded LF inside any string field is
    // rejected (same Clone2Leak-class defence applied to the admin
    // path)" — applies to `note` as well as `client`.
    if let Some(n) = note.as_deref()
        && n.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0x00))
    {
        return Err(error_response(
            "bad_request",
            "note must not contain CR/LF/NUL bytes",
        ));
    }

    // Identity collision check: every enrolled client has a unique
    // name. The PSK store and clients.json table are kept in lockstep,
    // so checking just the clients table is sufficient.
    if state.clients.borrow().contains_key(client) {
        return Err(error_response(
            "client_already_enrolled",
            &format!("client '{client}' already enrolled"),
        ));
    }

    let key_bytes = generate_psk_key()
        .await
        .map_err(|e| error_response("internal", &format!("rng: {e}")))?;
    let psk_hex = hex::encode(key_bytes);

    // Update the in-memory PSK store, then write the new on-disk file
    // (deterministic sorted render). RAII: the guard's default Drop
    // removes the in-memory insert; on success we `commit()` to
    // disarm it, mirroring the `InFlightGuard` pattern in github.rs.
    state
        .psks
        .borrow_mut()
        .insert(client.to_string(), key_bytes);
    let rollback = EnrollRollback::new(state, client);
    let psk_content = state.psks.borrow().render();
    atomic_write(
        &state.psk_file_path,
        psk_content.into_bytes(),
        PSK_FILE_MODE,
    )
    .await
    .map_err(|e| error_response("internal", &format!("write psks: {e}")))?;

    // Update clients.json: read, append, atomic write.
    let enrolled_at = format_rfc3339_z(SystemTime::now());
    let mut clients_doc = read_clients_doc(&state.clients_file_path)
        .await
        .map_err(|e| error_response("internal", &e))?;
    clients_doc.clients.push(crate::config::ClientEntry {
        name: client.to_string(),
        providers: vec![PROVIDER_GITHUB.to_string()],
        enrolled_at: enrolled_at.clone(),
        note: note.clone(),
    });
    let clients_bytes = serde_json::to_vec_pretty(&clients_doc)
        .map_err(|e| error_response("internal", &format!("encode clients.json: {e}")))?;
    atomic_write(&state.clients_file_path, clients_bytes, CLIENTS_FILE_MODE)
        .await
        .map_err(|e| error_response("internal", &format!("write clients.json: {e}")))?;

    // Commit to in-memory clients table (keyed on identity now).
    state.clients.borrow_mut().insert(
        client.to_string(),
        ResolvedClient {
            name: client.to_string(),
            providers: vec![PROVIDER_GITHUB.to_string()],
            enrolled_at,
            note,
        },
    );
    rollback.commit();

    info!(evt = %EventKind::Enroll, provider = provider, client = client);
    Ok(serde_json::json!({
        "ok": true,
        "identity": client,
        "psk_hex": psk_hex,
        "client_name": client,
    }))
}

async fn handle_revoke(
    req_id: &str,
    state: &SharedState,
    provider: &str,
    client: &str,
) -> Result<serde_json::Value, serde_json::Value> {
    let _ = req_id; // logged at handle_admin entry; not threaded further today
    if provider != PROVIDER_GITHUB {
        return Err(error_response(
            "unknown_provider",
            &format!("provider '{provider}' not configured"),
        ));
    }

    // Identity must be enrolled. Both the in-memory PSK store and the
    // clients table are kept in lockstep by `enroll`, so checking one
    // is sufficient.
    if !state.clients.borrow().contains_key(client) {
        return Err(error_response(
            "unknown_client",
            &format!("no enrolled client named '{client}'"),
        ));
    }

    // Rewrite clients.json without the entry. (The single-provider
    // build always removes the whole entry; multi-provider revoke is
    // out of scope this session.)
    let mut clients_doc = read_clients_doc(&state.clients_file_path)
        .await
        .map_err(|e| error_response("internal", &e))?;
    clients_doc.clients.retain(|c| c.name != client);
    let clients_bytes = serde_json::to_vec_pretty(&clients_doc)
        .map_err(|e| error_response("internal", &format!("encode clients.json: {e}")))?;
    atomic_write(&state.clients_file_path, clients_bytes, CLIENTS_FILE_MODE)
        .await
        .map_err(|e| error_response("internal", &format!("write clients.json: {e}")))?;

    // Remove from the PSK store and rewrite the on-disk file.
    state.psks.borrow_mut().remove(client);
    let psk_content = state.psks.borrow().render();
    atomic_write(
        &state.psk_file_path,
        psk_content.into_bytes(),
        PSK_FILE_MODE,
    )
    .await
    .map_err(|e| error_response("internal", &format!("write psks: {e}")))?;

    state.clients.borrow_mut().remove(client);

    info!(evt = %EventKind::Revoke, provider = provider, client = client);
    Ok(serde_json::json!({ "ok": true }))
}

async fn handle_mint(
    req_id: &str,
    state: &Rc<SharedState>,
    provider: &str,
    client: &str,
    path: &str,
) -> Result<serde_json::Value, serde_json::Value> {
    let provider_obj = lookup_provider(state, provider).ok_or_else(|| {
        error_response(
            "unknown_provider",
            &format!("provider '{provider}' not configured"),
        )
    })?;
    if !state.clients.borrow().contains_key(client) {
        return Err(error_response(
            "unknown_client",
            &format!("no enrolled client named '{client}'"),
        ));
    }
    match provider_obj.mint(req_id, path).await {
        Ok(outcome) => {
            let expires_unix = outcome
                .response
                .password_expiry_utc
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            Ok(serde_json::json!({
                "ok": true,
                "username": outcome.response.username,
                "password": outcome.response.password,
                "expires_at_unix": expires_unix,
                "repo_id": outcome.repo_id,
                "out_req_id": outcome.out_req_id,
                "gh_req_id": outcome.gh_req_id,
            }))
        }
        Err(e) => Err(error_response_from_github(&e)),
    }
}

async fn handle_selfcheck(
    req_id: &str,
    state: &Rc<SharedState>,
    provider: &str,
) -> Result<serde_json::Value, serde_json::Value> {
    let provider_obj = lookup_provider(state, provider).ok_or_else(|| {
        error_response(
            "unknown_provider",
            &format!("provider '{provider}' not configured"),
        )
    })?;
    match provider_obj.selfcheck(req_id).await {
        Ok(outcome) => Ok(serde_json::json!({
            "ok": true,
            "client_id": outcome.client_id,
            "installation_id": outcome.installation_id,
            "api_base": outcome.api_base,
            "clock_skew_sec": outcome.clock_skew_sec,
            "out_req_id": outcome.out_req_id,
            "gh_req_id": outcome.gh_req_id,
        })),
        Err(e) => Err(error_response_from_github(&e)),
    }
}

fn error_response_from_github(err: &GithubError) -> serde_json::Value {
    let (code, msg) = match err {
        GithubError::RepoNotFound { path } => (
            "repo_not_accessible",
            format!("repository '{path}' not found or App lacks access"),
        ),
        GithubError::Unauthorized { body } => {
            ("provider_4xx", format!("unauthorized (401): {body}"))
        }
        GithubError::Forbidden { body } => ("provider_4xx", format!("forbidden (403): {body}")),
        GithubError::RateLimited => ("provider_4xx", "rate limited (429)".to_string()),
        GithubError::MalformedPath(p) => ("bad_request", format!("malformed owner/repo path: {p}")),
        GithubError::OtherStatus(s) => ("internal", format!("provider status {s}")),
        GithubError::ClientIdMismatch {
            configured,
            reported,
        } => (
            "internal",
            format!("Client ID mismatch: configured {configured}, GitHub reports {reported}"),
        ),
        _ => ("internal", format!("{err}")),
    };
    error_response(code, &msg)
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
    let value: serde_json::Value =
        serde_json::from_slice(&response_bytes).map_err(AdminError::ResponseParse)?;

    if value.get("ok").and_then(|b| b.as_bool()) != Some(true) {
        let msg = value
            .get("error")
            .and_then(|s| s.as_str())
            .unwrap_or("(no error message)");
        eprintln!("symbolon: error: {msg}");
        return Ok(1);
    }

    print_success(&command, &value);
    Ok(0)
}

fn print_success(command: &CliCommand, response: &serde_json::Value) {
    match command {
        CliCommand::Status => {
            let uptime_sec = response
                .get("uptime_sec")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let providers = response
                .get("providers")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let client_count = response
                .get("client_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            println!("Uptime: {uptime_sec}s");
            println!("Providers: {providers}");
            println!("Clients: {client_count}");
        }
        CliCommand::List => {
            let empty = vec![];
            let entries = response
                .get("clients")
                .and_then(|v| v.as_array())
                .unwrap_or(&empty);
            if entries.is_empty() {
                println!("(no enrolled clients)");
                return;
            }
            for c in entries {
                let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let provs = c
                    .get("providers")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                let enrolled = c.get("enrolled_at").and_then(|v| v.as_str()).unwrap_or("?");
                println!("{name}\t{provs}\t{enrolled}");
            }
        }
        CliCommand::GithubEnroll { client, .. } => {
            let psk_hex = response
                .get("psk_hex")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            println!("Enrolled '{client}' for github.com.");
            println!();
            println!("# On the client VM, install the helper binary alongside git:");
            println!("#   /usr/local/bin/git-credential-symbolon");
            println!();
            println!("# Write the PSK to /etc/symbolon/psk (mode 0600):");
            println!("{psk_hex}");
            println!();
            println!("# Configure git to use the helper for github.com:");
            println!("git config --global credential.https://github.com.helper \\");
            println!(
                "  \"/usr/local/bin/git-credential-symbolon \\
   --endpoint <broker-host>:9418 \\
   --identity {client} \\
   --psk-file /etc/symbolon/psk\""
            );
        }
        CliCommand::GithubRevoke { client } => {
            println!("Revoked '{client}' from github.com.");
        }
        CliCommand::GithubMint { .. } => {
            let username = response
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let password = response
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let exp = response
                .get("expires_at_unix")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            println!("username={username}");
            println!("password={password}");
            println!("expires_at_unix={exp}");
        }
        CliCommand::GithubSelfcheck => {
            let client_id = response
                .get("client_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let api = response
                .get("api_base")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let skew = response
                .get("clock_skew_sec")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            println!("OK: App {client_id} reachable at {api}, clock skew {skew}s");
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn error_response(code: &str, msg: &str) -> serde_json::Value {
    serde_json::json!({ "ok": false, "code": code, "error": msg })
}

fn lookup_provider<'a>(
    state: &'a SharedState,
    provider: &str,
) -> Option<&'a crate::providers::github::GitHubProvider> {
    // Single-provider build: the wire protocol carries the provider
    // *type* ("github"), but the daemon's HashMap is keyed by host
    // string ("github.com"). For now, "github" → the (one) configured
    // GitHub provider. When a second provider type lands, this routing
    // grows a type→provider map.
    if provider == PROVIDER_GITHUB {
        state.providers.values().next()
    } else {
        state.providers.get(provider)
    }
}

fn is_valid_client_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= crate::transport::MAX_IDENTITY_LEN
        && bytes
            .iter()
            .copied()
            .all(crate::transport::is_identity_byte)
}

async fn generate_psk_key() -> std::io::Result<[u8; 32]> {
    use compio::io::AsyncReadAtExt;
    let file = compio::fs::File::open("/dev/urandom").await?;
    let buf = vec![0u8; 32];
    let BufResult(res, buf) = file.read_exact_at(buf, 0).await;
    res?;
    buf.try_into()
        .map_err(|_| std::io::Error::other("short read from /dev/urandom"))
}

pub(crate) async fn atomic_write(path: &Path, content: Vec<u8>, mode: u32) -> std::io::Result<()> {
    use compio::io::AsyncWriteAtExt;
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent"))?
        .to_path_buf();
    let base = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let tmp = dir.join(format!(
        "{}.tmp.{}",
        base.to_string_lossy(),
        ulid::Ulid::new()
    ));
    {
        let mut f = compio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .await?;
        let BufResult(res, _) = f.write_all_at(content, 0).await;
        res?;
        f.sync_all().await?;
    }
    if let Err(e) = compio::fs::rename(&tmp, path).await {
        let _ = compio::fs::remove_file(&tmp).await;
        return Err(e);
    }
    // Parent-dir fsync: open the dir as a File and call sync_all.
    // compio::fs::File::open defaults to O_RDONLY which is the right
    // mode for fsync-only on a directory.
    compio::fs::File::open(&dir).await?.sync_all().await?;
    Ok(())
}

async fn read_clients_doc(path: &Path) -> Result<crate::config::ClientsFile, String> {
    match compio::fs::read(path).await {
        Ok(bytes) => {
            let text = std::str::from_utf8(&bytes)
                .map_err(|e| format!("non-utf8 {}: {e}", path.display()))?;
            crate::config::parse_clients_file(text, path)
                .map_err(|e| format!("parse {}: {e}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(crate::config::ClientsFile {
            version: crate::config::CLIENTS_SCHEMA_VERSION,
            clients: Vec::new(),
        }),
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

fn format_rfc3339_z(t: SystemTime) -> String {
    // Tries the clock; on any failure (pre-epoch clock, year-9999
    // overflow on the time crate side, format-string error) falls
    // back to the epoch. The caller stores this value verbatim into
    // the on-disk `enrolled_at` field — better to record a wrong
    // timestamp than to abort an otherwise-successful enroll.
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let formatted = i64::try_from(secs)
        .ok()
        .and_then(|s| time::OffsetDateTime::from_unix_timestamp(s).ok())
        .and_then(|dt| {
            dt.format(&time::format_description::well_known::Rfc3339)
                .ok()
        });
    match formatted {
        Some(s) => s,
        None => {
            tracing::warn!(
                evt = "rfc3339_format_failed",
                secs = secs,
                "falling back to epoch for enrolled_at timestamp"
            );
            "1970-01-01T00:00:00Z".to_string()
        }
    }
}

// Returns false (denial) only on a definitive non-root, non-self UID.
// On `socket_peercred` syscall failure we admit the connection and
// log; refusing on syscall error would be a denial-of-service
// against the operator if the kernel ever returns a transient EINVAL
// or similar.
fn check_peer_uid(stream: &UnixStream, my_uid: u32) -> bool {
    use std::os::fd::AsFd;
    match rustix::net::sockopt::socket_peercred(stream.as_fd()) {
        Ok(cred) => {
            let uid = cred.uid.as_raw();
            if uid == 0 || uid == my_uid {
                true
            } else {
                tracing::warn!(
                    evt = %EventKind::AdminDenied,
                    peer_uid = uid,
                    peer_pid = cred.pid.as_raw_nonzero().get(),
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

// Per-iteration `Vec` allocation. For the admin protocol's tiny
// JSON requests this is invisible; iggy's `BytesMut::with_capacity`
// + `.clear()` (or compio's `BufferPool` + `AsyncReadManaged`) is
// the reuse pattern if it ever matters.
async fn read_line(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut accumulated = Vec::new();
    // Single 1 KiB chunk buffer reused across reads via clear-and-
    // reclaim (iggy pattern at
    // iggy/core/server/src/tcp/connection_handler.rs:49-81).
    // compio takes the Vec by value and returns it; we reuse the
    // allocation on the next iteration.
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

async fn write_response(stream: &mut UnixStream, value: &serde_json::Value) -> std::io::Result<()> {
    let mut payload = serde_json::to_vec(value).map_err(std::io::Error::other)?;
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
            provider: "github".to_string(),
            client: "vm-1".to_string(),
            note: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: Request = serde_json::from_str(&s).unwrap();
        match back {
            Request::Enroll {
                provider, client, ..
            } => {
                assert_eq!(provider, "github");
                assert_eq!(client, "vm-1");
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
    fn is_valid_client_name_accepts_typical_names() {
        assert!(is_valid_client_name("dev-vm-1"));
        assert!(is_valid_client_name("client.42"));
        assert!(is_valid_client_name("a_b_c"));
    }

    #[test]
    fn is_valid_client_name_rejects_bad() {
        assert!(!is_valid_client_name(""));
        assert!(!is_valid_client_name("with space"));
        assert!(!is_valid_client_name("has:colon"));
        assert!(!is_valid_client_name("has\nlf"));
        assert!(!is_valid_client_name("has\rcr"));
        assert!(!is_valid_client_name("över-äscii"));
    }

    #[compio::test]
    async fn atomic_write_round_trip_with_mode() {
        let dir = std::env::temp_dir().join(format!("symbolon-aw-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.bin");
        atomic_write(&path, b"hello\n".to_vec(), 0o600)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello\n");
        let metadata = std::fs::metadata(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        // Overwrite.
        atomic_write(&path, b"world\n".to_vec(), 0o640)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"world\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn format_rfc3339_z_is_z_suffixed() {
        let t = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let s = format_rfc3339_z(t);
        assert!(s.ends_with('Z'), "got {s}");
        assert_eq!(s.len(), 20, "expected fixed-width 20, got {s}");
    }

    #[test]
    fn error_response_shape() {
        let e = error_response("bad_request", "nope");
        assert_eq!(e["ok"], serde_json::json!(false));
        assert_eq!(e["code"], "bad_request");
        assert_eq!(e["error"], "nope");
    }
}
