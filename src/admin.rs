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
//! with mode `0o640`, `symbolon.psk` with `0o600`. After every `symbolon.psk`
//! write the daemon sends `SIGHUP` to stunnel via
//! [`rustix::process::kill_process`].

use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use compio::BufResult;
use compio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use compio::net::{UnixListener, UnixStream};
use futures_util::FutureExt;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::daemon::{ResolvedClient, SharedState};
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
        ip: IpAddr,
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
        ip: IpAddr,
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
            CliCommand::GithubEnroll { client, ip, note } => Request::Enroll {
                provider: PROVIDER_GITHUB.to_string(),
                client: client.clone(),
                ip: *ip,
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
            info!(evt = "admin_request", req_id = %req_id, ok = false, error = %e);
            let resp = error_response("bad_request", &format!("request parse failed: {e}"));
            let _ = write_response(&mut stream, &resp).await;
            return;
        }
    };
    info!(evt = "admin_request", req_id = %req_id, op = %request.op_name());
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
            ip,
            note,
        } => handle_enroll(req_id, state, provider, client, *ip, note.clone()).await,
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
    let mut entries: Vec<serde_json::Value> = state
        .clients
        .borrow()
        .iter()
        .map(|(ip, c)| {
            let mut provs: Vec<&str> = c.providers.iter().map(String::as_str).collect();
            provs.sort();
            serde_json::json!({
                "name": c.name,
                "ip": ip.to_string(),
                "providers": provs,
                "enrolled_at": c.enrolled_at,
                "note": c.note,
            })
        })
        .collect();
    entries.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    serde_json::json!({ "ok": true, "clients": entries })
}

async fn handle_enroll(
    req_id: &str,
    state: &SharedState,
    provider: &str,
    client: &str,
    ip: IpAddr,
    note: Option<String>,
) -> Result<serde_json::Value, serde_json::Value> {
    let _ = req_id; // logged at handle_admin entry; not threaded further today
    // Collapse IPv4-mapped IPv6 (::ffff:a.b.c.d) → IPv4 so an
    // operator enrolling the dual-stack form for an IPv4 host hits
    // the same bucket the daemon's accept-loop canonicalizes into.
    // Mirrors daemon::canonicalize_ip on the accept path.
    let ip = crate::daemon::canonicalize_ip(ip);
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

    // Snapshot existing entries for collision checks. Drop the borrow
    // before any await/file I/O — we'll re-acquire borrow_mut at the
    // commit step.
    let existing: Vec<(IpAddr, String)> = state
        .clients
        .borrow()
        .iter()
        .map(|(ip, c)| (*ip, c.name.clone()))
        .collect();
    if existing.iter().any(|(_, n)| n == client) {
        return Err(error_response(
            "client_already_enrolled",
            &format!("client '{client}' already enrolled"),
        ));
    }
    if existing.iter().any(|(existing_ip, _)| existing_ip == &ip) {
        return Err(error_response(
            "client_ip_collision",
            &format!("ip {ip} already maps to another client"),
        ));
    }

    let key_bytes = generate_psk_key()
        .await
        .map_err(|e| error_response("internal", &format!("rng: {e}")))?;
    let psk_hex = hex_encode(&key_bytes);

    // Update symbolon.psk: read existing, append new line, atomic write.
    let mut psk_entries = read_psk_file(&state.psk_file_path)
        .await
        .map_err(|e| error_response("internal", &e))?;
    psk_entries.push((client.to_string(), psk_hex.clone()));
    let psk_content = render_psk_file(&psk_entries);
    atomic_write(
        &state.psk_file_path,
        psk_content.into_bytes(),
        PSK_FILE_MODE,
    )
    .await
    .map_err(|e| error_response("internal", &format!("write psk: {e}")))?;

    // Update clients.json: read, append, atomic write.
    let enrolled_at = format_rfc3339_z(SystemTime::now());
    let mut clients_doc = read_clients_doc(&state.clients_file_path)
        .await
        .map_err(|e| error_response("internal", &e))?;
    clients_doc.clients.push(crate::config::ClientEntry {
        name: client.to_string(),
        ip,
        providers: vec![PROVIDER_GITHUB.to_string()],
        enrolled_at: enrolled_at.clone(),
        note: note.clone(),
    });
    let clients_bytes = serde_json::to_vec_pretty(&clients_doc)
        .map_err(|e| error_response("internal", &format!("encode clients.json: {e}")))?;
    atomic_write(&state.clients_file_path, clients_bytes, CLIENTS_FILE_MODE)
        .await
        .map_err(|e| error_response("internal", &format!("write clients.json: {e}")))?;

    // Commit to in-memory state.
    state.clients.borrow_mut().insert(
        ip,
        ResolvedClient {
            name: client.to_string(),
            providers: vec![PROVIDER_GITHUB.to_string()],
            enrolled_at,
            note,
        },
    );

    // SIGHUP stunnel. A failure here is logged but does NOT undo the
    // enroll — operator notices via `symbolon status` or stunnel logs.
    if let Err(e) = state.stunnel.sighup().await {
        warn!(evt = "stunnel_sighup_failed", error = %e);
    }

    info!(evt = "enroll", provider = provider, client = client, ip = %ip);
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

    // Find the client's IP for in-memory removal.
    let client_ip = {
        let borrow = state.clients.borrow();
        borrow
            .iter()
            .find(|(_, c)| c.name == client)
            .map(|(ip, _)| *ip)
    };
    let Some(client_ip) = client_ip else {
        return Err(error_response(
            "unknown_client",
            &format!("no enrolled client named '{client}'"),
        ));
    };

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

    // Rewrite symbolon.psk without the matching identity.
    let mut psk_entries = read_psk_file(&state.psk_file_path)
        .await
        .map_err(|e| error_response("internal", &e))?;
    psk_entries.retain(|(ident, _)| ident != client);
    let psk_content = render_psk_file(&psk_entries);
    atomic_write(
        &state.psk_file_path,
        psk_content.into_bytes(),
        PSK_FILE_MODE,
    )
    .await
    .map_err(|e| error_response("internal", &format!("write psk: {e}")))?;

    state.clients.borrow_mut().remove(&client_ip);

    if let Err(e) = state.stunnel.sighup().await {
        warn!(evt = "stunnel_sighup_failed", error = %e);
    }

    info!(evt = "revoke", provider = provider, client = client);
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
    let known_client = state.clients.borrow().values().any(|c| c.name == client);
    if !known_client {
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
        GithubError::Unauthorized => ("provider_4xx", "App key invalid (401)".to_string()),
        GithubError::Forbidden => ("provider_4xx", "App lacks permission (403)".to_string()),
        GithubError::RateLimited => ("provider_4xx", "rate limited (429)".to_string()),
        GithubError::MalformedPath(p) => ("bad_request", format!("malformed owner/repo path: {p}")),
        GithubError::ServerError(s) => ("internal", format!("provider 5xx: {s}")),
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
                let ip = c.get("ip").and_then(|v| v.as_str()).unwrap_or("?");
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
                println!("{name}\t{ip}\t{provs}\t{enrolled}");
            }
        }
        CliCommand::GithubEnroll { client, ip, .. } => {
            let psk_hex = response
                .get("psk_hex")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            println!("Enrolled '{client}' for github.com at {ip}.");
            println!();
            println!("# Paste-ready snippet for the client VM:");
            println!("#");
            println!("# /etc/stunnel/symbolon-client.conf");
            println!("[symbolon]");
            println!("client = yes");
            println!("accept = 127.0.0.1:9418");
            println!("connect = <broker-host>:9418");
            println!("PSKsecrets = /etc/stunnel/symbolon-client.psk");
            println!("ciphers = PSK");
            println!();
            println!("# /etc/stunnel/symbolon-client.psk (mode 0600)");
            println!("{client}:{psk_hex}");
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
    !s.is_empty()
        && s.is_ascii()
        && !s
            .chars()
            .any(|c| c == ':' || c == '\n' || c == '\r' || c.is_whitespace())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").expect("write to String never fails");
    }
    s
}

async fn generate_psk_key() -> std::io::Result<[u8; 32]> {
    use compio::io::AsyncReadAtExt;
    let file = compio::fs::File::open("/dev/urandom").await?;
    let buf = vec![0u8; 32];
    let BufResult(res, buf) = file.read_exact_at(buf, 0).await;
    res?;
    let arr: [u8; 32] = buf
        .try_into()
        .map_err(|_| std::io::Error::other("short read from /dev/urandom"))?;
    Ok(arr)
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

async fn read_psk_file(path: &Path) -> Result<Vec<(String, String)>, String> {
    match compio::fs::read(path).await {
        Ok(bytes) => {
            let s = std::str::from_utf8(&bytes)
                .map_err(|e| format!("psk file {} not utf-8: {e}", path.display()))?;
            let mut out = Vec::new();
            for line in s.lines() {
                if line.is_empty() {
                    continue;
                }
                if let Some((ident, key)) = line.split_once(':') {
                    out.push((ident.to_string(), key.to_string()));
                }
            }
            Ok(out)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

fn render_psk_file(entries: &[(String, String)]) -> String {
    let mut s = String::new();
    for (ident, key) in entries {
        s.push_str(ident);
        s.push(':');
        s.push_str(key);
        s.push('\n');
    }
    s
}

async fn read_clients_doc(path: &Path) -> Result<crate::config::ClientsFile, String> {
    match compio::fs::read(path).await {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(crate::config::ClientsFile {
            version: 1,
            clients: Vec::new(),
        }),
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

fn format_rfc3339_z(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // from_unix_timestamp accepts any i64 within ±9999 years; secs
    // (u64) saturates to i64 just past the year-292B mark, so the
    // cast is fine here. RFC3339 formatting of a valid OffsetDateTime
    // is infallible. Both unwraps would only fire on internal bugs.
    let dt = time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .expect("u64 seconds within i64::MAX");
    dt.format(&time::format_description::well_known::Rfc3339)
        .expect("RFC3339 format is infallible for OffsetDateTime")
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
                    evt = "admin_denied",
                    peer_uid = uid,
                    peer_pid = cred.pid.as_raw_nonzero().get(),
                );
                false
            }
        }
        Err(e) => {
            tracing::warn!(
                evt = "admin_peercred_failed",
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
// the reuse pattern if it ever matters. See daemon.rs::read_more
// for the symmetric comment.
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
            Ok(0) => return Ok(accumulated),
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
    fn hex_encode_known_vector() {
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0x0F, 0xF0]), "000ff0");
    }

    #[test]
    fn request_round_trips() {
        let r = Request::Enroll {
            provider: "github".to_string(),
            client: "vm-1".to_string(),
            ip: "192.168.122.10".parse().unwrap(),
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

    #[compio::test]
    async fn render_and_read_psk_round_trip() {
        let entries = vec![
            ("vm-1".to_string(), "a1b2".to_string()),
            ("vm-2".to_string(), "ccdd".to_string()),
        ];
        let rendered = render_psk_file(&entries);
        assert_eq!(rendered, "vm-1:a1b2\nvm-2:ccdd\n");
        let dir = std::env::temp_dir().join(format!("symbolon-psk-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("symbolon.psk");
        atomic_write(&path, rendered.into_bytes(), 0o600)
            .await
            .unwrap();
        let parsed = read_psk_file(&path).await.unwrap();
        assert_eq!(parsed, entries);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[compio::test]
    async fn read_psk_file_missing_returns_empty() {
        let path = std::env::temp_dir().join(format!("symbolon-nope-{}", ulid::Ulid::new()));
        assert!(read_psk_file(&path).await.unwrap().is_empty());
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
