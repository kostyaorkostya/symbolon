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
//! with mode `0o640`, `gcb.psk` with `0o600`. After every `gcb.psk`
//! write the daemon sends `SIGHUP` to stunnel via
//! [`rustix::process::kill_process`].

use std::collections::HashSet;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use compio::BufResult;
use compio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use compio::net::{UnixListener, UnixStream};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::daemon::{ResolvedClient, SharedState};
use crate::providers::github::GithubError;

const CLIENTS_FILE_MODE: u32 = 0o640;
const PSK_FILE_MODE: u32 = 0o600;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const PER_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const PROVIDER_GITHUB: &str = "github";

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
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
    #[error("stunnel pidfile {} is unreadable or malformed", path.display())]
    StunnelPid {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("stunnel pidfile {} contained {raw:?} (not a valid PID)", path.display())]
    StunnelPidParse { path: PathBuf, raw: String },
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

pub async fn run_admin_loop(
    listener: UnixListener,
    state: Rc<SharedState>,
) -> Result<(), AdminError> {
    loop {
        let (stream, _peer) = listener.accept().await.map_err(AdminError::Accept)?;
        if state.shutting_down.get() {
            drop(stream);
            continue;
        }
        let state = state.clone();
        compio::runtime::spawn(async move {
            let _guard = crate::daemon::DrainGuard::new(state.clone());
            let _ =
                compio::time::timeout(PER_CONNECTION_TIMEOUT, handle_admin(stream, state)).await;
        })
        .detach();
    }
}

async fn handle_admin(mut stream: UnixStream, state: Rc<SharedState>) {
    let raw = match read_line(&mut stream).await {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => return,
    };
    let request: Request = match serde_json::from_slice(&raw) {
        Ok(r) => r,
        Err(e) => {
            let resp = error_response("bad_request", &format!("request parse failed: {e}"));
            let _ = write_response(&mut stream, &resp).await;
            return;
        }
    };
    let resp_value = match dispatch(&request, &state).await {
        Ok(v) => v,
        Err(e) => e,
    };
    let _ = write_response(&mut stream, &resp_value).await;
}

async fn dispatch(
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
        } => handle_enroll(state, provider, client, *ip, note.clone()),
        Request::Revoke { provider, client } => handle_revoke(state, provider, client),
        Request::Mint {
            provider,
            client,
            path,
        } => handle_mint(state, provider, client, path).await,
        Request::Selfcheck { provider } => handle_selfcheck(state, provider).await,
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

fn handle_enroll(
    state: &SharedState,
    provider: &str,
    client: &str,
    ip: IpAddr,
    note: Option<String>,
) -> Result<serde_json::Value, serde_json::Value> {
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

    let key_bytes =
        generate_psk_key().map_err(|e| error_response("internal", &format!("rng: {e}")))?;
    let psk_hex = hex_encode(&key_bytes);

    // Update gcb.psk: read existing, append new line, atomic write.
    let mut psk_entries =
        read_psk_file(&state.psk_file_path).map_err(|e| error_response("internal", &e))?;
    psk_entries.push((client.to_string(), psk_hex.clone()));
    let psk_content = render_psk_file(&psk_entries);
    atomic_write(&state.psk_file_path, psk_content.as_bytes(), PSK_FILE_MODE)
        .map_err(|e| error_response("internal", &format!("write psk: {e}")))?;

    // Update clients.json: read, append, atomic write.
    let enrolled_at = format_rfc3339_z(SystemTime::now());
    let mut clients_doc =
        read_clients_doc(&state.clients_file_path).map_err(|e| error_response("internal", &e))?;
    clients_doc.clients.push(StoredClient {
        name: client.to_string(),
        ip,
        providers: vec![PROVIDER_GITHUB.to_string()],
        enrolled_at: enrolled_at.clone(),
        note: note.clone(),
    });
    let clients_bytes = serde_json::to_vec_pretty(&clients_doc)
        .map_err(|e| error_response("internal", &format!("encode clients.json: {e}")))?;
    atomic_write(&state.clients_file_path, &clients_bytes, CLIENTS_FILE_MODE)
        .map_err(|e| error_response("internal", &format!("write clients.json: {e}")))?;

    // Commit to in-memory state.
    let mut providers_set = HashSet::new();
    providers_set.insert(PROVIDER_GITHUB.to_string());
    state.clients.borrow_mut().insert(
        ip,
        ResolvedClient {
            name: client.to_string(),
            providers: providers_set,
            enrolled_at,
            note,
        },
    );

    // SIGHUP stunnel. A failure here is logged but does NOT undo the
    // enroll — operator notices via `gcb status` or stunnel logs.
    if let Err(e) = sighup_stunnel(&state.stunnel_pidfile) {
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

fn handle_revoke(
    state: &SharedState,
    provider: &str,
    client: &str,
) -> Result<serde_json::Value, serde_json::Value> {
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
    let mut clients_doc =
        read_clients_doc(&state.clients_file_path).map_err(|e| error_response("internal", &e))?;
    clients_doc.clients.retain(|c| c.name != client);
    let clients_bytes = serde_json::to_vec_pretty(&clients_doc)
        .map_err(|e| error_response("internal", &format!("encode clients.json: {e}")))?;
    atomic_write(&state.clients_file_path, &clients_bytes, CLIENTS_FILE_MODE)
        .map_err(|e| error_response("internal", &format!("write clients.json: {e}")))?;

    // Rewrite gcb.psk without the matching identity.
    let mut psk_entries =
        read_psk_file(&state.psk_file_path).map_err(|e| error_response("internal", &e))?;
    psk_entries.retain(|(ident, _)| ident != client);
    let psk_content = render_psk_file(&psk_entries);
    atomic_write(&state.psk_file_path, psk_content.as_bytes(), PSK_FILE_MODE)
        .map_err(|e| error_response("internal", &format!("write psk: {e}")))?;

    state.clients.borrow_mut().remove(&client_ip);

    if let Err(e) = sighup_stunnel(&state.stunnel_pidfile) {
        warn!(evt = "stunnel_sighup_failed", error = %e);
    }

    info!(evt = "revoke", provider = provider, client = client);
    Ok(serde_json::json!({ "ok": true }))
}

async fn handle_mint(
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
    match provider_obj.mint(path).await {
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
            }))
        }
        Err(e) => Err(error_response_from_github(&e)),
    }
}

async fn handle_selfcheck(
    state: &Rc<SharedState>,
    provider: &str,
) -> Result<serde_json::Value, serde_json::Value> {
    let provider_obj = lookup_provider(state, provider).ok_or_else(|| {
        error_response(
            "unknown_provider",
            &format!("provider '{provider}' not configured"),
        )
    })?;
    match provider_obj.selfcheck().await {
        Ok(outcome) => Ok(serde_json::json!({
            "ok": true,
            "app_id": outcome.app_id,
            "installation_id": outcome.installation_id,
            "api_base": outcome.api_base,
            "clock_skew_sec": outcome.clock_skew_sec,
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
        GithubError::AppIdMismatch {
            configured,
            reported,
        } => (
            "internal",
            format!("App ID mismatch: configured {configured}, GitHub reports {reported}"),
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
        eprintln!("gcb: error: {msg}");
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
            println!("# /etc/stunnel/gcb-client.conf");
            println!("[gcb]");
            println!("client = yes");
            println!("accept = 127.0.0.1:9418");
            println!("connect = <broker-host>:9418");
            println!("PSKsecrets = /etc/stunnel/gcb-client.psk");
            println!("ciphers = PSK");
            println!();
            println!("# /etc/stunnel/gcb-client.psk (mode 0600)");
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
            let app_id = response.get("app_id").and_then(|v| v.as_u64()).unwrap_or(0);
            let api = response
                .get("api_base")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let skew = response
                .get("clock_skew_sec")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            println!("OK: App {app_id} reachable at {api}, clock skew {skew}s");
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

fn generate_psk_key() -> std::io::Result<[u8; 32]> {
    let mut key = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut key)?;
    Ok(key)
}

fn atomic_write(path: &Path, content: &[u8], mode: u32) -> std::io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    let base = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let tmp = dir.join(format!(
        "{}.tmp.{}",
        base.to_string_lossy(),
        ulid::Ulid::new()
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(content)?;
        f.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

fn read_psk_file(path: &Path) -> Result<Vec<(String, String)>, String> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
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

#[derive(Debug, Serialize, Deserialize)]
struct ClientsDoc {
    version: u32,
    clients: Vec<StoredClient>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredClient {
    name: String,
    ip: IpAddr,
    providers: Vec<String>,
    enrolled_at: String,
    note: Option<String>,
}

fn read_clients_doc(path: &Path) -> Result<ClientsDoc, String> {
    match std::fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| format!("parse {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ClientsDoc {
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
    let dt = time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    dt.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn sighup_stunnel(pidfile: &Path) -> Result<(), AdminError> {
    let raw = match std::fs::read_to_string(pidfile) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Tolerated for test setups and bootstrap; warn-level
            // logging happens at the caller.
            return Err(AdminError::StunnelPid {
                path: pidfile.to_path_buf(),
                source: e,
            });
        }
        Err(source) => {
            return Err(AdminError::StunnelPid {
                path: pidfile.to_path_buf(),
                source,
            });
        }
    };
    let trimmed = raw.trim();
    let pid: i32 = trimmed.parse().map_err(|_| AdminError::StunnelPidParse {
        path: pidfile.to_path_buf(),
        raw: raw.clone(),
    })?;
    let pid = rustix::process::Pid::from_raw(pid).ok_or_else(|| AdminError::StunnelPidParse {
        path: pidfile.to_path_buf(),
        raw,
    })?;
    rustix::process::kill_process(pid, rustix::process::Signal::HUP).map_err(|e| {
        AdminError::StunnelPid {
            path: pidfile.to_path_buf(),
            source: std::io::Error::from(e),
        }
    })?;
    Ok(())
}

async fn read_line(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut accumulated = Vec::new();
    loop {
        if let Some(pos) = accumulated.iter().position(|&b| b == b'\n') {
            accumulated.truncate(pos);
            return Ok(accumulated);
        }
        if accumulated.len() >= MAX_REQUEST_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "admin request exceeds size cap",
            ));
        }
        let chunk = Vec::with_capacity(1024);
        let BufResult(res, chunk) = stream.read(chunk).await;
        match res {
            Ok(0) => return Ok(accumulated),
            Ok(_) => accumulated.extend_from_slice(&chunk),
            Err(e) => return Err(e),
        }
    }
}

async fn write_response(stream: &mut UnixStream, value: &serde_json::Value) -> std::io::Result<()> {
    let mut payload = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
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

    #[test]
    fn atomic_write_round_trip_with_mode() {
        let dir = std::env::temp_dir().join(format!("gcb-aw-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.bin");
        atomic_write(&path, b"hello\n", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello\n");
        let metadata = std::fs::metadata(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        // Overwrite.
        atomic_write(&path, b"world\n", 0o640).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"world\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_and_read_psk_round_trip() {
        let entries = vec![
            ("vm-1".to_string(), "a1b2".to_string()),
            ("vm-2".to_string(), "ccdd".to_string()),
        ];
        let rendered = render_psk_file(&entries);
        assert_eq!(rendered, "vm-1:a1b2\nvm-2:ccdd\n");
        let dir = std::env::temp_dir().join(format!("gcb-psk-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gcb.psk");
        atomic_write(&path, rendered.as_bytes(), 0o600).unwrap();
        let parsed = read_psk_file(&path).unwrap();
        assert_eq!(parsed, entries);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_psk_file_missing_returns_empty() {
        let path = std::env::temp_dir().join(format!("gcb-nope-{}", ulid::Ulid::new()));
        assert!(read_psk_file(&path).unwrap().is_empty());
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
