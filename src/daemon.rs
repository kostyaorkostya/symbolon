//! Daemon: bind the Unix-domain listen socket that stunnel forwards
//! into, accept connections, and run the per-connection state machine
//! defined in `docs/PROTOCOLS.md`:
//!
//! PROXY v2 parse → IP→client lookup → git-credential parse →
//! byte-exact host dispatch → provider mint → write response.
//!
//! Per-connection errors do not propagate to the caller: each branch
//! of the state machine emits the corresponding structured JSON log
//! event (`evt=proxy_header_invalid`, `evt=mint_denied`,
//! `evt=provider_error`, `evt=mint`) and closes the connection
//! without writing a response. Per AGENTS.md invariant #7 the source
//! IP from the PROXY v2 header is the daemon's only source of client
//! identity.
//!
//! Lifecycle: `SIGTERM` and `SIGINT` race the accept loop; on either,
//! `shutting_down` flips, in-flight handlers drain with a 5-second
//! deadline (PROTOCOLS.md § "Shutdown"), the admin and listen sockets
//! are unlinked in that order, and `evt=shutdown` is logged. `SIGHUP`
//! re-reads `clients.json` and swaps the in-memory table.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::FutureExt;

use compio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use compio::net::{UnixListener, UnixStream};
use compio::BufResult;
use tracing::{info, warn};

use crate::config::{ClientsFile, Config};
use crate::git_credential::{self, GitCredentialError};
use crate::providers::github::{GitHubProvider, GithubError};
use crate::proxy_protocol::{self, ProxyProtocolError};

const MAX_REQUEST_BYTES: usize = 8 * 1024;
const PER_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const READ_CHUNK_BYTES: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("failed to load clients.json")]
    LoadClients(#[from] crate::config::ConfigError),
    #[error("failed to construct GitHub provider")]
    Github(#[from] GithubError),
    #[error("failed to bind listen socket at {}", path.display())]
    Bind {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to unlink stale socket at {}", path.display())]
    Unlink {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("I/O error during accept")]
    Accept(#[source] std::io::Error),
    #[error("clients.json contains duplicate IP address {0}")]
    DuplicateClientIp(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedClient {
    pub name: String,
    pub providers: HashSet<String>,
    pub enrolled_at: String,
    pub note: Option<String>,
}

/// Shared between the listen-side accept loop and the admin-side
/// accept loop. `clients` is mutable so admin enroll/revoke can
/// update it in place; `providers` is fixed at startup.
pub struct SharedState {
    pub clients: RefCell<HashMap<IpAddr, ResolvedClient>>,
    pub providers: HashMap<String, GitHubProvider>,
    pub psk_file_path: PathBuf,
    pub clients_file_path: PathBuf,
    pub stunnel_pidfile: PathBuf,
    pub start_time: SystemTime,
    pub inflight: Cell<usize>,
    pub shutting_down: Cell<bool>,
}

/// RAII increment of `state.inflight`. Drop decrements. Wrapping a
/// per-connection handler in one lets the shutdown coordinator wait
/// for in-flight handlers to finish (up to a deadline) before
/// unlinking sockets.
pub struct DrainGuard(Rc<SharedState>);

impl DrainGuard {
    pub fn new(state: Rc<SharedState>) -> Self {
        state.inflight.set(state.inflight.get() + 1);
        Self(state)
    }
}

impl Drop for DrainGuard {
    fn drop(&mut self) {
        self.0.inflight.set(self.0.inflight.get().saturating_sub(1));
    }
}

pub async fn run(cfg: &Config, config_path: &Path) -> Result<(), DaemonError> {
    let clients_file = crate::config::load_clients_file(&cfg.clients.file)?;
    let clients_table = build_clients_table(clients_file)?;

    let mut providers: HashMap<String, GitHubProvider> = HashMap::new();
    if let Some(gh) = &cfg.provider.github {
        let provider = GitHubProvider::new(gh)?;
        providers.insert(gh.host.clone(), provider);
    }

    let state = Rc::new(SharedState {
        clients: RefCell::new(clients_table),
        providers,
        psk_file_path: cfg.stunnel.psk_file.clone(),
        clients_file_path: cfg.clients.file.clone(),
        stunnel_pidfile: cfg.stunnel.pidfile.clone(),
        start_time: SystemTime::now(),
        inflight: Cell::new(0),
        shutting_down: Cell::new(false),
    });

    let listen_path = &cfg.listen.socket;
    unlink_stale(listen_path)?;
    let listener = UnixListener::bind(listen_path)
        .await
        .map_err(|source| DaemonError::Bind {
            path: listen_path.clone(),
            source,
        })?;

    let admin_path = &cfg.admin.socket_path;
    unlink_stale(admin_path)?;
    let admin_listener =
        UnixListener::bind(admin_path)
            .await
            .map_err(|source| DaemonError::Bind {
                path: admin_path.clone(),
                source,
            })?;

    let provider_names: Vec<&str> = state.providers.keys().map(String::as_str).collect();
    info!(
        evt = "startup",
        version = env!("CARGO_PKG_VERSION"),
        config_path = %config_path.display(),
        listen_socket = %listen_path.display(),
        admin_socket = %admin_path.display(),
        providers = ?provider_names,
        "daemon started"
    );

    let admin_state = state.clone();
    compio::runtime::spawn(async move {
        if let Err(e) = crate::admin::run_admin_loop(admin_listener, admin_state).await {
            tracing::error!(error = %e, "admin loop exited");
        }
    })
    .detach();

    // Startup selfcheck — soft fail per PROTOCOLS.md step 6.
    for (host, provider) in &state.providers {
        match provider.selfcheck().await {
            Ok(outcome) => {
                info!(
                    evt = "selfcheck",
                    provider = %host,
                    ok = true,
                    clock_skew_sec = outcome.clock_skew_sec,
                );
            }
            Err(e) => {
                warn!(
                    evt = "selfcheck",
                    provider = %host,
                    ok = false,
                    error = %e,
                );
            }
        }
    }

    // SIGHUP — re-read clients.json and swap the in-memory table.
    let hup_state = state.clone();
    let hup_path = cfg.clients.file.clone();
    compio::runtime::spawn(async move {
        let sig = rustix::process::Signal::HUP.as_raw();
        loop {
            if compio::signal::unix::signal(sig).await.is_err() {
                break;
            }
            reload_clients(&hup_state, &hup_path);
        }
    })
    .detach();

    // Main accept loop, racing against SIGTERM / SIGINT.
    let sigterm_fut = compio::signal::unix::signal(rustix::process::Signal::TERM.as_raw());
    let sigint_fut = compio::signal::unix::signal(rustix::process::Signal::INT.as_raw());
    futures_util::pin_mut!(sigterm_fut, sigint_fut);

    let signal_name = loop {
        futures_util::select! {
            accept_res = listener.accept().fuse() => {
                let (stream, _peer) = accept_res.map_err(DaemonError::Accept)?;
                let req_id = ulid::Ulid::new().to_string();
                let state = state.clone();
                compio::runtime::spawn(async move {
                    let _guard = DrainGuard::new(state.clone());
                    let _ = compio::time::timeout(
                        PER_CONNECTION_TIMEOUT,
                        handle_connection(stream, req_id, state),
                    )
                    .await;
                })
                .detach();
            }
            _ = sigterm_fut.as_mut().fuse() => break "SIGTERM",
            _ = sigint_fut.as_mut().fuse() => break "SIGINT",
        }
    };

    // Shutdown drain.
    state.shutting_down.set(true);
    let initial_inflight = state.inflight.get();
    let drain_start = Instant::now();
    let drain_deadline = drain_start + Duration::from_secs(5);
    while state.inflight.get() > 0 && Instant::now() < drain_deadline {
        compio::time::sleep(Duration::from_millis(20)).await;
    }
    let drain_ms = drain_start.elapsed().as_millis() as u64;
    let remaining = state.inflight.get();
    let inflight_drained = initial_inflight.saturating_sub(remaining);

    // PROTOCOLS.md step 3: "Close the admin socket and the listen
    // socket (unlinking them)." — admin first, then listen.
    let _ = std::fs::remove_file(&cfg.admin.socket_path);
    let _ = std::fs::remove_file(&cfg.listen.socket);

    info!(
        evt = "shutdown",
        signal = signal_name,
        inflight_drained = inflight_drained,
        drain_ms = drain_ms,
    );
    Ok(())
}

fn reload_clients(state: &Rc<SharedState>, path: &Path) {
    let file = match crate::config::load_clients_file(path) {
        Ok(f) => f,
        Err(e) => {
            warn!(evt = "config_reload", triggered_by = "sighup", ok = false, error = %e);
            return;
        }
    };
    let new_table = match build_clients_table(file) {
        Ok(t) => t,
        Err(e) => {
            warn!(evt = "config_reload", triggered_by = "sighup", ok = false, error = %e);
            return;
        }
    };
    let count = new_table.len();
    *state.clients.borrow_mut() = new_table;
    info!(
        evt = "config_reload",
        triggered_by = "sighup",
        client_count = count
    );
}

fn unlink_stale(path: &Path) -> Result<(), DaemonError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(DaemonError::Unlink {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn build_clients_table(file: ClientsFile) -> Result<HashMap<IpAddr, ResolvedClient>, DaemonError> {
    let mut table = HashMap::new();
    for entry in file.clients {
        let key = entry.ip;
        let value = ResolvedClient {
            name: entry.name,
            providers: entry.providers.into_iter().collect(),
            enrolled_at: entry.enrolled_at,
            note: entry.note,
        };
        if table.insert(key, value).is_some() {
            return Err(DaemonError::DuplicateClientIp(key));
        }
    }
    Ok(table)
}

async fn handle_connection(mut stream: UnixStream, req_id: String, state: Rc<SharedState>) {
    // ------ Phase 1: PROXY v2 header ------
    let mut buf: Vec<u8> = Vec::with_capacity(MAX_REQUEST_BYTES);
    let parsed = loop {
        match proxy_protocol::parse(&buf) {
            Ok(p) => break p,
            Err(ProxyProtocolError::Incomplete { need_total, .. }) => {
                if need_total > MAX_REQUEST_BYTES {
                    warn!(req_id = %req_id, evt = "proxy_header_invalid", bytes_read = buf.len(), reason = "header_exceeds_cap");
                    return;
                }
                if !read_more(&mut stream, &mut buf).await {
                    warn!(req_id = %req_id, evt = "proxy_header_invalid", bytes_read = buf.len(), reason = "eof_before_header");
                    return;
                }
            }
            Err(e) => {
                warn!(req_id = %req_id, evt = "proxy_header_invalid", bytes_read = buf.len(), error = %e);
                return;
            }
        }
    };

    // ------ Phase 2: IP → client lookup ------
    let client = match state.clients.borrow().get(&parsed.source_ip).cloned() {
        Some(c) => c,
        None => {
            warn!(req_id = %req_id, evt = "mint_denied", reason = "client_unknown", src_ip = %parsed.source_ip);
            return;
        }
    };
    info!(req_id = %req_id, evt = "accept", src_ip = %parsed.source_ip, client = %client.name);

    // ------ Phase 3: git-credential block ------
    let mut block: Vec<u8> = Vec::with_capacity(MAX_REQUEST_BYTES - parsed.header_len);
    block.extend_from_slice(&buf[parsed.header_len..]);
    let request = loop {
        match git_credential::parse(&block) {
            Ok(r) => break r,
            Err(GitCredentialError::UnterminatedBlock) => {
                if block.len() >= MAX_REQUEST_BYTES - parsed.header_len {
                    warn!(req_id = %req_id, evt = "mint_denied", reason = "malformed_request", client = %client.name, detail = "request_exceeds_cap");
                    return;
                }
                if !read_more(&mut stream, &mut block).await {
                    warn!(req_id = %req_id, evt = "mint_denied", reason = "malformed_request", client = %client.name, detail = "eof_before_terminator");
                    return;
                }
            }
            Err(e) => {
                warn!(req_id = %req_id, evt = "mint_denied", reason = "malformed_request", client = %client.name, error = %e);
                return;
            }
        }
    };

    // ------ Phase 4: host dispatch ------
    let provider = match state.providers.get(&request.host) {
        Some(p) => p,
        None => {
            warn!(req_id = %req_id, evt = "mint_denied", reason = "unknown_host", host = %request.host, client = %client.name);
            return;
        }
    };

    // ------ Phase 5: mint ------
    let started = Instant::now();
    let mint_result = provider.mint(&request.path).await;
    let provider_ms = started.elapsed().as_millis() as u64;

    let (response, repo_id) = match mint_result {
        Ok(outcome) => (outcome.response, outcome.repo_id),
        Err(e) => {
            // RepoNotFound at mint-time = the provider just invalidated
            // a (possibly cached) repo-id; surface that to the operator
            // as a distinct event per PROTOCOLS.md.
            if matches!(e, GithubError::RepoNotFound { .. }) {
                info!(
                    req_id = %req_id,
                    evt = "cache_invalidated",
                    provider = %request.host,
                    repo = %request.path,
                    cause = "404",
                );
            }
            log_mint_error(
                &req_id,
                &client.name,
                &request.host,
                &request.path,
                provider_ms,
                e,
            );
            return;
        }
    };

    // ------ Phase 6: emit response ------
    let mut out = Vec::with_capacity(256);
    if let Err(e) = git_credential::write_response(&response, &mut out) {
        warn!(req_id = %req_id, evt = "provider_error", reason = "response_encode", provider = %request.host, error = %e);
        return;
    }
    if let Err(e) = write_all_buf(&mut stream, out).await {
        warn!(req_id = %req_id, evt = "provider_error", reason = "response_write", provider = %request.host, error = %e);
        return;
    }
    let _ = stream.flush().await;

    let expires_at_secs = response
        .password_expiry_utc
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(expires_at_secs);
    let ttl_sec = expires_at_secs.saturating_sub(now_secs);

    info!(
        req_id = %req_id,
        evt = "mint",
        provider = %request.host,
        client = %client.name,
        repo = %request.path,
        repo_id = repo_id,
        ttl_sec = ttl_sec,
        expires_at_unix = expires_at_secs,
        provider_ms = provider_ms,
    );
}

fn log_mint_error(
    req_id: &str,
    client_name: &str,
    host: &str,
    path: &str,
    provider_ms: u64,
    err: GithubError,
) {
    match &err {
        GithubError::RepoNotFound { .. } => {
            warn!(req_id = %req_id, evt = "mint_denied", reason = "repo_not_accessible", provider_status = 404, provider = %host, client = %client_name, repo = %path, provider_ms = provider_ms);
        }
        GithubError::Unauthorized => {
            warn!(req_id = %req_id, evt = "mint_denied", reason = "provider_4xx", provider_status = 401, provider = %host, client = %client_name, repo = %path, provider_ms = provider_ms);
        }
        GithubError::Forbidden => {
            warn!(req_id = %req_id, evt = "mint_denied", reason = "provider_4xx", provider_status = 403, provider = %host, client = %client_name, repo = %path, provider_ms = provider_ms);
        }
        GithubError::RateLimited => {
            warn!(req_id = %req_id, evt = "mint_denied", reason = "provider_4xx", provider_status = 429, provider = %host, client = %client_name, repo = %path, provider_ms = provider_ms);
        }
        GithubError::MalformedPath(_) => {
            warn!(req_id = %req_id, evt = "mint_denied", reason = "malformed_request", provider = %host, client = %client_name, repo = %path, provider_ms = provider_ms);
        }
        GithubError::ServerError(status) => {
            warn!(req_id = %req_id, evt = "provider_error", status = *status, provider = %host, repo = %path, provider_ms = provider_ms);
        }
        GithubError::UnexpectedStatus(status) => {
            warn!(req_id = %req_id, evt = "provider_error", status = *status, provider = %host, repo = %path, provider_ms = provider_ms);
        }
        _ => {
            warn!(req_id = %req_id, evt = "provider_error", provider = %host, repo = %path, provider_ms = provider_ms, error = %err);
        }
    }
}

async fn read_more(stream: &mut UnixStream, accumulated: &mut Vec<u8>) -> bool {
    let chunk = Vec::with_capacity(READ_CHUNK_BYTES);
    let BufResult(res, chunk) = stream.read(chunk).await;
    match res {
        Ok(0) => false,
        Ok(_) => {
            accumulated.extend_from_slice(&chunk);
            true
        }
        Err(_) => false,
    }
}

async fn write_all_buf(stream: &mut UnixStream, buf: Vec<u8>) -> std::io::Result<()> {
    let BufResult(res, _) = stream.write_all(buf).await;
    res.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientEntry;

    fn entry(name: &str, ip: &str, providers: &[&str]) -> ClientEntry {
        ClientEntry {
            name: name.to_string(),
            ip: ip.parse().unwrap(),
            providers: providers.iter().map(|s| s.to_string()).collect(),
            enrolled_at: "2026-05-31T00:00:00Z".to_string(),
            note: None,
        }
    }

    #[test]
    fn build_clients_table_indexes_by_ip() {
        let file = ClientsFile {
            version: 1,
            clients: vec![
                entry("vm-1", "192.168.122.10", &["github"]),
                entry("vm-2", "192.168.122.11", &["github"]),
            ],
        };
        let table = build_clients_table(file).unwrap();
        assert_eq!(table.len(), 2);
        let v1 = table.get(&"192.168.122.10".parse().unwrap()).unwrap();
        assert_eq!(v1.name, "vm-1");
        assert!(v1.providers.contains("github"));
    }

    #[test]
    fn build_clients_table_rejects_duplicate_ip() {
        let file = ClientsFile {
            version: 1,
            clients: vec![
                entry("vm-1", "192.168.122.10", &["github"]),
                entry("vm-1-dup", "192.168.122.10", &["github"]),
            ],
        };
        let err = build_clients_table(file).unwrap_err();
        assert!(matches!(err, DaemonError::DuplicateClientIp(_)));
    }

    #[test]
    fn build_clients_table_empty_is_ok() {
        let file = ClientsFile {
            version: 1,
            clients: vec![],
        };
        assert_eq!(build_clients_table(file).unwrap().len(), 0);
    }

    fn empty_state() -> Rc<SharedState> {
        Rc::new(SharedState {
            clients: RefCell::new(HashMap::new()),
            providers: HashMap::new(),
            psk_file_path: PathBuf::new(),
            clients_file_path: PathBuf::new(),
            stunnel_pidfile: PathBuf::new(),
            start_time: SystemTime::now(),
            inflight: Cell::new(0),
            shutting_down: Cell::new(false),
        })
    }

    #[test]
    fn drain_guard_increments_and_decrements() {
        let state = empty_state();
        assert_eq!(state.inflight.get(), 0);
        let g1 = DrainGuard::new(state.clone());
        assert_eq!(state.inflight.get(), 1);
        let g2 = DrainGuard::new(state.clone());
        assert_eq!(state.inflight.get(), 2);
        drop(g1);
        assert_eq!(state.inflight.get(), 1);
        drop(g2);
        assert_eq!(state.inflight.get(), 0);
    }

    #[test]
    fn reload_clients_swaps_in_place() {
        let state = empty_state();
        // Seed with one entry.
        state.clients.borrow_mut().insert(
            "10.0.0.1".parse().unwrap(),
            ResolvedClient {
                name: "old".to_string(),
                providers: HashSet::new(),
                enrolled_at: "x".to_string(),
                note: None,
            },
        );
        // Write a new clients.json containing a different IP.
        let path = std::env::temp_dir().join(format!("gcb-reload-test-{}.json", ulid::Ulid::new()));
        std::fs::write(
            &path,
            r#"{"version":1,"clients":[{"name":"new","ip":"10.0.0.2","providers":["github"],"enrolled_at":"y","note":null}]}"#,
        )
        .unwrap();
        reload_clients(&state, &path);
        let borrow = state.clients.borrow();
        assert_eq!(borrow.len(), 1);
        assert!(borrow.get(&"10.0.0.2".parse().unwrap()).is_some());
        assert!(borrow.get(&"10.0.0.1".parse().unwrap()).is_none());
        drop(borrow);
        let _ = std::fs::remove_file(&path);
    }
}
