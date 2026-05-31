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
//! Signal handling, the startup `selfcheck`, the `evt=shutdown`
//! drain, and `clients.json` hot reload are deferred to the
//! follow-up session that also wires `admin.rs`.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
struct ResolvedClient {
    name: String,
    #[allow(dead_code)] // reserved for per-provider allowlist; see invariant #3
    providers: HashSet<String>,
}

pub async fn run(cfg: &Config) -> Result<(), DaemonError> {
    let clients_file = crate::config::load_clients_file(&cfg.clients.file)?;
    let clients = Rc::new(build_clients_table(clients_file)?);

    let mut providers: HashMap<String, GitHubProvider> = HashMap::new();
    if let Some(gh) = &cfg.provider.github {
        let provider = GitHubProvider::new(gh)?;
        providers.insert(gh.host.clone(), provider);
    }
    let providers = Rc::new(providers);

    let socket_path = &cfg.listen.socket;
    match std::fs::remove_file(socket_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(DaemonError::Unlink {
                path: socket_path.clone(),
                source,
            });
        }
    }
    let listener = UnixListener::bind(socket_path)
        .await
        .map_err(|source| DaemonError::Bind {
            path: socket_path.clone(),
            source,
        })?;

    let provider_names: Vec<&str> = providers.keys().map(String::as_str).collect();
    info!(
        evt = "startup",
        version = env!("CARGO_PKG_VERSION"),
        listen_socket = %socket_path.display(),
        providers = ?provider_names,
        "daemon started"
    );

    loop {
        let (stream, _peer) = listener.accept().await.map_err(DaemonError::Accept)?;
        let req_id = ulid::Ulid::new().to_string();
        let providers = providers.clone();
        let clients = clients.clone();
        compio::runtime::spawn(async move {
            let _ = compio::time::timeout(
                PER_CONNECTION_TIMEOUT,
                handle_connection(stream, req_id, providers, clients),
            )
            .await;
        })
        .detach();
    }
}

fn build_clients_table(file: ClientsFile) -> Result<HashMap<IpAddr, ResolvedClient>, DaemonError> {
    let mut table = HashMap::new();
    for entry in file.clients {
        let key = entry.ip;
        let value = ResolvedClient {
            name: entry.name,
            providers: entry.providers.into_iter().collect(),
        };
        if table.insert(key, value).is_some() {
            return Err(DaemonError::DuplicateClientIp(key));
        }
    }
    Ok(table)
}

async fn handle_connection(
    mut stream: UnixStream,
    req_id: String,
    providers: Rc<HashMap<String, GitHubProvider>>,
    clients: Rc<HashMap<IpAddr, ResolvedClient>>,
) {
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
    let client = match clients.get(&parsed.source_ip) {
        Some(c) => c.clone(),
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
    let provider = match providers.get(&request.host) {
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

    let response = match mint_result {
        Ok(r) => r,
        Err(e) => {
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
}
