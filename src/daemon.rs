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
//! Lifecycle: three long-lived tasks are spawned by `run`:
//! the admin loop, the SIGHUP handler, and a SIGTERM/SIGINT watcher.
//! Their `JoinHandle`s are kept in locals and `await`ed in `run`
//! before it returns — structured concurrency, per the user's
//! "all futures must return or have a timeout" rule. The watcher
//! triggers `state.shutdown` (a compio `CancelToken`) on either
//! signal; the admin loop and SIGHUP loop also race their work
//! against `shutdown.wait()` and exit cleanly on cancellation. The
//! per-connection handler tasks are the one exception: they keep
//! `spawn(...).detach()` and are tracked via `DrainGuard` /
//! `inflight: Cell<usize>` — bounded by `PER_CONNECTION_TIMEOUT`
//! (5 s) and a 5 s drain deadline before sockets unlink. The
//! `evt=shutdown` event is then logged. `SIGHUP` re-reads
//! `clients.json` and swaps the in-memory table.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::FutureExt;
use futures_util::stream::{FuturesUnordered, StreamExt};

use compio::BufResult;
use compio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use compio::net::{UnixListener, UnixStream};
use compio::runtime::CancelToken;
use tracing::{info, warn};

use crate::config::{ClientsFile, Config, SandboxMode};
use crate::git_credential::{self, GitCredentialError};
use crate::providers::github::{GitHubProvider, GithubError};
use crate::proxy_protocol::{self, ProxyProtocolError};
use crate::sandbox::{self, SandboxError, SandboxLevel, SandboxPaths};

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
    #[error("config path {0} has no parent directory; sandbox cannot grant write access")]
    NoParentDir(&'static str),
    #[error("failed to apply sandbox")]
    Sandbox(#[from] SandboxError),
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
    pub listen_socket_path: PathBuf,
    pub admin_socket_path: PathBuf,
    pub start_time: SystemTime,
    /// Cancelled by `crate::signals` watchers on SIGTERM/SIGINT. The
    /// main accept loop and the admin loop both race `wait()` on it;
    /// the SIGHUP loop does too. Loops exit cleanly on cancel,
    /// letting their `JoinHandle`s be joined.
    pub shutdown: CancelToken,
}

/// Statistics returned from `Service::run` so main can log the
/// final `evt=shutdown` event.
pub struct RunStats {
    pub drain_ms: u64,
    pub inflight_drained: usize,
}

/// The running daemon: business logic only. Knows nothing about
/// signals, sd_notify, or pidfiles — main wires those.
pub struct Service {
    state: Rc<SharedState>,
}

impl Service {
    /// Bootstrap: load clients.json, build providers (reads PEM),
    /// bind both Unix sockets, apply the sandbox. Returns the
    /// service plus the two bound listeners; main owns and passes
    /// them back into `run`.
    pub async fn bootstrap(
        cfg: &Config,
        config_path: &Path,
        shutdown: CancelToken,
    ) -> Result<(Self, UnixListener, UnixListener), DaemonError> {
        let clients_file = crate::loader::load_clients_file(&cfg.clients.file).await?;
        let clients_table = build_clients_table(clients_file)?;

        let mut providers: HashMap<String, GitHubProvider> = HashMap::new();
        if let Some(gh) = &cfg.provider.github {
            let provider = GitHubProvider::new(gh).await?;
            providers.insert(gh.host.clone(), provider);
        }

        let state = Rc::new(SharedState {
            clients: RefCell::new(clients_table),
            providers,
            psk_file_path: cfg.stunnel.psk_file.clone(),
            clients_file_path: cfg.clients.file.clone(),
            stunnel_pidfile: cfg.stunnel.pidfile.clone(),
            listen_socket_path: cfg.listen.socket.clone(),
            admin_socket_path: cfg.admin.socket_path.clone(),
            start_time: SystemTime::now(),
            shutdown,
        });

        let listen_path = &cfg.listen.socket;
        unlink_stale(listen_path).await?;
        let listener =
            UnixListener::bind(listen_path)
                .await
                .map_err(|source| DaemonError::Bind {
                    path: listen_path.clone(),
                    source,
                })?;

        let admin_path = &cfg.admin.socket_path;
        unlink_stale(admin_path).await?;
        let admin_listener =
            UnixListener::bind(admin_path)
                .await
                .map_err(|source| DaemonError::Bind {
                    path: admin_path.clone(),
                    source,
                })?;

        apply_sandbox(cfg)?;

        info!(
            evt = "bootstrap",
            version = env!("CARGO_PKG_VERSION"),
            config_path = %config_path.display(),
            listen_socket = %listen_path.display(),
            admin_socket = %admin_path.display(),
        );

        Ok((Self { state }, listener, admin_listener))
    }

    /// Clone the SharedState handle for use by external tasks
    /// (e.g. the SIGHUP handler in `crate::signals`).
    pub fn state_handle(&self) -> Rc<SharedState> {
        self.state.clone()
    }

    /// The cancel token shared across daemon loops. Main triggers
    /// it via signals.
    pub fn shutdown_token(&self) -> CancelToken {
        self.state.shutdown.clone()
    }

    /// Per-provider startup selfcheck. Logs `evt=selfcheck` once per
    /// provider and never returns Err (soft-fail per PROTOCOLS.md).
    pub async fn selfcheck(&self) {
        for (host, provider) in &self.state.providers {
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
    }

    /// Run the accept loops until `shutdown` is cancelled, drain
    /// per-connection handlers, unlink sockets. Returns RunStats.
    pub async fn run(
        self,
        listener: UnixListener,
        admin_listener: UnixListener,
    ) -> Result<RunStats, DaemonError> {
        let state = self.state;
        let provider_names: Vec<&str> = state.providers.keys().map(String::as_str).collect();
        info!(evt = "startup", providers = ?provider_names, "daemon started");

        // Admin loop: held as a JoinHandle and awaited after the
        // accept loop exits. The admin loop itself selects on
        // `state.shutdown.wait()` so it terminates cleanly.
        let admin_state = state.clone();
        let admin_handle = compio::runtime::spawn(async move {
            if let Err(e) = crate::admin::run_admin_loop(admin_listener, admin_state).await {
                tracing::error!(error = %e, "admin loop exited");
            }
        });

        // Main accept loop, racing accept against the shutdown token.
        // Per-connection JoinHandles live in a FuturesUnordered;
        // select_next_some prunes completed ones in-loop so memory
        // stays bounded. Shape matches Apache iggy's tcp_listener.rs.
        let mut handlers: FuturesUnordered<compio::runtime::JoinHandle<()>> =
            FuturesUnordered::new();
        loop {
            futures_util::select! {
                accept_res = listener.accept().fuse() => {
                    let (stream, _peer) = accept_res.map_err(DaemonError::Accept)?;
                    // Race: shutdown.cancel() fired while accept was
                    // already polled-ready in this same select!
                    // iteration. Drop the stream rather than start
                    // a handler we won't drain — the next loop
                    // iteration's select! will pick the
                    // shutdown.wait() arm and break. Net effect:
                    // zero streams accepted after cancel; in-flight
                    // handlers drain on their own timers.
                    if state.shutdown.is_cancelled() {
                        drop(stream);
                        continue;
                    }
                    let req_id = ulid::Ulid::new().to_string();
                    let state = state.clone();
                    handlers.push(compio::runtime::spawn(async move {
                        let _ = compio::time::timeout(
                            PER_CONNECTION_TIMEOUT,
                            handle_connection(stream, req_id, state),
                        )
                        .await;
                    }));
                }
                // Prune completed handlers in-loop. select_next_some
                // yields Pending when the stream is empty, so this
                // arm doesn't fire-spin.
                _ = handlers.select_next_some() => {}
                _ = state.shutdown.clone().wait().fuse() => break,
            }
        }

        // Drain in-flight per-connection handlers with a deadline.
        // On timeout, dropping `handlers` cancels the still-in-flight
        // tasks via compio's JoinHandle drop=cancel semantics.
        let drain_start = Instant::now();
        let mut drained = 0usize;
        let _ = compio::time::timeout(Duration::from_secs(5), async {
            while handlers.next().await.is_some() {
                drained += 1;
            }
        })
        .await;
        let drain_ms = drain_start.elapsed().as_millis() as u64;
        let inflight_drained = drained;
        // `handlers` dropped at end of scope; remaining tasks cancelled.

        // Join admin loop. By this point shutdown is cancelled so
        // its inner select! will break.
        let _ = admin_handle.await;

        // PROTOCOLS.md step 3: "Close the admin socket and the listen
        // socket (unlinking them)." — admin first, then listen.
        let _ = compio::fs::remove_file(&state.admin_socket_path).await;
        let _ = compio::fs::remove_file(&state.listen_socket_path).await;

        Ok(RunStats {
            drain_ms,
            inflight_drained,
        })
    }
}

/// Convenience wrapper: bootstrap the service with a fresh
/// `CancelToken`, then run until the token fires. The daemon itself
/// does NOT install signal handlers — production code (main) wires
/// signals into the token via `crate::signals`. This wrapper is for
/// tests and other callers that want to drive the lifecycle by
/// dropping the spawned task.
pub async fn run(cfg: &Config, config_path: &Path) -> Result<RunStats, DaemonError> {
    let shutdown = CancelToken::new();
    let (service, listener, admin_listener) =
        Service::bootstrap(cfg, config_path, shutdown).await?;
    service.run(listener, admin_listener).await
}

/// Reload `clients.json` and atomically swap the in-memory table.
/// Public so `crate::signals` can call it on SIGHUP.
pub async fn reload_clients(state: &Rc<SharedState>, path: &Path) {
    let file = match crate::loader::load_clients_file(path).await {
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

fn apply_sandbox(cfg: &Config) -> Result<(), DaemonError> {
    let level = match cfg.security.sandbox {
        SandboxMode::Required => SandboxLevel::Required,
        SandboxMode::BestEffort => SandboxLevel::BestEffort,
        SandboxMode::Off => SandboxLevel::Off,
    };
    let mut read_dirs = vec![PathBuf::from("/etc/ssl/certs")];
    read_dirs.extend(cfg.security.extra_read_dirs.iter().cloned());
    let paths = SandboxPaths {
        read_files: vec![
            cfg.clients.file.clone(),
            cfg.stunnel.pidfile.clone(),
            PathBuf::from("/dev/urandom"),
        ],
        read_dirs,
        // Files consulted by libc `getaddrinfo` for our single
        // outbound HTTPS hostname (`api.github.com`). We resolve via
        // the system resolver (cyper default) — hickory is deferred
        // due to its tokio coupling, see AGENTS.md.
        resolv_files: [
            // glibc + musl: DNS nameserver list and search domains.
            "/etc/resolv.conf",
            // glibc + musl: static hostname→IP overrides; consulted
            // before DNS depending on nsswitch order.
            "/etc/hosts",
            // glibc: NSS module order (files vs dns vs mdns). musl
            // ignores this file; safe to keep on the allowlist for
            // glibc builds.
            "/etc/nsswitch.conf",
            // glibc: RFC 3484 address-sort preferences for the
            // results getaddrinfo returns. musl ignores it.
            "/etc/gai.conf",
            // /etc/host.conf and /etc/services intentionally NOT
            // included: host.conf is legacy and ignored by modern
            // libcs; /etc/services is for getservbyname (port-by-
            // name) which we don't use — we pass numeric port 443.
        ]
        .iter()
        .map(PathBuf::from)
        .collect(),
        write_parent_dirs: {
            let mut v = vec![
                cfg.clients
                    .file
                    .parent()
                    .ok_or(DaemonError::NoParentDir("clients.file"))?
                    .to_path_buf(),
                cfg.stunnel
                    .psk_file
                    .parent()
                    .ok_or(DaemonError::NoParentDir("stunnel.psk_file"))?
                    .to_path_buf(),
            ];
            // ready::notify writes the pidfile post-sandbox; its
            // parent dir must be in the write-allowlist.
            if let Some(pidfile) = cfg.runtime.pidfile.as_ref() {
                v.push(
                    pidfile
                        .parent()
                        .ok_or(DaemonError::NoParentDir("runtime.pidfile"))?
                        .to_path_buf(),
                );
            }
            v
        },
    };
    let outcome = sandbox::apply(level, &paths)?;
    let degraded = !matches!(outcome.status, "fully_enforced" | "off");
    if degraded {
        warn!(
            evt = "sandbox_applied",
            policy = ?cfg.security.sandbox,
            abi = outcome.requested_abi,
            status = outcome.status,
            fs = outcome.fs,
            tcp = outcome.tcp,
            scope = outcome.scope,
            seccomp = outcome.seccomp,
        );
    } else {
        info!(
            evt = "sandbox_applied",
            policy = ?cfg.security.sandbox,
            abi = outcome.requested_abi,
            status = outcome.status,
            fs = outcome.fs,
            tcp = outcome.tcp,
            scope = outcome.scope,
            seccomp = outcome.seccomp,
        );
    }
    Ok(())
}

async fn unlink_stale(path: &Path) -> Result<(), DaemonError> {
    match compio::fs::remove_file(path).await {
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
    let Some(client) = state.clients.borrow().get(&parsed.source_ip).cloned() else {
        warn!(req_id = %req_id, evt = "mint_denied", reason = "client_unknown", src_ip = %parsed.source_ip);
        return;
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
    let Some(provider) = state.providers.get(&request.host) else {
        warn!(req_id = %req_id, evt = "mint_denied", reason = "unknown_host", host = %request.host, client = %client.name);
        return;
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

// Per-iteration `Vec` allocation. For our traffic (<<1 mint/s) the
// alloc cost is invisible relative to network RTT. If profiling
// ever shows otherwise, iggy reuses a single
// `BytesMut::with_capacity(...)` via `.clear()` across iterations
// (see iggy/core/server/src/tcp/connection_handler.rs); compio's
// `BufferPool` + `AsyncReadManaged` is the io_uring-native answer.
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
            listen_socket_path: PathBuf::new(),
            admin_socket_path: PathBuf::new(),
            start_time: SystemTime::now(),
            shutdown: CancelToken::new(),
        })
    }

    // empty_state() builds a SharedState that contains a
    // CancelToken; CancelToken::new() panics outside a compio
    // runtime context. Tests that touch SharedState therefore run
    // under #[compio::test] even when their bodies do no I/O.

    #[compio::test]
    async fn reload_clients_swaps_in_place() {
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
        reload_clients(&state, &path).await;
        let borrow = state.clients.borrow();
        assert_eq!(borrow.len(), 1);
        assert!(borrow.get(&"10.0.0.2".parse().unwrap()).is_some());
        assert!(borrow.get(&"10.0.0.1".parse().unwrap()).is_none());
        drop(borrow);
        let _ = std::fs::remove_file(&path);
    }
}
