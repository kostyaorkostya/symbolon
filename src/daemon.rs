//! Daemon: bind the TCP listen socket the client connects to, accept
//! connections, and run the per-connection state machine defined in
//! `docs/PROTOCOLS.md`:
//!
//! Identity prelude → PSK lookup → Noise NNpsk0 handshake →
//! git-credential parse → byte-exact host dispatch → provider mint →
//! write response (encrypted via the Noise transport).
//!
//! Per-connection errors do not propagate to the caller: each branch
//! of the state machine emits the corresponding structured JSON log
//! event (`evt=prelude_invalid`, `evt=handshake_failed`,
//! `evt=mint_denied`, `evt=provider_error`, `evt=mint`) and closes
//! the connection without writing a response. Per AGENTS.md invariant
//! #7 the PSK identity from the Noise handshake is the daemon's sole
//! source of client identity.
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
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::FutureExt;

use compio::BufResult;
use compio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use compio::net::{TcpListener, TcpStream, UnixListener};
use compio::runtime::CancelToken;
use snow::{HandshakeState, TransportState};
use tracing::{info, warn};

use crate::config::{ClientsFile, Config};
use crate::connection_tracker::ConnectionTracker;
use crate::cpu_worker::CpuWorker;
use crate::events::EventKind;
use crate::git_credential;
use crate::providers::github::{GitHubProvider, GithubError};
use crate::psk_store::{PskStore, PskStoreError};
use crate::sandbox::{self, SandboxError, SandboxPaths};
use crate::transport::{self, PreludeError, TransportError};

/// Per-connection read budget enforced at the daemon's read loop.
/// Tighter than `git_credential::PARSER_HARD_MAX` (which is the
/// parser's absolute ceiling for direct callers) — at 8 KiB it caps
/// slow-loris connections well below the parser limit.
const WIRE_READ_BUDGET: usize = 8 * 1024;

const _WIRE_BUDGET_FITS_PARSER: () = assert!(WIRE_READ_BUDGET <= git_credential::PARSER_HARD_MAX);
const PER_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("failed to load clients.json")]
    LoadClients(#[from] crate::config::ConfigError),
    #[error("failed to load PSK file")]
    LoadPsks(#[from] PskStoreError),
    #[error("failed to construct GitHub provider")]
    Github(#[from] GithubError),
    #[error("failed to read PSK file at {}", path.display())]
    PskRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to bind listen socket")]
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
    #[error("clients.json contains duplicate identity {0:?}")]
    DuplicateClientName(String),
    #[error("config path {0} has no parent directory; sandbox cannot grant write access")]
    NoParentDir(&'static str),
    #[error("failed to apply sandbox")]
    Sandbox(#[from] SandboxError),
    #[error("failed to spawn CPU worker thread")]
    CpuWorker(#[source] std::io::Error),
    #[error("daemon prepare cancelled by shutdown signal")]
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedClient {
    pub(crate) name: String,
    pub(crate) providers: Vec<String>,
    pub(crate) enrolled_at: String,
    pub(crate) note: Option<String>,
}

/// Shared between the listen-side accept loop and the admin-side
/// accept loop. `clients` is mutable so admin enroll/revoke can
/// update it in place; `providers` is fixed at startup. Field
/// visibility is `pub(crate)` so external callers see only an
/// opaque `Rc<SharedState>` — they can hold and pass it around but
/// not peek at internals.
pub struct SharedState {
    /// Identity → metadata. Mutated by admin enroll/revoke. Lookup keyed
    /// on the PSK identity surfaced by the Noise prelude.
    pub(crate) clients: RefCell<HashMap<String, ResolvedClient>>,
    /// Identity → 32-byte PSK. Same identities as `clients` (the
    /// `enroll`/`revoke` admin paths keep them in lock-step). Daemon
    /// reads this on every accepted connection to seed the Noise
    /// responder.
    pub(crate) psks: RefCell<PskStore>,
    pub(crate) providers: HashMap<String, GitHubProvider>,
    pub(crate) psk_file_path: PathBuf,
    pub(crate) clients_file_path: PathBuf,
    pub(crate) admin_socket_path: PathBuf,
    pub(crate) start_time: SystemTime,
    /// Cancelled by `crate::signals` watchers on SIGTERM/SIGINT. The
    /// main accept loop and the admin loop both race `wait()` on it;
    /// the SIGHUP loop does too. Loops exit cleanly on cancel,
    /// letting their `JoinHandle`s be joined.
    pub(crate) shutdown: CancelToken,
}

/// Statistics returned from `Service::run` so main can log the
/// final `evt=shutdown` event.
pub struct RunStats {
    pub drain_ms: u64,
    pub inflight_drained: usize,
    /// True iff every inflight connection handler finished within
    /// the drain deadline. False means some handlers were left to
    /// time out on their own per-handler timeout.
    pub drain_complete: bool,
}

/// The running daemon: business logic only. Knows nothing about
/// signals, sd_notify, or pidfiles — main wires those.
pub struct Service {
    state: Rc<SharedState>,
    listener: TcpListener,
    admin_listener: UnixListener,
}

/// Cloneable, opaque handle to a running `Service`. External code
/// uses this for operator-visible actions (e.g. reloading
/// `clients.json` from a SIGHUP handler) without holding a
/// reference to `Service` itself — `Service` is consumed by
/// `run()`, so the handle is what survives across the spawn
/// boundary. Internal state remains private.
#[derive(Clone)]
pub struct ServiceHandle {
    state: Rc<SharedState>,
}

impl ServiceHandle {
    /// Reload `clients.json` from the path configured at
    /// `Service::prepare` time and atomically swap the in-memory
    /// table. Logs the outcome as `evt=config_reload`.
    pub async fn reload_clients(&self) {
        let path = self.state.clients_file_path.clone();
        self.state.reload_clients(&path).await
    }
}

impl Service {
    /// Sequencing matters here: PEM bytes, the TCP listen bind, the
    /// admin Unix-socket bind, and the initial PSK file read all need
    /// access the sandbox would deny, so they happen first.
    /// `apply_sandbox` then closes the gate. The shared `CpuWorker`
    /// is spawned AFTER the sandbox so its thread inherits the
    /// Landlock ruleset — spawning it before would leak an
    /// unsandboxed thread into the process.
    pub async fn prepare(
        cfg: &Config,
        config_path: &Path,
        shutdown: CancelToken,
    ) -> Result<Self, DaemonError> {
        // Race the whole preparation against shutdown so an early
        // SIGTERM (e.g. during a hung PEM read on a stale NFS mount)
        // returns cleanly without binding sockets we'd then have to
        // unlink.
        futures_util::select_biased! {
            _ = shutdown.clone().wait().fuse() => Err(DaemonError::Cancelled),
            r = Self::prepare_inner(cfg, config_path, shutdown.clone()).fuse() => r,
        }
    }

    async fn prepare_inner(
        cfg: &Config,
        config_path: &Path,
        shutdown: CancelToken,
    ) -> Result<Self, DaemonError> {
        let clients_file = crate::loader::load_clients_file(&cfg.clients.file).await?;
        let clients_table = build_clients_table(clients_file)?;

        // Pre-sandbox: load the PSK store. Tolerate ENOENT — a fresh
        // deployment starts with an empty roster and grows via `enroll`.
        let psk_store = load_psk_store(&cfg.listen.psk_file).await?;

        // Pre-sandbox: read provider PEMs into memory.
        let github_key = if let Some(gh) = &cfg.provider.github {
            Some(GitHubProvider::load_key(gh).await?)
        } else {
            None
        };

        // Pre-sandbox: bind the inbound TCP listener directly. The
        // daemon terminates Noise NNpsk0 in-process.
        let listen_addr = cfg.listen.bind;
        let listener =
            TcpListener::bind(&listen_addr)
                .await
                .map_err(|source| DaemonError::Bind {
                    path: PathBuf::from(listen_addr.to_string()),
                    source,
                })?;

        // Admin UDS bind. There is a microsecond-scale race between
        // bind(2) and chmod() where the inode briefly carries umask-
        // default perms; INSTALL.md pins the parent dir (`/run/symbolon`)
        // 0o750 owned by group `symbolon`, so a world-mode socket inside
        // is still unreachable from outside that group.
        let admin_path = &cfg.admin.socket_path;
        unlink_stale(admin_path).await?;
        let admin_listener =
            UnixListener::bind(admin_path)
                .await
                .map_err(|source| DaemonError::Bind {
                    path: admin_path.clone(),
                    source,
                })?;
        // 0600: only root and the daemon UID can talk to admin.
        // SO_PEERCRED in run_admin_loop is the second gate.
        chmod_socket(admin_path, 0o600)?;

        // Sandbox gate closes here.
        apply_sandbox(cfg)?;

        // Post-sandbox: spawn the shared CPU worker (its OS thread
        // inherits the Landlock ruleset via TGID-wide application).
        let cpu_worker =
            Rc::new(CpuWorker::new("symbolon-cpu-worker").map_err(DaemonError::CpuWorker)?);

        // Post-sandbox: construct providers with pre-loaded keys.
        let mut providers: HashMap<String, GitHubProvider> = HashMap::new();
        if let Some(gh) = &cfg.provider.github {
            let key = github_key.expect("github_key loaded above when gh is Some");
            let provider = GitHubProvider::new(gh, key, cpu_worker.clone(), shutdown.clone())?;
            providers.insert(gh.host.clone(), provider);
        }

        let state = Rc::new(SharedState {
            clients: RefCell::new(clients_table),
            psks: RefCell::new(psk_store),
            providers,
            psk_file_path: cfg.listen.psk_file.clone(),
            clients_file_path: cfg.clients.file.clone(),
            admin_socket_path: cfg.admin.socket_path.clone(),
            start_time: SystemTime::now(),
            shutdown,
        });

        info!(
            evt = %EventKind::Prepare,
            version = env!("CARGO_PKG_VERSION"),
            config_path = %config_path.display(),
            listen_addr = %listen_addr,
            admin_socket = %admin_path.display(),
        );

        Ok(Self {
            state,
            listener,
            admin_listener,
        })
    }

    /// Returns an opaque cloneable handle to the running service.
    /// Use it from outside code to drive operator-visible actions
    /// (e.g. SIGHUP-triggered `reload_clients`) without holding a
    /// reference to `Service` itself (which is consumed by `run`).
    pub fn handle(&self) -> ServiceHandle {
        ServiceHandle {
            state: self.state.clone(),
        }
    }

    /// Per-provider startup selfcheck. Logs `evt=selfcheck` once per
    /// provider and never returns Err (soft-fail per PROTOCOLS.md).
    /// Each provider's selfcheck is itself bounded by its configured
    /// `selfcheck_timeout` and races the shutdown token from inside
    /// `GitHubProvider::with_breadcrumbs` — so a SIGTERM during this
    /// call returns quickly with `GithubError::Cancelled` rather
    /// than hanging the daemon at startup.
    pub async fn selfcheck(&self) {
        for (host, provider) in &self.state.providers {
            let req_id = ulid::Ulid::new().to_string();
            match provider.selfcheck(&req_id).await {
                Ok(outcome) => {
                    info!(
                        evt = %EventKind::Selfcheck,
                        req_id = %req_id,
                        out_req_id = %outcome.out_req_id,
                        gh_req_id = outcome.gh_req_id.as_deref().unwrap_or(""),
                        provider = %host,
                        ok = true,
                        clock_skew_sec = outcome.clock_skew_sec,
                    );
                }
                Err(e) => {
                    warn!(
                        evt = %EventKind::Selfcheck,
                        req_id = %req_id,
                        provider = %host,
                        ok = false,
                        error = %crate::logging::ErrorChain(&e),
                    );
                }
            }
        }
    }

    /// Run the accept loops until `shutdown` is cancelled, drain
    /// per-connection handlers, unlink the admin socket. Returns RunStats.
    pub async fn run(self) -> Result<RunStats, DaemonError> {
        let Service {
            state,
            listener,
            admin_listener,
        } = self;
        let provider_names: Vec<&str> = state.providers.keys().map(String::as_str).collect();
        info!(evt = %EventKind::Startup, providers = ?provider_names, "daemon started");

        // Admin loop: held as a JoinHandle and awaited after the
        // accept loop exits. The admin loop itself selects on
        // `state.shutdown.wait()` so it terminates cleanly.
        let admin_state = state.clone();
        let admin_handle = compio::runtime::spawn(async move {
            if let Err(e) = crate::admin::run_admin_loop(admin_listener, admin_state).await {
                tracing::error!(error = %crate::logging::ErrorChain(&e), "admin loop exited");
            }
        });

        // Per-connection bookkeeping via ConnectionTracker. Each
        // spawn is wrapped with PER_CONNECTION_TIMEOUT; drain on
        // shutdown waits up to 5 s for handlers to finish, after
        // which the spawned tasks are left to time out on their own.
        let tracker = ConnectionTracker::new(PER_CONNECTION_TIMEOUT, Duration::from_secs(5));
        loop {
            futures_util::select! {
                accept_res = listener.accept().fuse() => {
                    let (stream, _peer) = accept_res.map_err(DaemonError::Accept)?;
                    // Race: shutdown.cancel() fired while accept was
                    // already polled-ready in this same select!
                    // iteration. Drop the stream rather than start
                    // a handler we won't drain — the next loop
                    // iteration's select! will pick the
                    // shutdown.wait() arm and break.
                    if state.shutdown.is_cancelled() {
                        drop(stream);
                        continue;
                    }
                    let req_id = ulid::Ulid::new().to_string();
                    let state = state.clone();
                    tracker.spawn(async move || {
                        handle_connection(stream, req_id, state).await;
                    });
                }
                _ = state.shutdown.clone().wait().fuse() => break,
            }
        }

        // Measure the full shutdown window: drain + admin-join + any
        // straggler cleanup. The previous accounting only covered
        // listen-side drain; admin-side drain happens inside
        // `admin_handle`'s loop, and unbounded admin handlers could
        // hide latency from the JSON log line.
        let shutdown_start = Instant::now();
        let drain_stats = tracker.drain().await;
        let inflight_drained = drain_stats.inflight_drained;
        let drain_complete = drain_stats.drain_complete;

        // Join admin loop. By this point shutdown is cancelled so
        // its inner select! will break; it then runs its own internal
        // drain on its tracker. Time spent here is also part of the
        // shutdown latency budget.
        let _ = admin_handle.await;

        let drain_ms = shutdown_start.elapsed().as_millis() as u64;
        if !drain_complete {
            tracing::warn!(
                evt = %EventKind::DrainIncomplete,
                inflight_drained,
                drain_ms,
                "drain deadline expired with handlers still in flight",
            );
        }

        // PROTOCOLS.md shutdown step: unlink the admin Unix socket.
        // The listen socket is a TCP listener — closing the file
        // descriptor (when `listener` drops below) is sufficient.
        let _ = compio::fs::remove_file(&state.admin_socket_path).await;
        drop(listener);

        Ok(RunStats {
            drain_ms,
            inflight_drained,
            drain_complete,
        })
    }
}

/// Convenience wrapper: prepare the service with a fresh
/// `CancelToken`, then run until the token fires. The daemon itself
/// does NOT install signal handlers — production code (main) wires
/// signals into the token via `crate::signals`. This wrapper is for
/// tests and other callers that want to drive the lifecycle by
/// dropping the spawned task.
pub async fn run(cfg: &Config, config_path: &Path) -> Result<RunStats, DaemonError> {
    let shutdown = CancelToken::new();
    let service = Service::prepare(cfg, config_path, shutdown).await?;
    service.run().await
}

impl SharedState {
    /// Reload `clients.json` and atomically swap the in-memory
    /// table. Public so the SIGHUP handler installed by `main` can
    /// drive a reload through the state handle without importing
    /// daemon-internal helpers.
    pub async fn reload_clients(&self, path: &Path) {
        reload_clients_inner(self, path).await
    }
}

async fn reload_clients_inner(state: &SharedState, path: &Path) {
    let file = match crate::loader::load_clients_file(path).await {
        Ok(f) => f,
        Err(e) => {
            warn!(evt = %EventKind::ConfigReload, triggered_by = "sighup", ok = false, error = %crate::logging::ErrorChain(&e));
            return;
        }
    };
    let new_table = match build_clients_table(file) {
        Ok(t) => t,
        Err(e) => {
            warn!(evt = %EventKind::ConfigReload, triggered_by = "sighup", ok = false, error = %crate::logging::ErrorChain(&e));
            return;
        }
    };
    // Reload the PSK store alongside clients.json so hand-edits to
    // the on-disk roster (rare; admin enroll/revoke is the normal
    // path) are picked up coherently.
    let new_psks = match load_psk_store(&state.psk_file_path).await {
        Ok(store) => store,
        Err(e) => {
            warn!(evt = %EventKind::ConfigReload, triggered_by = "sighup", ok = false, error = %crate::logging::ErrorChain(&e));
            return;
        }
    };
    let client_count = new_table.len();
    let psk_count = new_psks.len();
    *state.clients.borrow_mut() = new_table;
    *state.psks.borrow_mut() = new_psks;
    info!(
        evt = %EventKind::ConfigReload,
        triggered_by = "sighup",
        client_count = client_count,
        psk_count = psk_count,
    );
}

/// Read the on-disk PSK file and parse it into a `PskStore`. Treats
/// `ENOENT` as "fresh deployment" → empty store.
async fn load_psk_store(path: &Path) -> Result<PskStore, DaemonError> {
    let bytes = match compio::fs::read(path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(PskStore::empty()),
        Err(source) => {
            return Err(DaemonError::PskRead {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let text = std::str::from_utf8(&bytes).map_err(|source| {
        DaemonError::LoadPsks(PskStoreError::Utf8 {
            path: path.to_path_buf(),
            source,
        })
    })?;
    PskStore::parse(text, path).map_err(DaemonError::LoadPsks)
}

fn chmod_socket(path: &Path, mode: u32) -> Result<(), DaemonError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms).map_err(|source| DaemonError::Bind {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(target_env = "musl")]
const fn nameservice_files() -> &'static [&'static str] {
    &["/etc/resolv.conf", "/etc/hosts"]
}

#[cfg(not(target_env = "musl"))]
const fn nameservice_files() -> &'static [&'static str] {
    &[
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/gai.conf",
    ]
}

fn apply_sandbox(cfg: &Config) -> Result<(), DaemonError> {
    let level = cfg.security.sandbox;
    let mut read_dirs = vec![PathBuf::from("/etc/ssl/certs")];
    read_dirs.extend(cfg.security.extra_read_dirs.iter().cloned());
    let paths = SandboxPaths {
        read_files: vec![
            cfg.clients.file.clone(),
            cfg.listen.psk_file.clone(),
            PathBuf::from("/dev/urandom"),
        ],
        read_dirs,
        // Files consulted by libc `getaddrinfo` for our single
        // outbound HTTPS hostname (`api.github.com`). musl reads only
        // /etc/resolv.conf and /etc/hosts; nsswitch.conf and gai.conf
        // are pure glibc constructs the musl binary never opens, so
        // they're omitted from the musl ruleset. /etc/host.conf and
        // /etc/services are intentionally NOT included on either:
        // host.conf is legacy/ignored, /etc/services is for
        // getservbyname which we don't use (we pass numeric 443).
        resolv_files: nameservice_files().iter().map(PathBuf::from).collect(),
        write_parent_dirs: {
            let mut v = vec![
                cfg.clients
                    .file
                    .parent()
                    .ok_or(DaemonError::NoParentDir("clients.file"))?
                    .to_path_buf(),
                cfg.listen
                    .psk_file
                    .parent()
                    .ok_or(DaemonError::NoParentDir("listen.psk_file"))?
                    .to_path_buf(),
                // Shutdown unlinks the admin Unix socket; without
                // its parent in the allowlist, the remove_file would
                // silently fail post-sandbox and leave a stale socket
                // for the next start.
                cfg.admin
                    .socket_path
                    .parent()
                    .ok_or(DaemonError::NoParentDir("admin.socket_path"))?
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
    // tracing's event! macro requires a const level, so we can't
    // factor the level branch out further than this.
    if degraded {
        warn!(
            evt = %EventKind::SandboxApplied,
            policy = ?cfg.security.sandbox,
            abi = outcome.requested_abi,
            status = outcome.status,
            fs = outcome.fs,
            tcp = outcome.tcp,
            scope = outcome.scope,
        );
    } else {
        info!(
            evt = %EventKind::SandboxApplied,
            policy = ?cfg.security.sandbox,
            abi = outcome.requested_abi,
            status = outcome.status,
            fs = outcome.fs,
            tcp = outcome.tcp,
            scope = outcome.scope,
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

fn build_clients_table(file: ClientsFile) -> Result<HashMap<String, ResolvedClient>, DaemonError> {
    let mut table = HashMap::new();
    for entry in file.clients {
        let key = entry.name.clone();
        let value = ResolvedClient {
            name: entry.name,
            providers: entry.providers.into_iter().collect(),
            enrolled_at: entry.enrolled_at,
            note: entry.note,
        };
        if table.insert(key.clone(), value).is_some() {
            return Err(DaemonError::DuplicateClientName(key));
        }
    }
    Ok(table)
}

async fn handle_connection(mut stream: TcpStream, req_id: String, state: Rc<SharedState>) {
    let peer = stream.peer_addr().ok();
    // ------ Phase 1: identity prelude ------
    let identity_owned = match read_prelude(&mut stream).await {
        Ok(s) => s,
        Err(reason) => {
            warn!(
                req_id = %req_id,
                evt = %EventKind::PreludeInvalid,
                peer = ?peer,
                reason = reason,
            );
            return;
        }
    };

    // ------ Phase 2: PSK lookup + client metadata lookup ------
    let psk = match state.psks.borrow().lookup(&identity_owned) {
        Some(p) => zeroize::Zeroizing::new(*p),
        None => {
            warn!(
                req_id = %req_id,
                evt = %EventKind::MintDenied,
                reason = "client_unknown",
                psk_identity = %identity_owned,
                peer = ?peer,
            );
            return;
        }
    };
    let Some(client) = state.clients.borrow().get(&identity_owned).cloned() else {
        // PSK exists but no clients.json entry — operator desynced the
        // two files; refuse to mint rather than guess metadata.
        warn!(
            req_id = %req_id,
            evt = %EventKind::MintDenied,
            reason = "client_metadata_missing",
            psk_identity = %identity_owned,
        );
        return;
    };
    info!(
        req_id = %req_id,
        evt = %EventKind::Accept,
        psk_identity = %client.name,
        peer = ?peer,
    );

    // ------ Phase 2b: Noise NNpsk0 responder handshake ------
    let mut transport_state = match run_responder_handshake(&mut stream, &psk).await {
        Ok(ts) => ts,
        Err(reason) => {
            warn!(
                req_id = %req_id,
                evt = %EventKind::HandshakeFailed,
                client = %client.name,
                reason = reason,
            );
            return;
        }
    };

    // ------ Phase 3: encrypted git-credential request ------
    let request_bytes = match read_framed_decrypt(&mut stream, &mut transport_state).await {
        Ok(b) => b,
        Err(reason) => {
            warn!(
                req_id = %req_id,
                evt = %EventKind::MintDenied,
                reason = "transport_read",
                client = %client.name,
                detail = reason,
            );
            return;
        }
    };
    if request_bytes.len() > WIRE_READ_BUDGET {
        warn!(
            req_id = %req_id,
            evt = %EventKind::MintDenied,
            reason = "malformed_request",
            client = %client.name,
            detail = "request_exceeds_cap",
        );
        return;
    }
    let request = match git_credential::parse(&request_bytes) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                req_id = %req_id,
                evt = %EventKind::MintDenied,
                reason = "malformed_request",
                client = %client.name,
                error = %e,
            );
            return;
        }
    };
    drop(request_bytes);

    // ------ Phase 4: host dispatch ------
    let Some(provider) = state.providers.get(&request.host) else {
        warn!(
            req_id = %req_id,
            evt = %EventKind::MintDenied,
            reason = "unknown_host",
            host = %request.host,
            client = %client.name,
        );
        return;
    };

    // ------ Phase 5: mint ------
    let started = Instant::now();
    let mint_result = provider.mint(&req_id, &request.path).await;
    let provider_ms = started.elapsed().as_millis() as u64;

    let (response, repo_id, out_req_id, gh_req_id) = match mint_result {
        Ok(outcome) => (
            outcome.response,
            outcome.repo_id,
            outcome.out_req_id,
            outcome.gh_req_id,
        ),
        Err(e) => {
            // RepoNotFound at mint-time = the provider just invalidated
            // a (possibly cached) repo-id; surface that to the operator
            // as a distinct event per PROTOCOLS.md.
            if matches!(e, GithubError::RepoNotFound { .. }) {
                info!(
                    req_id = %req_id,
                    evt = %EventKind::CacheInvalidated,
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

    // ------ Phase 6: emit encrypted response ------
    let mut out = Vec::with_capacity(256);
    if let Err(e) = git_credential::write_response(&response, &mut out) {
        warn!(
            req_id = %req_id,
            evt = %EventKind::ProviderError,
            reason = "response_encode",
            provider = %request.host,
            error = %e,
        );
        return;
    }
    if let Err(reason) = write_framed_encrypt(&mut stream, &mut transport_state, &out).await {
        warn!(
            req_id = %req_id,
            evt = %EventKind::ProviderError,
            reason = "response_write",
            provider = %request.host,
            detail = reason,
        );
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
        out_req_id = %out_req_id,
        gh_req_id = gh_req_id.as_deref().unwrap_or(""),
        evt = %EventKind::Mint,
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
            warn!(
                req_id = %req_id,
                evt = %EventKind::MintDenied,
                reason = "repo_not_accessible",
                provider_status = 404,
                provider = %host,
                client = %client_name,
                repo = %path,
                provider_ms = provider_ms,
            );
        }
        GithubError::Unauthorized { body } => {
            warn!(
                req_id = %req_id,
                evt = %EventKind::MintDenied,
                reason = "provider_4xx",
                provider_status = 401,
                provider = %host,
                client = %client_name,
                repo = %path,
                provider_ms = provider_ms,
                error = %body,
            );
        }
        GithubError::Forbidden { body } => {
            warn!(
                req_id = %req_id,
                evt = %EventKind::MintDenied,
                reason = "provider_4xx",
                provider_status = 403,
                provider = %host,
                client = %client_name,
                repo = %path,
                provider_ms = provider_ms,
                error = %body,
            );
        }
        GithubError::RateLimited => {
            warn!(
                req_id = %req_id,
                evt = %EventKind::MintDenied,
                reason = "provider_4xx",
                provider_status = 429,
                provider = %host,
                client = %client_name,
                repo = %path,
                provider_ms = provider_ms,
            );
        }
        GithubError::MalformedPath(_) => {
            warn!(
                req_id = %req_id,
                evt = %EventKind::MintDenied,
                reason = "malformed_request",
                provider = %host,
                client = %client_name,
                repo = %path,
                provider_ms = provider_ms,
            );
        }
        GithubError::ServerError(status) => {
            warn!(
                req_id = %req_id,
                evt = %EventKind::ProviderError,
                status = *status,
                provider = %host,
                repo = %path,
                provider_ms = provider_ms,
            );
        }
        GithubError::UnexpectedStatus(status) => {
            warn!(
                req_id = %req_id,
                evt = %EventKind::ProviderError,
                status = *status,
                provider = %host,
                repo = %path,
                provider_ms = provider_ms,
            );
        }
        _ => {
            warn!(
                req_id = %req_id,
                evt = %EventKind::ProviderError,
                provider = %host,
                repo = %path,
                provider_ms = provider_ms,
                error = %crate::logging::ErrorChain(&err),
            );
        }
    }
}

// ----- TCP/Noise I/O helpers ---------------------------------------------
//
// All errors are surfaced as static `&'static str` reason codes so that
// `handle_connection` can pass them straight into structured log fields
// without leaking error formatting choices upstream. The Noise transport
// itself never returns recoverable errors mid-stream: any failure here
// drops the connection.

/// Read EXACTLY `n` bytes from `stream` into a fresh `Vec`. Returns
/// `None` on EOF or I/O error.
async fn read_exact_n(stream: &mut TcpStream, n: usize) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(n);
    while out.len() < n {
        let remaining = n - out.len();
        let buf = Vec::with_capacity(remaining);
        let BufResult(res, mut filled) = stream.read(buf).await;
        match res {
            Ok(0) => return None,
            Ok(read) => {
                filled.truncate(read);
                out.extend_from_slice(&filled);
            }
            Err(_) => return None,
        }
    }
    Some(out)
}

/// Write all bytes in `payload`, returning Ok on full write.
async fn write_all_bytes(stream: &mut TcpStream, payload: Vec<u8>) -> std::io::Result<()> {
    let BufResult(res, _) = stream.write_all(payload).await;
    res.map(|_| ())
}

/// Read the identity prelude: 6-byte header + identity bytes. Returns
/// the owned identity string on success, or a static reason on failure.
async fn read_prelude(stream: &mut TcpStream) -> Result<String, &'static str> {
    let head = read_exact_n(stream, 6)
        .await
        .ok_or("eof_before_prelude_head")?;
    // Validate magic + version + id_len without committing to a
    // borrowing parse yet (we need a final &[u8] that contains the
    // identity bytes too).
    match transport::parse_prelude(&head) {
        Err(PreludeError::Incomplete { .. }) => { /* expected — keep going */ }
        Err(PreludeError::BadMagic { .. }) => return Err("bad_magic"),
        Err(PreludeError::BadVersion { .. }) => return Err("bad_version"),
        Err(PreludeError::BadIdentityLen { .. }) => return Err("bad_identity_len"),
        // The 6-byte head can't have an invalid charset error.
        Err(PreludeError::InvalidCharset { .. }) => return Err("invalid_charset"),
        Ok(_) => unreachable!("6 bytes is never a complete prelude (min 7)"),
    }
    let id_len = head[5] as usize;
    let tail = read_exact_n(stream, id_len)
        .await
        .ok_or("eof_before_identity")?;
    let mut full = head;
    full.extend_from_slice(&tail);
    let (identity, _) = transport::parse_prelude(&full).map_err(|e| match e {
        PreludeError::BadMagic { .. } => "bad_magic",
        PreludeError::BadVersion { .. } => "bad_version",
        PreludeError::BadIdentityLen { .. } => "bad_identity_len",
        PreludeError::InvalidCharset { .. } => "invalid_charset",
        PreludeError::Incomplete { .. } => "incomplete",
    })?;
    Ok(identity.as_str().to_string())
}

/// Run the responder side of `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`.
/// Consumes one inbound framed handshake message, writes one outbound,
/// then transitions to transport mode.
async fn run_responder_handshake(
    stream: &mut TcpStream,
    psk: &[u8; 32],
) -> Result<TransportState, &'static str> {
    let mut hs: HandshakeState = transport::responder(psk).map_err(|e| match e {
        TransportError::BadPskLen { .. } => "bad_psk_len",
        TransportError::Params(_) => "noise_params",
        TransportError::Handshake(_) => "noise_build",
        TransportError::Transition(_) | TransportError::Transport(_) => "noise_internal",
        TransportError::OversizedFrame { .. } => "noise_oversize",
    })?;
    let mut scratch = vec![0u8; transport::MAX_MESSAGE_SIZE];

    // -> psk, e (read one framed message)
    let msg1 = read_framed_raw(stream).await?;
    transport::handshake_read(&mut hs, &msg1, &mut scratch).map_err(|_| "handshake_read_failed")?;

    // <- e, ee (write one framed message)
    let n = transport::handshake_write(&mut hs, &[], &mut scratch)
        .map_err(|_| "handshake_write_failed")?;
    write_framed_raw(stream, &scratch[..n])
        .await
        .map_err(|_| "handshake_write_io")?;

    transport::into_transport(hs).map_err(|_| "handshake_into_transport_failed")
}

/// Read a 16-bit BE length-prefixed framed payload from `stream`.
async fn read_framed_raw(stream: &mut TcpStream) -> Result<Vec<u8>, &'static str> {
    let len_buf_vec = read_exact_n(stream, 2)
        .await
        .ok_or("eof_before_frame_len")?;
    let len_buf: [u8; 2] = len_buf_vec
        .as_slice()
        .try_into()
        .map_err(|_| "frame_len_underflow")?;
    let len = transport::read_frame_length(&len_buf).map_err(|_| "frame_too_big")?;
    read_exact_n(stream, len)
        .await
        .ok_or("eof_before_frame_body")
}

/// Read one framed Noise transport message and decrypt it.
async fn read_framed_decrypt(
    stream: &mut TcpStream,
    ts: &mut TransportState,
) -> Result<Vec<u8>, &'static str> {
    let ct = read_framed_raw(stream).await?;
    let mut out = vec![0u8; transport::MAX_MESSAGE_SIZE];
    let n = transport::transport_read(ts, &ct, &mut out).map_err(|_| "decrypt_failed")?;
    out.truncate(n);
    Ok(out)
}

/// Frame `payload` with a 16-bit BE length prefix and write to stream.
async fn write_framed_raw(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    let framed = transport::frame(payload)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too big"))?;
    write_all_bytes(stream, framed).await
}

/// Encrypt `plaintext` through the transport, frame it, and send.
async fn write_framed_encrypt(
    stream: &mut TcpStream,
    ts: &mut TransportState,
    plaintext: &[u8],
) -> Result<(), &'static str> {
    let mut buf = vec![0u8; transport::MAX_MESSAGE_SIZE];
    let n = transport::transport_write(ts, plaintext, &mut buf).map_err(|_| "encrypt_failed")?;
    write_framed_raw(stream, &buf[..n])
        .await
        .map_err(|_| "write_io")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientEntry;

    fn entry(name: &str, providers: &[&str]) -> ClientEntry {
        ClientEntry {
            name: name.to_string(),
            providers: providers.iter().map(|s| s.to_string()).collect(),
            enrolled_at: "2026-05-31T00:00:00Z".to_string(),
            note: None,
        }
    }

    #[test]
    fn build_clients_table_indexes_by_name() {
        let file = ClientsFile {
            version: 2,
            clients: vec![entry("vm-1", &["github"]), entry("vm-2", &["github"])],
        };
        let table = build_clients_table(file).unwrap();
        assert_eq!(table.len(), 2);
        let v1 = table.get("vm-1").unwrap();
        assert_eq!(v1.name, "vm-1");
        assert!(v1.providers.iter().any(|p| p == "github"));
    }

    #[test]
    fn build_clients_table_rejects_duplicate_name() {
        let file = ClientsFile {
            version: 2,
            clients: vec![entry("vm-1", &["github"]), entry("vm-1", &["github"])],
        };
        let err = build_clients_table(file).unwrap_err();
        assert!(matches!(err, DaemonError::DuplicateClientName(n) if n == "vm-1"));
    }

    #[test]
    fn build_clients_table_empty_is_ok() {
        let file = ClientsFile {
            version: 2,
            clients: vec![],
        };
        assert_eq!(build_clients_table(file).unwrap().len(), 0);
    }

    // The previous `empty_state()` helper is gone; the one remaining
    // test that needs a SharedState builds one inline so its setup
    // is local and explicit.

    #[compio::test]
    async fn reload_clients_swaps_in_place() {
        let clients_path =
            std::env::temp_dir().join(format!("symbolon-reload-test-{}.json", ulid::Ulid::new()));
        std::fs::write(
            &clients_path,
            r#"{"version":2,"clients":[{"name":"new","providers":["github"],"enrolled_at":"y","note":null}]}"#,
        )
        .unwrap();
        // psk_file_path points at a nonexistent file; load_psk_store
        // treats ENOENT as "fresh deployment" → empty PSK store.
        let nonexistent_psk =
            std::env::temp_dir().join(format!("symbolon-reload-test-psks-{}", ulid::Ulid::new()));
        let state = Rc::new(SharedState {
            clients: RefCell::new({
                let mut m = HashMap::new();
                m.insert(
                    "old".to_string(),
                    ResolvedClient {
                        name: "old".to_string(),
                        providers: Vec::new(),
                        enrolled_at: "x".to_string(),
                        note: None,
                    },
                );
                m
            }),
            psks: RefCell::new(PskStore::empty()),
            providers: HashMap::new(),
            psk_file_path: nonexistent_psk,
            clients_file_path: clients_path.clone(),
            admin_socket_path: PathBuf::new(),
            start_time: SystemTime::now(),
            shutdown: CancelToken::new(),
        });
        state.reload_clients(&clients_path).await;
        let borrow = state.clients.borrow();
        assert_eq!(borrow.len(), 1);
        assert!(borrow.contains_key("new"));
        assert!(!borrow.contains_key("old"));
        drop(borrow);
        let _ = std::fs::remove_file(&clients_path);
    }
}
