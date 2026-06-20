//! Daemon: TCP accept loop driving `transport::Responder` per
//! connection, plus the admin UDS loop and SIGHUP reload glue.
//!
//! Per-connection errors do not propagate: each failure point logs
//! a structured event (`evt=prelude_invalid` /
//! `evt=handshake_failed` / `evt=mint_denied` /
//! `evt=provider_error` / `evt=mint`) and drops the connection.
//!
//! See `docs/ARCHITECTURE.md` for the full lifecycle picture.

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
use tracing::{info, warn};

use crate::config::{ClientsFile, Config};
use crate::connection_tracker::ConnectionTracker;
use crate::cpu_worker::CpuWorker;
use crate::events::EventKind;
use crate::git_credential;
use crate::providers::github::{GitHubProvider, GithubError};
use crate::providers::{Provider, ProviderError};
use crate::psk_store::{PskStore, PskStoreError};
use crate::sandbox::{self, SandboxError, SandboxPaths};
use crate::transport::{Phase, Responder, SessionError, Step};

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
    #[error("failed to chmod admin socket at {}", path.display())]
    Chmod {
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
    /// One concrete provider per configured `[provider.<name>]`
    /// section. Wire dispatch picks by `provider.host()`; admin
    /// dispatch picks by `provider.kind()`. Cardinality is 1 today;
    /// when GitLab/Gitea land, add a sibling module + `ProviderKind`
    /// variant.
    pub(crate) providers: Vec<Box<dyn Provider>>,
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
        let clients_table = HashMap::try_from(clients_file)?;

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
        // RAII: the next several `?` steps (chmod, sandbox, CpuWorker,
        // provider construction) all happen AFTER the UDS bind. Any
        // failure there leaves an orphaned socket on disk; this guard
        // does best-effort cleanup on Drop. Disarmed on the success
        // path below so the socket lives.
        let admin_bind_guard = AdminBindGuard::new(admin_path.clone());
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
        let mut providers: Vec<Box<dyn Provider>> = Vec::new();
        if let Some(gh) = &cfg.provider.github {
            let key = github_key.expect("github_key loaded above when gh is Some");
            let provider = GitHubProvider::new(gh, key, cpu_worker.clone(), shutdown.clone())?;
            providers.push(Box::new(provider));
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

        admin_bind_guard.disarm();
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
    /// timeout and races the shutdown token from inside the provider
    /// — so a SIGTERM during this call returns quickly with
    /// `ProviderError::Cancelled` rather than hanging the daemon at
    /// startup.
    pub async fn selfcheck(&self) {
        for provider in &self.state.providers {
            let req_id = ulid::Ulid::new().to_string();
            match provider.selfcheck(&req_id).await {
                Ok(outcome) => {
                    info!(
                        evt = %EventKind::Selfcheck,
                        req_id = %req_id,
                        out_req_id = %outcome.out_req_id,
                        provider_req_id = outcome.provider_req_id.as_deref().unwrap_or(""),
                        provider = %provider.host(),
                        ok = true,
                        clock_skew_sec = outcome.clock_skew_sec,
                    );
                }
                Err(e) => {
                    warn!(
                        evt = %EventKind::Selfcheck,
                        req_id = %req_id,
                        provider = %provider.host(),
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
        let provider_names: Vec<&str> = state.providers.iter().map(|p| p.host()).collect();
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

        let drain_ms = u64::try_from(shutdown_start.elapsed().as_millis()).unwrap_or(u64::MAX);
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
    /// Look up the configured provider whose wire-protocol kind
    /// matches `name` (e.g. `"github"` → `ProviderKind::Github`).
    /// Used by the admin path to route `mint` / `selfcheck` requests
    /// to the right provider instance. Wire-side dispatch (the
    /// git-credential `host=` match) lives in `handle_connection`
    /// and uses `provider.host()` instead.
    pub fn lookup_provider(&self, name: &str) -> Option<&(dyn crate::providers::Provider + '_)> {
        let kind: crate::providers::ProviderKind = name.parse().ok()?;
        self.providers
            .iter()
            .find(|p| p.kind() == kind)
            .map(|b| b.as_ref())
    }

    /// Reload `clients.json` and atomically swap the in-memory
    /// table. Public so the SIGHUP handler installed by `main` can
    /// drive a reload through the state handle without importing
    /// daemon-internal helpers.
    pub async fn reload_clients(&self, path: &Path) {
        let file = match crate::loader::load_clients_file(path).await {
            Ok(f) => f,
            Err(e) => {
                warn!(evt = %EventKind::ConfigReload, triggered_by = "sighup", ok = false, error = %crate::logging::ErrorChain(&e));
                return;
            }
        };
        let new_table = match HashMap::try_from(file) {
            Ok(t) => t,
            Err(e) => {
                warn!(evt = %EventKind::ConfigReload, triggered_by = "sighup", ok = false, error = %crate::logging::ErrorChain(&e));
                return;
            }
        };
        // Reload the PSK store alongside clients.json so hand-edits to
        // the on-disk roster (rare; admin enroll/revoke is the normal
        // path) are picked up coherently.
        let new_psks = match load_psk_store(&self.psk_file_path).await {
            Ok(store) => store,
            Err(e) => {
                warn!(evt = %EventKind::ConfigReload, triggered_by = "sighup", ok = false, error = %crate::logging::ErrorChain(&e));
                return;
            }
        };
        let client_count = new_table.len();
        let psk_count = new_psks.len();
        // No `.await` between these two assignments: the single-threaded
        // compio runtime means no other task observes a split where
        // `clients` has been swapped but `psks` hasn't (or vice-versa).
        *self.clients.borrow_mut() = new_table;
        *self.psks.borrow_mut() = new_psks;
        info!(
            evt = %EventKind::ConfigReload,
            triggered_by = "sighup",
            client_count = client_count,
            psk_count = psk_count,
        );
    }
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
    std::fs::set_permissions(path, perms).map_err(|source| DaemonError::Chmod {
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

/// RAII guard: unlinks the admin UDS on Drop unless explicitly
/// disarmed. Used during `prepare_inner` so any failure between
/// `UnixListener::bind` and the success return doesn't leave an
/// orphaned socket on disk. After the sandbox closes, the unlink
/// will silently fail (Landlock blocks the syscall) — that's
/// acceptable because the next `prepare_inner` cleans it via
/// `unlink_stale`.
struct AdminBindGuard {
    path: Option<PathBuf>,
}

impl AdminBindGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(mut self) {
        self.path = None;
    }
}

impl Drop for AdminBindGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = std::fs::remove_file(&p);
        }
    }
}

impl TryFrom<ClientsFile> for HashMap<String, ResolvedClient> {
    type Error = DaemonError;

    fn try_from(file: ClientsFile) -> Result<Self, Self::Error> {
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
}

async fn handle_connection(mut stream: TcpStream, req_id: String, state: Rc<SharedState>) {
    /// Cross-step state the driver needs to stash so the final
    /// `evt=mint` log event (emitted only after the encrypted
    /// response is on the wire) can see everything from the
    /// earlier `Step::Request` arm.
    struct MintRecord {
        host: String,
        path: String,
        response: git_credential::Response,
        out_req_id: String,
        provider_req_id: Option<String>,
        provider_ms: u64,
    }

    let peer = stream.peer_addr().ok();
    let mut sess = Responder::new();
    let mut client_name: Option<String> = None;
    let mut mint_record: Option<MintRecord> = None;

    loop {
        let phase_at_entry = sess.phase();
        let step = match sess.step() {
            Ok(s) => s,
            Err(e) => {
                log_session_failure(&req_id, peer, phase_at_entry, client_name.as_deref(), &e);
                return;
            }
        };

        match step {
            Step::ReadExact { n } => {
                let phase = sess.phase();
                let Some(bytes) = read_exact_n(&mut stream, n).await else {
                    log_phase_eof(&req_id, peer, phase, client_name.as_deref());
                    return;
                };
                if let Err(e) = sess.recv(&bytes) {
                    log_session_failure(&req_id, peer, phase, client_name.as_deref(), &e);
                    return;
                }
            }

            Step::NeedPsk { identity } => {
                let psk = match state.psks.borrow().lookup(&identity) {
                    Some(p) => *p,
                    None => {
                        warn!(
                            req_id = %req_id,
                            evt = %EventKind::MintDenied,
                            reason = "client_unknown",
                            psk_identity = %identity,
                            peer = ?peer,
                        );
                        return;
                    }
                };
                let Some(client) = state.clients.borrow().get(&identity).cloned() else {
                    // PSK exists but no clients.json entry — operator
                    // desynced the two files; refuse to mint rather than
                    // guess metadata.
                    warn!(
                        req_id = %req_id,
                        evt = %EventKind::MintDenied,
                        reason = "client_metadata_missing",
                        psk_identity = %identity,
                    );
                    return;
                };
                info!(
                    req_id = %req_id,
                    evt = %EventKind::Accept,
                    psk_identity = %client.name,
                    peer = ?peer,
                );
                client_name = Some(client.name);
                if let Err(e) = sess.set_psk(psk) {
                    log_session_failure(&req_id, peer, sess.phase(), client_name.as_deref(), &e);
                    return;
                }
            }

            Step::Write(bytes) => {
                if let Err(e) = write_all_bytes(&mut stream, bytes).await {
                    warn!(
                        req_id = %req_id,
                        evt = %EventKind::HandshakeFailed,
                        client = client_name.as_deref().unwrap_or(""),
                        reason = "handshake_write_io",
                        error = %e,
                    );
                    return;
                }
                if let Err(e) = sess.wrote() {
                    log_session_failure(&req_id, peer, sess.phase(), client_name.as_deref(), &e);
                    return;
                }
            }

            Step::Request(request_bytes) => {
                let client_str = client_name.as_deref().unwrap_or("");
                if request_bytes.len() > WIRE_READ_BUDGET {
                    warn!(
                        req_id = %req_id,
                        evt = %EventKind::MintDenied,
                        reason = "malformed_request",
                        client = client_str,
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
                            client = client_str,
                            error = %e,
                        );
                        return;
                    }
                };
                drop(request_bytes);

                let Some(provider) = state.providers.iter().find(|p| p.host() == request.host)
                else {
                    warn!(
                        req_id = %req_id,
                        evt = %EventKind::MintDenied,
                        reason = "unknown_host",
                        host = %request.host,
                        client = client_str,
                    );
                    return;
                };

                let started = Instant::now();
                let mint_result = provider.mint(&req_id, &request.path).await;
                let provider_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

                let outcome = match mint_result {
                    Ok(o) => o,
                    Err(e) => {
                        // RepoNotFound at mint-time = the provider just
                        // invalidated a (possibly cached) repo handle; surface
                        // that as a distinct event per PROTOCOLS.md.
                        if matches!(e, ProviderError::RepoNotFound { .. }) {
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
                            client_str,
                            &request.host,
                            &request.path,
                            provider_ms,
                            e,
                        );
                        return;
                    }
                };

                let mut response_bytes = Vec::with_capacity(256);
                if let Err(e) =
                    git_credential::write_response(&outcome.response, &mut response_bytes)
                {
                    warn!(
                        req_id = %req_id,
                        evt = %EventKind::ProviderError,
                        reason = "response_encode",
                        provider = %request.host,
                        error = %e,
                    );
                    return;
                }

                if let Err(e) = sess.set_response(&response_bytes) {
                    log_session_failure(&req_id, peer, sess.phase(), client_name.as_deref(), &e);
                    return;
                }

                mint_record = Some(MintRecord {
                    host: request.host,
                    path: request.path,
                    response: outcome.response,
                    out_req_id: outcome.out_req_id,
                    provider_req_id: outcome.provider_req_id,
                    provider_ms,
                });
            }

            Step::Done => {
                let _ = stream.flush().await;
                if let (Some(client_str), Some(rec)) =
                    (client_name.as_deref(), mint_record.as_ref())
                {
                    let expires_at_secs = rec
                        .response
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
                        out_req_id = %rec.out_req_id,
                        provider_req_id = rec.provider_req_id.as_deref().unwrap_or(""),
                        evt = %EventKind::Mint,
                        provider = %rec.host,
                        client = %client_str,
                        repo = %rec.path,
                        ttl_sec = ttl_sec,
                        expires_at_unix = expires_at_secs,
                        provider_ms = rec.provider_ms,
                    );
                }
                return;
            }
        }
    }
}

/// Map a `SessionError` from the responder state machine to its
/// log event. `phase` is the state we were in BEFORE the failing
/// call — used for `FrameTooBig` whose meaning depends on whether
/// we were doing the handshake or the transport read.
fn log_session_failure(
    req_id: &str,
    peer: Option<std::net::SocketAddr>,
    phase: Phase,
    client_name: Option<&str>,
    err: &SessionError,
) {
    let client_str = client_name.unwrap_or("");
    match err {
        SessionError::PreludeBadMagic { .. } => warn!(
            req_id = %req_id,
            evt = %EventKind::PreludeInvalid,
            peer = ?peer,
            reason = "bad_magic",
        ),
        SessionError::PreludeBadVersion { .. } => warn!(
            req_id = %req_id,
            evt = %EventKind::PreludeInvalid,
            peer = ?peer,
            reason = "bad_version",
        ),
        SessionError::PreludeBadIdentityLen { .. } => warn!(
            req_id = %req_id,
            evt = %EventKind::PreludeInvalid,
            peer = ?peer,
            reason = "bad_identity_len",
        ),
        SessionError::PreludeInvalidCharset { .. } => warn!(
            req_id = %req_id,
            evt = %EventKind::PreludeInvalid,
            peer = ?peer,
            reason = "invalid_charset",
        ),
        SessionError::HandshakeRead(_) => warn!(
            req_id = %req_id,
            evt = %EventKind::HandshakeFailed,
            client = client_str,
            reason = "handshake_read_failed",
        ),
        SessionError::HandshakeWrite(_) => warn!(
            req_id = %req_id,
            evt = %EventKind::HandshakeFailed,
            client = client_str,
            reason = "handshake_write_failed",
        ),
        SessionError::IntoTransport(_) => warn!(
            req_id = %req_id,
            evt = %EventKind::HandshakeFailed,
            client = client_str,
            reason = "handshake_into_transport_failed",
        ),
        SessionError::TransportRead(_) => warn!(
            req_id = %req_id,
            evt = %EventKind::MintDenied,
            client = client_str,
            reason = "transport_read",
            detail = "decrypt_failed",
        ),
        SessionError::TransportWrite(_) => warn!(
            req_id = %req_id,
            evt = %EventKind::ProviderError,
            reason = "response_write",
            client = client_str,
        ),
        SessionError::FrameTooBig { got } => match phase {
            Phase::Transport => warn!(
                req_id = %req_id,
                evt = %EventKind::MintDenied,
                client = client_str,
                reason = "transport_read",
                detail = "frame_too_big",
                got = got,
            ),
            _ => warn!(
                req_id = %req_id,
                evt = %EventKind::HandshakeFailed,
                client = client_str,
                reason = "frame_too_big",
                got = got,
            ),
        },
        SessionError::BadPskLen { .. }
        | SessionError::RecvLen { .. }
        | SessionError::WrongState { .. } => warn!(
            req_id = %req_id,
            evt = %EventKind::HandshakeFailed,
            client = client_str,
            reason = "internal",
            error = %err,
        ),
    }
}

/// Log a clean EOF (read returned 0 bytes) attributed to the current
/// protocol phase.
fn log_phase_eof(
    req_id: &str,
    peer: Option<std::net::SocketAddr>,
    phase: Phase,
    client_name: Option<&str>,
) {
    let client_str = client_name.unwrap_or("");
    match phase {
        Phase::PreludeHead => warn!(
            req_id = %req_id,
            evt = %EventKind::PreludeInvalid,
            peer = ?peer,
            reason = "eof_before_prelude_head",
        ),
        Phase::PreludeBody => warn!(
            req_id = %req_id,
            evt = %EventKind::PreludeInvalid,
            peer = ?peer,
            reason = "eof_before_identity",
        ),
        Phase::Handshake => warn!(
            req_id = %req_id,
            evt = %EventKind::HandshakeFailed,
            client = client_str,
            reason = "eof_during_handshake",
        ),
        Phase::Transport => warn!(
            req_id = %req_id,
            evt = %EventKind::MintDenied,
            client = client_str,
            reason = "transport_read",
            detail = "eof",
        ),
        Phase::AwaitingPsk | Phase::Done => warn!(
            req_id = %req_id,
            evt = %EventKind::HandshakeFailed,
            client = client_str,
            reason = "eof_unexpected_phase",
        ),
    }
}

fn log_mint_error(
    req_id: &str,
    client_name: &str,
    host: &str,
    path: &str,
    provider_ms: u64,
    err: ProviderError,
) {
    match &err {
        ProviderError::RepoNotFound { .. } => {
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
        ProviderError::Unauthorized { body } => {
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
        ProviderError::Forbidden { body } => {
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
        ProviderError::RateLimited => {
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
        ProviderError::MalformedPath { .. } => {
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
        ProviderError::UnexpectedStatus { status } => {
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

// ----- TCP I/O primitives ------------------------------------------------
//
// The two functions the state machine driver in `handle_connection` calls
// against the TCP socket. Everything else (prelude parsing, Noise
// handshake driving, framing, encrypt/decrypt) lives inside
// `transport::Responder`.

/// Read EXACTLY `n` bytes from `stream` into a fresh `Vec`. Returns
/// `None` on EOF or I/O error. Reuses the same chunk buffer across
/// poll iterations — under a slow peer this is the difference
/// between one allocation and one-per-byte.
async fn read_exact_n(stream: &mut TcpStream, n: usize) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut chunk: Vec<u8> = Vec::with_capacity(n);
    while out.len() < n {
        let remaining = n - out.len();
        chunk.clear();
        if chunk.capacity() < remaining {
            chunk.reserve(remaining - chunk.capacity());
        }
        let BufResult(res, returned) = stream.read(chunk).await;
        chunk = returned;
        match res {
            Ok(0) => return None,
            Ok(read) => {
                chunk.truncate(read);
                out.extend_from_slice(&chunk);
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
            version: crate::config::CLIENTS_SCHEMA_VERSION,
            clients: vec![entry("vm-1", &["github"]), entry("vm-2", &["github"])],
        };
        let table = HashMap::try_from(file).unwrap();
        assert_eq!(table.len(), 2);
        let v1 = table.get("vm-1").unwrap();
        assert_eq!(v1.name, "vm-1");
        assert!(v1.providers.iter().any(|p| p == "github"));
    }

    #[test]
    fn build_clients_table_rejects_duplicate_name() {
        let file = ClientsFile {
            version: crate::config::CLIENTS_SCHEMA_VERSION,
            clients: vec![entry("vm-1", &["github"]), entry("vm-1", &["github"])],
        };
        let err = HashMap::try_from(file).unwrap_err();
        assert!(matches!(err, DaemonError::DuplicateClientName(n) if n == "vm-1"));
    }

    #[test]
    fn build_clients_table_empty_is_ok() {
        let file = ClientsFile {
            version: crate::config::CLIENTS_SCHEMA_VERSION,
            clients: vec![],
        };
        assert_eq!(HashMap::try_from(file).unwrap().len(), 0);
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
            r#"{"version":1,"clients":[{"name":"new","providers":["github"],"enrolled_at":"y","note":null}]}"#,
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
            providers: Vec::new(),
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
