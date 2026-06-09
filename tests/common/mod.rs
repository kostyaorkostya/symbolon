//! Shared test helpers across `tests/{github_provider, daemon, admin}.rs`.
//!
//! Lives under `tests/common/mod.rs` (NOT `tests/common.rs`) so
//! Cargo does not compile it as its own test binary.

#![allow(dead_code)] // each test file uses a subset of these helpers

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use compio::BufResult;
use compio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use compio::net::{TcpStream, UnixStream};
use serde_json::Value;
use snow::TransportState;
use symbolon::transport::{self, MAX_MESSAGE_SIZE};
use symbolon::{
    AdminConfig, ClientsConfig, Config, CpuWorker, GitHubProvider, ListenConfig, LogLevel,
    LoggingConfig, MlockMode, ProviderGithub, Providers, RuntimeConfig, SandboxMode,
    SecurityConfig,
};
use wiremock::matchers::{method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const CLIENT_ID: &str = "Iv1.test12345";
pub const INSTALLATION_ID: u64 = 789;
pub const OWNER: &str = "octocat";
pub const REPO: &str = "Hello-World";
pub const REPO_ID: u64 = 42;
pub const TOKEN: &str = "ghs_xxxxxxxxxxxxxxxxxxxx";
pub const EXPIRES_AT: &str = "2026-05-31T13:00:00Z";

pub fn fixture_pem_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test_app_key.pem")
}

pub fn unique_id() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// File paths for one test daemon instance. All under the system temp dir,
/// unique per process+counter so parallel test workers don't collide.
pub struct TempPaths {
    pub admin: PathBuf,
    pub clients: PathBuf,
    pub psks: PathBuf,
}

impl TempPaths {
    pub fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.admin);
        let _ = std::fs::remove_file(&self.clients);
        let _ = std::fs::remove_file(&self.psks);
    }
}

pub fn unique_paths_full() -> TempPaths {
    let id = unique_id();
    let pid = std::process::id();
    let t = std::env::temp_dir();
    TempPaths {
        admin: t.join(format!("symbolon-test-{pid}-{id}-admin.sock")),
        clients: t.join(format!("symbolon-test-{pid}-{id}-clients.json")),
        psks: t.join(format!("symbolon-test-{pid}-{id}-psks")),
    }
}

/// Backwards-compatible shim for tests that previously took (listen, clients).
/// Returns (clients_path, psks_path).
pub fn unique_paths() -> (PathBuf, PathBuf) {
    let p = unique_paths_full();
    (p.clients, p.psks)
}

pub fn repo_path() -> String {
    format!("/repos/{OWNER}/{REPO}")
}

pub fn mint_path() -> String {
    format!("/app/installations/{INSTALLATION_ID}/access_tokens")
}

pub fn canonical_mint_body() -> Vec<u8> {
    format!(
        r#"{{"repository_ids":[{REPO_ID}],"permissions":{{"contents":"write","metadata":"read"}}}}"#
    )
    .into_bytes()
}

pub async fn build_provider(api_base: String) -> GitHubProvider {
    let cfg = ProviderGithub {
        host: "github.com".to_string(),
        api_base,
        client_id: CLIENT_ID.to_string(),
        installation_id: INSTALLATION_ID,
        private_key_path: fixture_pem_path(),
        selfcheck_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(10),
        user_agent: "symbolon".to_string(),
    };
    let key = GitHubProvider::load_key(&cfg).await.unwrap();
    let worker = Rc::new(CpuWorker::new("symbolon-test-jwt-signer").unwrap());
    let cancel = compio::runtime::CancelToken::new();
    GitHubProvider::with_overrides(&cfg, key, worker, cancel, None, SystemTime::now).unwrap()
}

pub async fn mount_repo_ok(server: &MockServer) {
    Mock::given(method("GET"))
        .and(wm_path(repo_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": REPO_ID})))
        .mount(server)
        .await;
}

pub async fn mount_mint_ok(server: &MockServer) {
    Mock::given(method("POST"))
        .and(wm_path(mint_path()))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(serde_json::json!({"token": TOKEN, "expires_at": EXPIRES_AT})),
        )
        .mount(server)
        .await;
}

/// Build a daemon `Config` for a test instance. Picks an ephemeral
/// TCP port via `:0` so the OS assigns; the caller should then read
/// the assigned port back from `Service::prepare`'s log or the
/// listener once the daemon has started.
pub fn build_full_config(paths: &TempPaths, api_base: String, bind: SocketAddr) -> Config {
    Config {
        listen: ListenConfig {
            bind,
            psk_file: paths.psks.clone(),
        },
        admin: AdminConfig {
            socket_path: paths.admin.clone(),
        },
        clients: ClientsConfig {
            file: paths.clients.clone(),
        },
        logging: LoggingConfig {
            level: LogLevel::Info,
        },
        security: SecurityConfig {
            sandbox: SandboxMode::Off,
            extra_read_dirs: vec![],
            mlock: MlockMode::Off,
        },
        runtime: RuntimeConfig::default(),
        provider: Providers {
            github: Some(ProviderGithub {
                host: "github.com".to_string(),
                api_base,
                client_id: CLIENT_ID.to_string(),
                installation_id: INSTALLATION_ID,
                private_key_path: fixture_pem_path(),
                selfcheck_timeout: Duration::from_secs(5),
                request_timeout: Duration::from_secs(10),
                user_agent: "symbolon".to_string(),
            }),
        },
    }
}

/// Older config shape (no explicit bind). Kept for tests that just need a
/// daemon Config but won't actually exercise the listen path.
pub fn build_config(_unused: PathBuf, clients_path: PathBuf, api_base: String) -> Config {
    // Use a fresh paths bundle so unrelated tests don't share files.
    let paths = TempPaths {
        admin: std::env::temp_dir().join(format!("symbolon-cfg-{}-admin.sock", unique_id())),
        clients: clients_path,
        psks: std::env::temp_dir().join(format!("symbolon-cfg-{}-psks", unique_id())),
    };
    build_full_config(
        &paths,
        api_base,
        // 127.0.0.1:0 → OS-assigned ephemeral port; the test that uses this
        // shape (`tests/daemon.rs`) reads the assigned port via the daemon's
        // own logs or its accept-side bookkeeping.
        "127.0.0.1:0".parse().unwrap(),
    )
}

/// Write a `clients.json` (schema v2) with the given enrolled identities.
pub fn write_clients_json(path: &Path, entries: &[&str]) {
    let entries_json: Vec<String> = entries
        .iter()
        .map(|name| {
            format!(
                r#"{{"name":"{name}","providers":["github"],"enrolled_at":"2026-05-31T00:00:00Z","note":null}}"#
            )
        })
        .collect();
    let body = format!(r#"{{"version":2,"clients":[{}]}}"#, entries_json.join(","));
    std::fs::write(path, body).unwrap();
}

/// Write a `psks` file (`identity:hex_psk` per line).
pub fn write_psks_file(path: &Path, entries: &[(&str, [u8; 32])]) {
    let mut body = String::new();
    for (id, psk) in entries {
        body.push_str(id);
        body.push(':');
        for b in psk {
            body.push_str(&format!("{b:02x}"));
        }
        body.push('\n');
    }
    std::fs::write(path, body).unwrap();
}

/// Wait until `path` shows up on disk (Unix-socket bind, etc.). Useful right
/// after spawning the daemon to avoid racing the admin loop's first accept.
pub async fn wait_for_socket(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        compio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("socket {} did not appear within 1s", path.display());
}

/// Connect to `addr` over TCP, run the NNpsk0 initiator handshake with
/// `psk` + identity prelude, write `payload` as a single encrypted Noise
/// frame, read one encrypted response, return the decrypted bytes.
pub async fn client_handshake_and_send(
    addr: SocketAddr,
    identity: &str,
    psk: [u8; 32],
    payload: &[u8],
) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).await.expect("tcp connect");
    let prelude = transport::encode_prelude(identity).expect("encode prelude");
    let BufResult(res, _) = stream.write_all(prelude).await;
    res.expect("write prelude");

    let mut hs = transport::initiator(&psk).expect("build initiator");
    let mut scratch = vec![0u8; MAX_MESSAGE_SIZE];

    // -> psk, e
    let n = transport::handshake_write(&mut hs, &[], &mut scratch).expect("hs write 1");
    let frame1 = transport::frame(&scratch[..n]).expect("frame 1");
    let BufResult(res, _) = stream.write_all(frame1).await;
    res.expect("write hs 1");

    // <- e, ee
    let frame2 = read_framed(&mut stream).await.expect("read hs 2");
    let _ = transport::handshake_read(&mut hs, &frame2, &mut scratch).expect("hs read 2");

    let mut ts: TransportState = transport::into_transport(hs).expect("into transport");

    let n = transport::transport_write(&mut ts, payload, &mut scratch).expect("encrypt");
    let framed_req = transport::frame(&scratch[..n]).expect("frame req");
    let BufResult(res, _) = stream.write_all(framed_req).await;
    res.expect("write req");
    let _ = stream.flush().await;

    let resp_frame = read_framed(&mut stream).await.expect("read resp");
    let n = transport::transport_read(&mut ts, &resp_frame, &mut scratch).expect("decrypt");
    scratch[..n].to_vec()
}

/// Variant of `client_handshake_and_send` that returns ONLY the
/// decrypted application-layer bytes (or an empty Vec on EOF before
/// the daemon emits a response). Use this from tests that assert the
/// daemon dropped the connection after processing the encrypted
/// request.
///
/// Walks the full state machine: prelude → handshake (in + out) →
/// encrypted request → attempt to read encrypted response. If the
/// daemon dropped the socket before sending anything decryptable, we
/// return an empty Vec.
pub async fn client_handshake_and_read_eof(
    addr: SocketAddr,
    identity: &str,
    psk: [u8; 32],
    payload: &[u8],
) -> Vec<u8> {
    let mut stream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let prelude = match transport::encode_prelude(identity) {
        Some(p) => p,
        None => return Vec::new(),
    };
    let BufResult(res, _) = stream.write_all(prelude).await;
    if res.is_err() {
        return Vec::new();
    }

    let mut hs = match transport::initiator(&psk) {
        Ok(h) => h,
        Err(_) => return Vec::new(),
    };
    let mut scratch = vec![0u8; MAX_MESSAGE_SIZE];

    // -> psk, e
    let n = match transport::handshake_write(&mut hs, &[], &mut scratch) {
        Ok(n) => n,
        Err(_) => return Vec::new(),
    };
    let framed = match transport::frame(&scratch[..n]) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let BufResult(res, _) = stream.write_all(framed).await;
    if res.is_err() {
        return Vec::new();
    }

    // <- e, ee (server may have closed if PSK lookup / identity check
    // failed before getting here; read_framed then returns Err and we
    // bail with empty Vec).
    let reply = match read_framed(&mut stream).await {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    if transport::handshake_read(&mut hs, &reply, &mut scratch).is_err() {
        return Vec::new();
    }

    let mut ts = match transport::into_transport(hs) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };

    // Encrypt and send the (possibly malformed) request.
    let n = match transport::transport_write(&mut ts, payload, &mut scratch) {
        Ok(n) => n,
        Err(_) => return Vec::new(),
    };
    let framed_req = match transport::frame(&scratch[..n]) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let BufResult(res, _) = stream.write_all(framed_req).await;
    if res.is_err() {
        return Vec::new();
    }
    let _ = stream.flush().await;

    // Try to read + decrypt a response. EOF → empty Vec.
    let resp_frame = match read_framed(&mut stream).await {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    match transport::transport_read(&mut ts, &resp_frame, &mut scratch) {
        Ok(n) => scratch[..n].to_vec(),
        Err(_) => Vec::new(),
    }
}

async fn read_framed(stream: &mut TcpStream) -> Result<Vec<u8>, std::io::Error> {
    let mut len_buf = read_exact_n(stream, 2).await?;
    let arr: [u8; 2] = len_buf
        .as_slice()
        .try_into()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "len underflow"))?;
    let len = u16::from_be_bytes(arr) as usize;
    len_buf.clear();
    read_exact_n(stream, len).await
}

async fn read_exact_n(stream: &mut TcpStream, n: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut out: Vec<u8> = Vec::with_capacity(n);
    while out.len() < n {
        let remaining = n - out.len();
        let buf = Vec::with_capacity(remaining);
        let BufResult(res, mut filled) = stream.read(buf).await;
        let read = res?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof",
            ));
        }
        filled.truncate(read);
        out.extend_from_slice(&filled);
    }
    Ok(out)
}

pub async fn admin_request(admin_socket: &Path, request: Value) -> Value {
    let mut stream = UnixStream::connect(admin_socket).await.unwrap();
    let mut bytes = serde_json::to_vec(&request).unwrap();
    bytes.push(b'\n');
    let BufResult(write_res, _) = stream.write_all(bytes).await;
    write_res.unwrap();
    let _ = stream.flush().await;
    let mut accumulated = Vec::new();
    loop {
        let chunk = Vec::with_capacity(4096);
        let BufResult(res, chunk) = stream.read(chunk).await;
        match res {
            Ok(0) => break,
            Ok(_) => accumulated.extend_from_slice(&chunk),
            Err(_) => break,
        }
    }
    let line = accumulated
        .split(|&b| b == b'\n')
        .next()
        .unwrap_or(&[])
        .to_vec();
    serde_json::from_slice(&line).unwrap()
}

/// Spawn a daemon with the given config; wait until the admin socket appears.
/// Returns once the daemon is ready to accept admin commands.
pub async fn spawn_daemon(paths: &TempPaths, api_base: String) {
    spawn_daemon_with_bind(paths, api_base, "127.0.0.1:0".parse().unwrap()).await
}

pub async fn spawn_daemon_with_bind(paths: &TempPaths, api_base: String, bind: SocketAddr) {
    let cfg = build_full_config(paths, api_base, bind);
    compio::runtime::spawn(async move {
        let _ = symbolon::run_daemon(&cfg, std::path::Path::new("/test/config.toml")).await;
    })
    .detach();
    wait_for_socket(&paths.admin).await;
}

/// Bind a throw-away TCP listener on the loopback to discover a free
/// ephemeral port, drop the listener, and return the address. There's
/// a small race window between drop and the daemon's bind in which
/// another process could grab the port; in test loops this is fine.
pub fn pick_free_loopback_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);
    addr
}

/// Wait until a TCP listener is accepting on `addr`. Used after spawning
/// the daemon so the test client doesn't race the bind syscall.
pub async fn wait_for_tcp(addr: SocketAddr) {
    for _ in 0..200 {
        match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(50)) {
            Ok(_) => return,
            Err(_) => compio::time::sleep(Duration::from_millis(5)).await,
        }
    }
    panic!("daemon TCP listener {addr} did not come up within 1s");
}
