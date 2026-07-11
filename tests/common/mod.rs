//! Shared test helpers across `tests/{github_provider, daemon, admin}.rs`.
//!
//! Lives under `tests/common/mod.rs` (NOT `tests/common.rs`) so
//! Cargo does not compile it as its own test binary.

// Each test binary compiles this whole file as a sibling crate and
// only uses a subset; `dead_code` suppresses the unused-helper noise
// per-test-binary, not in this file's own context.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use compio::BufResult;
use compio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use compio::net::{TcpStream, UnixStream};
use serde_json::Value;
use snow::TransportState;
use symbolon::transport::{self, MAX_MESSAGE_SIZE};
use symbolon::{
    AdminConfig, AppKeyBackend, BrokerPrivateKey, BrokerPublicKey, ClientsConfig, Config,
    GitHubProvider, JwtBackend, JwtBackendError, JwtClaims, JwtSigningKey, ListenConfig,
    LoggingConfig, MlockMode, ProviderGithub, Providers, RuntimeConfig, SandboxMode,
    SecurityConfig,
};
use wiremock::matchers::{body_bytes, method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// In-process signing backend for the wiremock provider tests: signs
/// with the fixture PEM directly. The real `file`/`tpm` backends move
/// the key out of process, but these tests exercise the HTTP/mint
/// logic, not signing — wiremock never validates the App JWT — so a
/// fast in-process signer keeps them subprocess-free. The real file
/// agent is exercised end-to-end in `tests/sign_agent.rs`.
struct InProcessBackend(JwtSigningKey);

#[async_trait::async_trait(?Send)]
impl JwtBackend for InProcessBackend {
    async fn sign(&self, claims: &JwtClaims) -> Result<String, JwtBackendError> {
        self.0
            .sign_rs256(claims)
            .map_err(|e| JwtBackendError::Rejected(e.to_string()))
    }
    async fn self_check(&self) -> Result<(), JwtBackendError> {
        Ok(())
    }
}

fn in_process_backend() -> Box<dyn JwtBackend> {
    let pem = std::fs::read(fixture_pem_path()).unwrap();
    Box::new(InProcessBackend(JwtSigningKey::from_pem(&pem).unwrap()))
}

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

/// Fixed broker static private key shared by every test daemon. Any
/// 32-byte value is a valid X25519 private key; a constant keeps the
/// matching public key derivable in test clients without plumbing.
pub const TEST_BROKER_PRIV: [u8; 32] = [7u8; 32];

pub fn test_broker_pub() -> BrokerPublicKey {
    BrokerPrivateKey::from(TEST_BROKER_PRIV).derive_public()
}

/// Write the broker static key file (64 hex chars) for a test daemon.
pub fn write_broker_key_file(path: &Path) {
    std::fs::write(path, hex::encode(TEST_BROKER_PRIV)).unwrap();
}

pub fn unique_id() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// File paths for one test daemon instance. All under the system temp dir,
/// unique per process+counter so parallel test workers don't collide.
/// `Drop` removes all three on scope exit, so a panicking test doesn't
/// leak temp files.
pub struct TempPaths {
    pub admin: PathBuf,
    pub clients: PathBuf,
    pub psks: PathBuf,
    pub broker_key: PathBuf,
}

impl Drop for TempPaths {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.admin);
        let _ = std::fs::remove_file(&self.clients);
        let _ = std::fs::remove_file(&self.psks);
        let _ = std::fs::remove_file(&self.broker_key);
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
        broker_key: t.join(format!("symbolon-test-{pid}-{id}-broker.key")),
    }
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

/// Request body for the metadata-only installation token POST that
/// precedes the `GET /repos/{owner}/{repo}` lookup. Must match the
/// inline literal in `src/providers/github.rs::mint_metadata_token_inner`
/// byte for byte.
pub fn canonical_metadata_token_body() -> Vec<u8> {
    br#"{"permissions":{"metadata":"read"}}"#.to_vec()
}

/// Placeholder token returned by `mount_metadata_token_ok`. The
/// resolve step uses it as a bearer for `GET /repos/...`; tests only
/// observe the narrow-mint token (`TOKEN`), so the value here is
/// arbitrary but visibly distinct.
pub const METADATA_TOKEN: &str = "ghs_metadata_only_xxxxxxxx";

/// Mount the metadata-only installation token POST that the resolve
/// step requires (`POST /app/installations/{id}/access_tokens` with
/// `{"permissions":{"metadata":"read"}}` body). Pair with
/// `mount_repo_ok` so the subsequent `GET /repos/{owner}/{repo}`
/// authenticates correctly.
pub async fn mount_metadata_token_ok(server: &MockServer) {
    Mock::given(method("POST"))
        .and(wm_path(mint_path()))
        .and(body_bytes(canonical_metadata_token_body()))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(
                serde_json::json!({"token": METADATA_TOKEN, "expires_at": EXPIRES_AT}),
            ),
        )
        .mount(server)
        .await;
}

pub async fn build_provider(api_base: String) -> GitHubProvider {
    build_provider_with_clock(api_base, SystemTime::now).await
}

/// Clock that returns a fixed past instant (2001-09-09T01:46:40Z,
/// Unix 1_000_000_000). Used in tests that need token-cache hits:
/// provider responses with `EXPIRES_AT` ("2026-05-31T13:00:00Z") are
/// in the future relative to this clock, so cached tokens remain valid.
pub fn past_clock() -> SystemTime {
    std::time::UNIX_EPOCH + Duration::from_secs(1_000_000_000)
}

pub async fn build_provider_with_clock(
    api_base: String,
    clock: fn() -> SystemTime,
) -> GitHubProvider {
    let cfg = ProviderGithub {
        host: "github.com".to_string(),
        api_base,
        client_id: CLIENT_ID.to_string(),
        installation_id: INSTALLATION_ID.into(),
        app_key_backend: AppKeyBackend::File,
        private_key_path: Some(fixture_pem_path()),
        tpm: None,
        selfcheck_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(10),
        user_agent: "symbolon".to_string(),
    };
    let cancel = compio::runtime::CancelToken::new();
    GitHubProvider::with_overrides(&cfg, in_process_backend(), cancel, None, clock).unwrap()
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
            static_key_file: paths.broker_key.clone(),
        },
        admin: AdminConfig {
            socket_path: paths.admin.clone(),
        },
        clients: ClientsConfig {
            file: paths.clients.clone(),
        },
        logging: LoggingConfig {
            level: tracing::Level::INFO,
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
                installation_id: INSTALLATION_ID.into(),
                app_key_backend: AppKeyBackend::File,
                private_key_path: Some(fixture_pem_path()),
                tpm: None,
                selfcheck_timeout: Duration::from_secs(5),
                request_timeout: Duration::from_secs(10),
                user_agent: "symbolon".to_string(),
            }),
        },
    }
}

/// Write a `clients.json` with the given enrolled identities.
pub fn write_clients_json(path: &Path, entries: &[&str]) {
    let entries_json: Vec<String> = entries
        .iter()
        .map(|name| {
            format!(
                r#"{{"name":"{name}","providers":["github"],"enrolled_at":"2026-05-31T00:00:00Z","note":null}}"#
            )
        })
        .collect();
    let body = format!(r#"{{"clients":[{}]}}"#, entries_json.join(","));
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

/// Connect to `addr` over TCP, run the NKpsk2 initiator handshake
/// (identity TLV as msg1 payload, PSK mixed at msg2), write `payload`
/// as a single encrypted Noise frame, read one encrypted response,
/// return the decrypted bytes.
pub async fn client_handshake_and_send(
    addr: SocketAddr,
    identity: &str,
    psk: [u8; 32],
    payload: &[u8],
) -> Vec<u8> {
    let identity = symbolon::Identity::parse(identity).expect("test identity must be valid");
    let psk = symbolon::Psk::from(psk);
    let mut stream = TcpStream::connect(addr).await.expect("tcp connect");
    let mut hs = transport::initiator(&psk, &test_broker_pub()).expect("build initiator");
    let mut scratch = vec![0u8; MAX_MESSAGE_SIZE];

    // -> e, es (identity TLV as encrypted payload)
    let tlv = transport::encode_identity_tlv(&identity);
    let n = transport::handshake_write(&mut hs, &tlv, &mut scratch).expect("hs write 1");
    let frame1 = transport::frame(&scratch[..n]).expect("frame 1");
    let BufResult(res, _) = stream.write_all(frame1).await;
    res.expect("write hs 1");

    // <- e, ee, psk
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
/// decrypted application-layer bytes (or an empty Vec on any failure
/// before the daemon emits a response). Use this from tests that
/// assert the daemon denied the session — under NKpsk2 that shows up
/// either as a dropped connection (malformed TLV) or as a handshake
/// that completes msg2 and then dies (unknown identity / wrong PSK:
/// this side fails to decrypt msg2, or the daemon fails to decrypt
/// the request frame — both land in the empty-Vec paths below).
pub async fn client_handshake_and_read_eof(
    addr: SocketAddr,
    identity: &str,
    psk: [u8; 32],
    payload: &[u8],
) -> Vec<u8> {
    let identity = match symbolon::Identity::parse(identity) {
        Ok(id) => id,
        Err(_) => return Vec::new(),
    };
    let psk = symbolon::Psk::from(psk);
    let mut stream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let mut hs = match transport::initiator(&psk, &test_broker_pub()) {
        Ok(h) => h,
        Err(_) => return Vec::new(),
    };
    let mut scratch = vec![0u8; MAX_MESSAGE_SIZE];

    // -> e, es (identity TLV as encrypted payload)
    let tlv = transport::encode_identity_tlv(&identity);
    let n = match transport::handshake_write(&mut hs, &tlv, &mut scratch) {
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

    // <- e, ee, psk (an unknown identity still gets a msg2 — built
    // against a random substitute PSK — so the failure here is the
    // decrypt, not the read).
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

async fn read_framed<R: AsyncRead>(stream: &mut R) -> Result<Vec<u8>, std::io::Error> {
    let mut len_buf = read_exact_n(stream, 2).await?;
    let arr: [u8; 2] = len_buf
        .as_slice()
        .try_into()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "len underflow"))?;
    let len = u16::from_be_bytes(arr) as usize;
    len_buf.clear();
    read_exact_n(stream, len).await
}

async fn read_exact_n<R: AsyncRead>(stream: &mut R, n: usize) -> Result<Vec<u8>, std::io::Error> {
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
    write_broker_key_file(&paths.broker_key);
    // Production uses LISTEN_FDS handoff via systemd/systemfd; tests
    // pre-bind here and feed the listeners through the test-only
    // `prepare_with_listeners` constructor. Env vars are process-global,
    // so we can't use the real listenfd path across parallel #[compio::test]
    // runtimes.
    let listener = compio::net::TcpListener::bind(&cfg.listen.bind)
        .await
        .expect("bind test TCP listener");
    let admin_listener = compio::net::UnixListener::bind(&cfg.admin.socket_path)
        .await
        .expect("bind test admin UDS");
    // Inject an in-process signing backend so the daemon under test
    // doesn't fork the real key subprocess (which would re-exec the
    // test harness). The real agent is covered in tests/sign_agent.rs.
    let signer = in_process_backend();
    compio::runtime::spawn(async move {
        let shutdown = compio::runtime::CancelToken::new();
        let service = symbolon::Service::prepare_with_listeners(
            &cfg,
            std::path::Path::new("/test/config.toml"),
            shutdown,
            listener,
            admin_listener,
            Some(signer),
        )
        .await
        .expect("prepare test service");
        let _ = service.run().await;
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
