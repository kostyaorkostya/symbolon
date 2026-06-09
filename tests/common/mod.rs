//! Shared test helpers across `tests/{github_provider, daemon, admin}.rs`.
//!
//! Lives under `tests/common/mod.rs` (NOT `tests/common.rs`) so
//! Cargo does not compile it as its own test binary.

#![allow(dead_code)] // each test file uses a subset of these helpers

use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use compio::BufResult;
use compio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use compio::net::UnixStream;
use gcb::{
    AdminConfig, ClientsConfig, Config, CpuWorker, GitHubProvider, ListenConfig, LogLevel,
    LoggingConfig, MlockMode, ProviderGithub, Providers, RuntimeConfig, SandboxMode,
    SecurityConfig, StunnelConfig,
};
use serde_json::Value;
use wiremock::matchers::{method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const CLIENT_ID: &str = "Iv1.test12345";
pub const INSTALLATION_ID: u64 = 789;
pub const OWNER: &str = "octocat";
pub const REPO: &str = "Hello-World";
pub const REPO_ID: u64 = 42;
pub const TOKEN: &str = "ghs_xxxxxxxxxxxxxxxxxxxx";
pub const EXPIRES_AT: &str = "2026-05-31T13:00:00Z";
pub const CLIENT_IP: &str = "192.168.122.10";

pub const PROXY_V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

pub fn fixture_pem_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test_app_key.pem")
}

pub fn unique_id() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

pub struct TempPaths {
    pub listen: PathBuf,
    pub admin: PathBuf,
    pub clients: PathBuf,
    pub psk: PathBuf,
    pub pidfile: PathBuf,
}

impl TempPaths {
    pub fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.listen);
        let _ = std::fs::remove_file(&self.admin);
        let _ = std::fs::remove_file(&self.clients);
        let _ = std::fs::remove_file(&self.psk);
        let _ = std::fs::remove_file(&self.pidfile);
    }
}

pub fn unique_paths_full() -> TempPaths {
    let id = unique_id();
    let pid = std::process::id();
    let t = std::env::temp_dir();
    TempPaths {
        listen: t.join(format!("gcb-test-{pid}-{id}.sock")),
        admin: t.join(format!("gcb-test-{pid}-{id}-admin.sock")),
        clients: t.join(format!("gcb-test-{pid}-{id}-clients.json")),
        psk: t.join(format!("gcb-test-{pid}-{id}-gcb.psk")),
        pidfile: t.join(format!("gcb-test-{pid}-{id}-stunnel.pid")),
    }
}

pub fn unique_paths() -> (PathBuf, PathBuf) {
    let p = unique_paths_full();
    (p.listen, p.clients)
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
        user_agent: "gcb".to_string(),
    };
    let key = GitHubProvider::load_key(&cfg).await.unwrap();
    let worker = Rc::new(CpuWorker::new("gcb-test-jwt-signer").unwrap());
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

pub fn build_config(socket_path: PathBuf, clients_path: PathBuf, api_base: String) -> Config {
    let id = unique_id();
    let pid = std::process::id();
    let t = std::env::temp_dir();
    Config {
        listen: ListenConfig {
            socket: socket_path,
        },
        admin: AdminConfig {
            socket_path: t.join(format!("gcb-test-{pid}-{id}-admin.sock")),
        },
        clients: ClientsConfig { file: clients_path },
        stunnel: StunnelConfig {
            psk_file: t.join(format!("gcb-test-{pid}-{id}-gcb.psk")),
            pidfile: t.join(format!("gcb-test-{pid}-{id}-stunnel.pid")),
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
                user_agent: "gcb".to_string(),
            }),
        },
    }
}

pub fn build_full_config(paths: &TempPaths, api_base: String) -> Config {
    Config {
        listen: ListenConfig {
            socket: paths.listen.clone(),
        },
        admin: AdminConfig {
            socket_path: paths.admin.clone(),
        },
        clients: ClientsConfig {
            file: paths.clients.clone(),
        },
        stunnel: StunnelConfig {
            psk_file: paths.psk.clone(),
            pidfile: paths.pidfile.clone(),
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
                user_agent: "gcb".to_string(),
            }),
        },
    }
}

pub fn write_clients_json(path: &Path, entries: &[(&str, &str)]) {
    let entries_json: Vec<String> = entries
        .iter()
        .map(|(name, ip)| {
            format!(
                r#"{{"name":"{name}","ip":"{ip}","providers":["github"],"enrolled_at":"2026-05-31T00:00:00Z","note":null}}"#
            )
        })
        .collect();
    let body = format!(r#"{{"version":1,"clients":[{}]}}"#, entries_json.join(","));
    std::fs::write(path, body).unwrap();
}

pub fn build_proxy_v4(src: [u8; 4]) -> Vec<u8> {
    let mut buf = PROXY_V2_SIGNATURE.to_vec();
    buf.push(0x21); // version 2, command PROXY
    buf.push(0x11); // TCP/IPv4
    buf.extend_from_slice(&12u16.to_be_bytes()); // address-block length
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&[10, 0, 0, 1]); // dst IP
    buf.extend_from_slice(&[0x12, 0x34]); // src port
    buf.extend_from_slice(&[0x56, 0x78]); // dst port
    buf
}

pub async fn wait_for_socket(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        compio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("socket {} did not appear within 1s", path.display());
}

pub async fn send_and_read_all(socket_path: &Path, payload: Vec<u8>) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket_path).await.unwrap();
    let BufResult(write_res, _) = stream.write_all(payload).await;
    write_res.unwrap();
    let _ = stream.flush().await;
    let mut response = Vec::new();
    loop {
        let chunk = Vec::with_capacity(1024);
        let BufResult(res, chunk) = stream.read(chunk).await;
        match res {
            Ok(0) => break,
            Ok(_) => response.extend_from_slice(&chunk),
            Err(_) => break,
        }
    }
    response
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

pub async fn spawn_daemon(paths: &TempPaths, api_base: String) {
    let cfg = build_full_config(paths, api_base);
    compio::runtime::spawn(async move {
        let _ = gcb::run_daemon(&cfg, std::path::Path::new("/test/config.toml")).await;
    })
    .detach();
    wait_for_socket(&paths.admin).await;
}
