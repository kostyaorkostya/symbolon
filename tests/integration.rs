//! Integration tests: `GitHubProvider` against a `wiremock` server.
//!
//! Each test starts its own `MockServer`; wiremock runs a tokio
//! runtime in a sidecar thread, the cyper request loops in compio
//! on the test thread, and they meet over a localhost TCP port.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use gcb::config::ProviderGithub;
use gcb::providers::github::{GitHubProvider, GithubError};

use serde_json::json;
use wiremock::matchers::{body_bytes, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const APP_ID: u64 = 12345;
const INSTALLATION_ID: u64 = 789;
const OWNER: &str = "octocat";
const REPO: &str = "Hello-World";
const REPO_ID: u64 = 42;
const TOKEN: &str = "ghs_xxxxxxxxxxxxxxxxxxxx";
const EXPIRES_AT: &str = "2026-05-31T13:00:00Z";

fn fixture_pem_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test_app_key.pem")
}

fn build_provider(api_base: String) -> GitHubProvider {
    let cfg = ProviderGithub {
        host: "github.com".to_string(),
        api_base,
        app_id: APP_ID,
        installation_id: INSTALLATION_ID,
        private_key_path: fixture_pem_path(),
    };
    GitHubProvider::with_overrides(&cfg, None, SystemTime::now).unwrap()
}

fn repo_path() -> String {
    format!("/repos/{OWNER}/{REPO}")
}

fn mint_path() -> String {
    format!("/app/installations/{INSTALLATION_ID}/access_tokens")
}

fn canonical_mint_body() -> Vec<u8> {
    format!(
        r#"{{"repository_ids":[{REPO_ID}],"permissions":{{"contents":"write","metadata":"read"}}}}"#
    )
    .into_bytes()
}

async fn mount_repo_ok(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(repo_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": REPO_ID})))
        .mount(server)
        .await;
}

async fn mount_mint_ok(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"token": TOKEN, "expires_at": EXPIRES_AT})),
        )
        .mount(server)
        .await;
}

#[compio::test]
async fn mint_happy_path() {
    let server = MockServer::start().await;
    mount_repo_ok(&server).await;
    mount_mint_ok(&server).await;

    let provider = build_provider(server.uri());
    let outcome = provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();

    assert_eq!(outcome.response.username, "x-access-token");
    assert_eq!(outcome.response.password, TOKEN);
    assert_eq!(outcome.repo_id, REPO_ID);
    let secs = outcome
        .response
        .password_expiry_utc
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // 2026-05-31T13:00:00Z = 1780232400
    assert_eq!(secs, 1_780_232_400);
}

#[compio::test]
async fn mint_uses_cached_repo_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(repo_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": REPO_ID})))
        .expect(1) // GET must be called exactly once across both mints
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"token": TOKEN, "expires_at": EXPIRES_AT})),
        )
        .expect(2)
        .mount(&server)
        .await;

    let provider = build_provider(server.uri());
    provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();
    provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();
    // MockServer's drop verifies `.expect(N)` counts.
}

#[compio::test]
async fn mint_request_headers_and_body_exact() {
    let server = MockServer::start().await;
    mount_repo_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .and(header("Accept", "application/vnd.github+json"))
        .and(header("X-GitHub-Api-Version", "2022-11-28"))
        .and(header(
            "User-Agent",
            concat!("gcb/", env!("CARGO_PKG_VERSION")),
        ))
        .and(header("Content-Type", "application/json"))
        .and(body_bytes(canonical_mint_body()))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"token": TOKEN, "expires_at": EXPIRES_AT})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(server.uri());
    provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();
}

#[compio::test]
async fn resolve_returns_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(repo_path()))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let provider = build_provider(server.uri());
    let err = provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap_err();
    assert!(
        matches!(err, GithubError::RepoNotFound { ref path } if path == &format!("{OWNER}/{REPO}"))
    );
}

#[compio::test]
async fn mint_returns_401() {
    let server = MockServer::start().await;
    mount_repo_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let provider = build_provider(server.uri());
    assert!(matches!(
        provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap_err(),
        GithubError::Unauthorized
    ));
}

#[compio::test]
async fn mint_returns_403() {
    let server = MockServer::start().await;
    mount_repo_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let provider = build_provider(server.uri());
    assert!(matches!(
        provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap_err(),
        GithubError::Forbidden
    ));
}

#[compio::test]
async fn mint_returns_429() {
    let server = MockServer::start().await;
    mount_repo_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;

    let provider = build_provider(server.uri());
    assert!(matches!(
        provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap_err(),
        GithubError::RateLimited
    ));
}

#[compio::test]
async fn mint_returns_500() {
    let server = MockServer::start().await;
    mount_repo_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let provider = build_provider(server.uri());
    assert!(matches!(
        provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap_err(),
        GithubError::ServerError(500)
    ));
}

#[compio::test]
async fn mint_invalidates_on_404() {
    let server = MockServer::start().await;

    // The GET resolver is always available — we expect it to be hit
    // exactly twice (once for the first successful mint, once again
    // after the 404-driven cache invalidation forces a re-resolve).
    Mock::given(method("GET"))
        .and(path(repo_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": REPO_ID})))
        .expect(2)
        .mount(&server)
        .await;

    // First POST: success. Use a scoped mock so we can remove it.
    let first_post = Mock::given(method("POST"))
        .and(path(mint_path()))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"token": TOKEN, "expires_at": EXPIRES_AT})),
        )
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    let provider = build_provider(server.uri());
    provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();

    drop(first_post);

    // Second POST: 404 (repo deleted/recreated).
    let second_post = Mock::given(method("POST"))
        .and(path(mint_path()))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    let err = provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap_err();
    assert!(matches!(err, GithubError::RepoNotFound { .. }));

    drop(second_post);

    // Third POST: succeeds again; GET must fire again because the
    // 404 invalidated the cached repo-id.
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"token": TOKEN, "expires_at": EXPIRES_AT})),
        )
        .expect(1)
        .mount(&server)
        .await;

    provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();
    // Drop of `server` at end of test verifies all `.expect(N)` counts.
}

// =====================================================================
// Daemon end-to-end tests
// =====================================================================

mod daemon_e2e {
    use super::*;

    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use compio::BufResult;
    use compio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
    use compio::net::UnixStream;
    use gcb::config::{
        AdminConfig, ClientsConfig, Config, ListenConfig, LogLevel, LoggingConfig, Providers,
        SandboxMode, SecurityConfig, StunnelConfig,
    };

    const PROXY_V2_SIGNATURE: [u8; 12] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];
    const CLIENT_IP: &str = "192.168.122.10";

    fn unique_id() -> u64 {
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

    fn unique_paths() -> (PathBuf, PathBuf) {
        let p = unique_paths_full();
        (p.listen, p.clients)
    }

    fn write_clients_json(path: &Path, entries: &[(&str, &str)]) {
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

    fn build_config(socket_path: PathBuf, clients_path: PathBuf, api_base: String) -> Config {
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
            },
            provider: Providers {
                github: Some(ProviderGithub {
                    host: "github.com".to_string(),
                    api_base,
                    app_id: APP_ID,
                    installation_id: INSTALLATION_ID,
                    private_key_path: fixture_pem_path(),
                }),
            },
        }
    }

    fn build_proxy_v4(src: [u8; 4]) -> Vec<u8> {
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

    async fn wait_for_socket(path: &Path) {
        for _ in 0..200 {
            if path.exists() {
                return;
            }
            compio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("socket {} did not appear within 1s", path.display());
    }

    async fn send_and_read_all(socket_path: &Path, payload: Vec<u8>) -> Vec<u8> {
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

    #[compio::test]
    async fn daemon_happy_path() {
        let (socket_path, clients_path) = unique_paths();
        write_clients_json(&clients_path, &[("vm-1", CLIENT_IP)]);
        let server = MockServer::start().await;
        mount_repo_ok(&server).await;
        mount_mint_ok(&server).await;
        let cfg = build_config(socket_path.clone(), clients_path.clone(), server.uri());

        compio::runtime::spawn(async move {
            let _ = gcb::daemon::run(&cfg, std::path::Path::new("/test/config.toml")).await;
        })
        .detach();
        wait_for_socket(&socket_path).await;

        let mut payload = build_proxy_v4([192, 168, 122, 10]);
        payload.extend_from_slice(
            format!("protocol=https\nhost=github.com\npath={OWNER}/{REPO}\n\n").as_bytes(),
        );
        let resp = send_and_read_all(&socket_path, payload).await;
        let body = std::str::from_utf8(&resp).unwrap();
        assert!(
            body.contains(&format!("password={TOKEN}\n")),
            "response: {body:?}"
        );
        assert!(body.starts_with("username=x-access-token\n"));

        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_file(&clients_path);
    }

    #[compio::test]
    async fn daemon_rejects_unknown_client_ip() {
        let (socket_path, clients_path) = unique_paths();
        write_clients_json(&clients_path, &[("vm-1", CLIENT_IP)]);
        let server = MockServer::start().await;
        let cfg = build_config(socket_path.clone(), clients_path.clone(), server.uri());

        compio::runtime::spawn(async move {
            let _ = gcb::daemon::run(&cfg, std::path::Path::new("/test/config.toml")).await;
        })
        .detach();
        wait_for_socket(&socket_path).await;

        let mut payload = build_proxy_v4([10, 0, 0, 99]); // not in clients.json
        payload.extend_from_slice(
            format!("protocol=https\nhost=github.com\npath={OWNER}/{REPO}\n\n").as_bytes(),
        );
        let resp = send_and_read_all(&socket_path, payload).await;
        assert!(resp.is_empty(), "expected EOF, got: {resp:?}");

        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_file(&clients_path);
    }

    #[compio::test]
    async fn daemon_rejects_unknown_host() {
        let (socket_path, clients_path) = unique_paths();
        write_clients_json(&clients_path, &[("vm-1", CLIENT_IP)]);
        let server = MockServer::start().await;
        let cfg = build_config(socket_path.clone(), clients_path.clone(), server.uri());

        compio::runtime::spawn(async move {
            let _ = gcb::daemon::run(&cfg, std::path::Path::new("/test/config.toml")).await;
        })
        .detach();
        wait_for_socket(&socket_path).await;

        let mut payload = build_proxy_v4([192, 168, 122, 10]);
        payload.extend_from_slice(b"protocol=https\nhost=evil.example\npath=foo/bar\n\n");
        let resp = send_and_read_all(&socket_path, payload).await;
        assert!(resp.is_empty(), "expected EOF, got: {resp:?}");

        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_file(&clients_path);
    }

    #[compio::test]
    async fn daemon_rejects_malformed_request() {
        let (socket_path, clients_path) = unique_paths();
        write_clients_json(&clients_path, &[("vm-1", CLIENT_IP)]);
        let server = MockServer::start().await;
        let cfg = build_config(socket_path.clone(), clients_path.clone(), server.uri());

        compio::runtime::spawn(async move {
            let _ = gcb::daemon::run(&cfg, std::path::Path::new("/test/config.toml")).await;
        })
        .detach();
        wait_for_socket(&socket_path).await;

        // Missing `path=` line.
        let mut payload = build_proxy_v4([192, 168, 122, 10]);
        payload.extend_from_slice(b"protocol=https\nhost=github.com\n\n");
        let resp = send_and_read_all(&socket_path, payload).await;
        assert!(resp.is_empty(), "expected EOF, got: {resp:?}");

        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_file(&clients_path);
    }
}

// =====================================================================
// Admin end-to-end tests
// =====================================================================

mod admin_e2e {
    use super::daemon_e2e::{TempPaths, unique_paths_full};
    use super::*;

    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::Duration;

    use compio::BufResult;
    use compio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
    use compio::net::UnixStream;
    use gcb::config::{
        AdminConfig, ClientsConfig, Config, ListenConfig, LogLevel, LoggingConfig, Providers,
        SandboxMode, SecurityConfig, StunnelConfig,
    };
    use serde_json::Value;

    fn build_full_config(paths: &TempPaths, api_base: String) -> Config {
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
            },
            provider: Providers {
                github: Some(ProviderGithub {
                    host: "github.com".to_string(),
                    api_base,
                    app_id: APP_ID,
                    installation_id: INSTALLATION_ID,
                    private_key_path: fixture_pem_path(),
                }),
            },
        }
    }

    fn write_clients_json(path: &Path, entries: &[(&str, &str)]) {
        let entries_json: Vec<String> = entries.iter().map(|(name, ip)| {
            format!(r#"{{"name":"{name}","ip":"{ip}","providers":["github"],"enrolled_at":"2026-05-31T00:00:00Z","note":null}}"#)
        }).collect();
        let body = format!(r#"{{"version":1,"clients":[{}]}}"#, entries_json.join(","));
        std::fs::write(path, body).unwrap();
    }

    async fn wait_for_socket(path: &Path) {
        for _ in 0..200 {
            if path.exists() {
                return;
            }
            compio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("socket {} did not appear within 1s", path.display());
    }

    async fn admin_request(admin_socket: &Path, request: Value) -> Value {
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

    async fn spawn_daemon(paths: &TempPaths, api_base: String) {
        let cfg = build_full_config(paths, api_base);
        compio::runtime::spawn(async move {
            let _ = gcb::daemon::run(&cfg, std::path::Path::new("/test/config.toml")).await;
        })
        .detach();
        wait_for_socket(&paths.admin).await;
    }

    #[compio::test]
    async fn admin_status_reports_uptime_and_provider_count() {
        let paths = unique_paths_full();
        write_clients_json(&paths.clients, &[]);
        let server = MockServer::start().await;
        spawn_daemon(&paths, server.uri()).await;

        let resp = admin_request(&paths.admin, serde_json::json!({"op": "status"})).await;
        assert_eq!(resp["ok"], serde_json::json!(true));
        assert_eq!(resp["client_count"], 0);
        assert_eq!(resp["providers"], serde_json::json!(["github.com"]));
        paths.cleanup();
    }

    #[compio::test]
    async fn admin_list_initially_empty() {
        let paths = unique_paths_full();
        write_clients_json(&paths.clients, &[]);
        let server = MockServer::start().await;
        spawn_daemon(&paths, server.uri()).await;

        let resp = admin_request(&paths.admin, serde_json::json!({"op": "list"})).await;
        assert_eq!(resp["ok"], serde_json::json!(true));
        assert!(resp["clients"].as_array().unwrap().is_empty());
        paths.cleanup();
    }

    #[compio::test]
    async fn admin_enroll_persists_to_clients_json_and_psk_file() {
        let paths = unique_paths_full();
        write_clients_json(&paths.clients, &[]);
        let server = MockServer::start().await;
        spawn_daemon(&paths, server.uri()).await;

        let resp = admin_request(
            &paths.admin,
            serde_json::json!({
                "op": "enroll",
                "provider": "github",
                "client": "vm-1",
                "ip": "192.168.122.10",
                "note": null,
            }),
        )
        .await;
        assert_eq!(resp["ok"], serde_json::json!(true));
        let psk_hex = resp["psk_hex"].as_str().unwrap();
        assert_eq!(psk_hex.len(), 64);
        assert!(psk_hex.chars().all(|c| c.is_ascii_hexdigit()));

        // Verify gcb.psk content + mode.
        let psk_text = std::fs::read_to_string(&paths.psk).unwrap();
        assert!(
            psk_text.starts_with(&format!("vm-1:{psk_hex}")),
            "got: {psk_text:?}"
        );
        let psk_mode = std::fs::metadata(&paths.psk).unwrap().permissions().mode() & 0o777;
        assert_eq!(psk_mode, 0o600);

        // Verify clients.json content + mode.
        let clients_text = std::fs::read_to_string(&paths.clients).unwrap();
        assert!(clients_text.contains("\"name\": \"vm-1\""));
        assert!(clients_text.contains("\"192.168.122.10\""));
        let cl_mode = std::fs::metadata(&paths.clients)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(cl_mode, 0o640);

        // Verify in-memory state via `list`.
        let listed = admin_request(&paths.admin, serde_json::json!({"op": "list"})).await;
        assert_eq!(listed["clients"].as_array().unwrap().len(), 1);

        paths.cleanup();
    }

    #[compio::test]
    async fn admin_enroll_appends_without_clobbering_existing() {
        let paths = unique_paths_full();
        write_clients_json(&paths.clients, &[("vm-0", "192.168.122.9")]);
        // Pre-seed psk file with one entry.
        std::fs::write(&paths.psk, "vm-0:0123abcd\n").unwrap();
        let server = MockServer::start().await;
        spawn_daemon(&paths, server.uri()).await;

        let resp = admin_request(
            &paths.admin,
            serde_json::json!({
                "op": "enroll",
                "provider": "github",
                "client": "vm-1",
                "ip": "192.168.122.10",
                "note": null,
            }),
        )
        .await;
        assert_eq!(resp["ok"], serde_json::json!(true));

        let psk_text = std::fs::read_to_string(&paths.psk).unwrap();
        assert!(
            psk_text.contains("vm-0:0123abcd"),
            "lost pre-existing entry: {psk_text}"
        );
        assert!(psk_text.contains("vm-1:"), "missing new entry: {psk_text}");

        paths.cleanup();
    }

    #[compio::test]
    async fn admin_enroll_rejects_duplicate_client_name() {
        let paths = unique_paths_full();
        write_clients_json(&paths.clients, &[("vm-1", "192.168.122.10")]);
        let server = MockServer::start().await;
        spawn_daemon(&paths, server.uri()).await;

        let resp = admin_request(
            &paths.admin,
            serde_json::json!({
                "op": "enroll",
                "provider": "github",
                "client": "vm-1",
                "ip": "192.168.122.20",
                "note": null,
            }),
        )
        .await;
        assert_eq!(resp["ok"], serde_json::json!(false));
        assert_eq!(resp["code"], "client_already_enrolled");
        paths.cleanup();
    }

    #[compio::test]
    async fn admin_enroll_rejects_duplicate_ip() {
        let paths = unique_paths_full();
        write_clients_json(&paths.clients, &[("vm-1", "192.168.122.10")]);
        let server = MockServer::start().await;
        spawn_daemon(&paths, server.uri()).await;

        let resp = admin_request(
            &paths.admin,
            serde_json::json!({
                "op": "enroll",
                "provider": "github",
                "client": "vm-2",
                "ip": "192.168.122.10",
                "note": null,
            }),
        )
        .await;
        assert_eq!(resp["ok"], serde_json::json!(false));
        assert_eq!(resp["code"], "client_ip_collision");
        paths.cleanup();
    }

    #[compio::test]
    async fn admin_revoke_removes_psk_entry_and_updates_clients() {
        let paths = unique_paths_full();
        write_clients_json(&paths.clients, &[]);
        let server = MockServer::start().await;
        spawn_daemon(&paths, server.uri()).await;

        // Enroll, then revoke.
        let enroll = admin_request(
            &paths.admin,
            serde_json::json!({
                "op": "enroll",
                "provider": "github",
                "client": "vm-1",
                "ip": "192.168.122.10",
                "note": null,
            }),
        )
        .await;
        assert_eq!(enroll["ok"], serde_json::json!(true));

        let revoke = admin_request(
            &paths.admin,
            serde_json::json!({
                "op": "revoke",
                "provider": "github",
                "client": "vm-1",
            }),
        )
        .await;
        assert_eq!(revoke["ok"], serde_json::json!(true));

        // PSK file should no longer contain vm-1.
        let psk_text = std::fs::read_to_string(&paths.psk).unwrap();
        assert!(
            !psk_text.contains("vm-1:"),
            "psk still has vm-1: {psk_text}"
        );

        // List reports empty.
        let listed = admin_request(&paths.admin, serde_json::json!({"op": "list"})).await;
        assert!(listed["clients"].as_array().unwrap().is_empty());

        paths.cleanup();
    }

    #[compio::test]
    async fn admin_revoke_unknown_client_returns_error() {
        let paths = unique_paths_full();
        write_clients_json(&paths.clients, &[]);
        let server = MockServer::start().await;
        spawn_daemon(&paths, server.uri()).await;

        let resp = admin_request(
            &paths.admin,
            serde_json::json!({"op": "revoke", "provider": "github", "client": "ghost"}),
        )
        .await;
        assert_eq!(resp["ok"], serde_json::json!(false));
        assert_eq!(resp["code"], "unknown_client");
        paths.cleanup();
    }

    #[compio::test]
    async fn admin_mint_calls_provider_via_wiremock() {
        let paths = unique_paths_full();
        write_clients_json(&paths.clients, &[("vm-1", "192.168.122.10")]);
        let server = MockServer::start().await;
        mount_repo_ok(&server).await;
        mount_mint_ok(&server).await;
        spawn_daemon(&paths, server.uri()).await;

        let resp = admin_request(
            &paths.admin,
            serde_json::json!({
                "op": "mint",
                "provider": "github",
                "client": "vm-1",
                "path": format!("{OWNER}/{REPO}"),
            }),
        )
        .await;
        assert_eq!(resp["ok"], serde_json::json!(true));
        assert_eq!(resp["username"], "x-access-token");
        assert_eq!(resp["password"], TOKEN);
        paths.cleanup();
    }

    #[compio::test]
    async fn admin_selfcheck_against_wiremock() {
        let paths = unique_paths_full();
        write_clients_json(&paths.clients, &[]);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/app"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": APP_ID})),
            )
            .mount(&server)
            .await;
        spawn_daemon(&paths, server.uri()).await;

        let resp = admin_request(
            &paths.admin,
            serde_json::json!({"op": "selfcheck", "provider": "github"}),
        )
        .await;
        assert_eq!(
            resp["ok"],
            serde_json::json!(true),
            "selfcheck failed: {resp:?}"
        );
        assert_eq!(resp["app_id"], APP_ID);
        paths.cleanup();
    }
}
