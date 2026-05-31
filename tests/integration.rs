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
    let resp = provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();

    assert_eq!(resp.username, "x-access-token");
    assert_eq!(resp.password, TOKEN);
    let secs = resp
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

    use compio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
    use compio::net::UnixStream;
    use compio::BufResult;
    use gcb::config::{
        AdminConfig, ClientsConfig, Config, ListenConfig, LogLevel, LoggingConfig, Providers,
        StunnelConfig,
    };

    const PROXY_V2_SIGNATURE: [u8; 12] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];
    const CLIENT_IP: &str = "192.168.122.10";

    fn unique_id() -> u64 {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    fn unique_paths() -> (PathBuf, PathBuf) {
        let id = unique_id();
        let pid = std::process::id();
        let socket = std::env::temp_dir().join(format!("gcb-test-{pid}-{id}.sock"));
        let clients = std::env::temp_dir().join(format!("gcb-test-{pid}-{id}-clients.json"));
        (socket, clients)
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
        Config {
            listen: ListenConfig {
                socket: socket_path,
            },
            admin: AdminConfig {
                socket_path: PathBuf::from("/unused-in-tests/admin.sock"),
            },
            clients: ClientsConfig { file: clients_path },
            stunnel: StunnelConfig {
                psk_file: PathBuf::from("/unused-in-tests/gcb.psk"),
            },
            logging: LoggingConfig {
                level: LogLevel::Info,
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
            let _ = gcb::daemon::run(&cfg).await;
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
            let _ = gcb::daemon::run(&cfg).await;
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
            let _ = gcb::daemon::run(&cfg).await;
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
            let _ = gcb::daemon::run(&cfg).await;
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
