//! End-to-end daemon tests: send PROXY v2 + git-credential bytes
//! at the listen socket, observe the response (or EOF).

mod common;

use wiremock::MockServer;

use common::{
    CLIENT_IP, OWNER, REPO, TOKEN, build_config, build_proxy_v4, mount_mint_ok, mount_repo_ok,
    send_and_read_all, unique_paths, wait_for_socket, write_clients_json,
};

#[compio::test]
async fn daemon_happy_path() {
    let (socket_path, clients_path) = unique_paths();
    write_clients_json(&clients_path, &[("vm-1", CLIENT_IP)]);
    let server = MockServer::start().await;
    mount_repo_ok(&server).await;
    mount_mint_ok(&server).await;
    let cfg = build_config(socket_path.clone(), clients_path.clone(), server.uri());

    compio::runtime::spawn(async move {
        let _ = symbolon::run_daemon(&cfg, std::path::Path::new("/test/config.toml")).await;
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
        let _ = symbolon::run_daemon(&cfg, std::path::Path::new("/test/config.toml")).await;
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
        let _ = symbolon::run_daemon(&cfg, std::path::Path::new("/test/config.toml")).await;
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
        let _ = symbolon::run_daemon(&cfg, std::path::Path::new("/test/config.toml")).await;
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

// End-to-end Clone2Leak defence: a request with an embedded CR byte
// in a value reaches the daemon's parser, which rejects it. The
// daemon closes the connection without a response.
#[compio::test]
async fn daemon_rejects_cr_in_host_value() {
    let (socket_path, clients_path) = unique_paths();
    write_clients_json(&clients_path, &[("vm-1", CLIENT_IP)]);
    let server = MockServer::start().await;
    let cfg = build_config(socket_path.clone(), clients_path.clone(), server.uri());

    compio::runtime::spawn(async move {
        let _ = symbolon::run_daemon(&cfg, std::path::Path::new("/test/config.toml")).await;
    })
    .detach();
    wait_for_socket(&socket_path).await;

    let mut payload = build_proxy_v4([192, 168, 122, 10]);
    payload.extend_from_slice(b"protocol=https\nhost=github.com\rmalicious\npath=foo\n\n");
    let resp = send_and_read_all(&socket_path, payload).await;
    assert!(
        resp.is_empty(),
        "CR in value must close the connection without a response"
    );

    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&clients_path);
}
