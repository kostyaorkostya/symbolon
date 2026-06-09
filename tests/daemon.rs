//! End-to-end daemon tests: open TCP to the listener, run NNpsk0
//! handshake, send a git-credential request through the transport,
//! observe the response (or EOF).

mod common;

use wiremock::MockServer;

use common::{
    OWNER, REPO, TOKEN, client_handshake_and_read_eof, client_handshake_and_send, mount_mint_ok,
    mount_repo_ok, pick_free_loopback_addr, spawn_daemon_with_bind, unique_paths_full,
    wait_for_tcp, write_clients_json, write_psks_file,
};

const TEST_PSK: [u8; 32] = [0xab; 32];

#[compio::test]
async fn daemon_happy_path() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &["vm-1"]);
    write_psks_file(&paths.psks, &[("vm-1", TEST_PSK)]);
    let server = MockServer::start().await;
    mount_repo_ok(&server).await;
    mount_mint_ok(&server).await;
    let addr = pick_free_loopback_addr();
    spawn_daemon_with_bind(&paths, server.uri(), addr).await;
    wait_for_tcp(addr).await;

    let req = format!("protocol=https\nhost=github.com\npath={OWNER}/{REPO}\n\n").into_bytes();
    let resp = client_handshake_and_send(addr, "vm-1", TEST_PSK, &req).await;
    let body = std::str::from_utf8(&resp).unwrap();
    assert!(
        body.contains(&format!("password={TOKEN}\n")),
        "response: {body:?}"
    );
    assert!(body.starts_with("username=x-access-token\n"));

    paths.cleanup();
}

#[compio::test]
async fn daemon_rejects_unknown_identity() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &["vm-1"]);
    write_psks_file(&paths.psks, &[("vm-1", TEST_PSK)]);
    let server = MockServer::start().await;
    let addr = pick_free_loopback_addr();
    spawn_daemon_with_bind(&paths, server.uri(), addr).await;
    wait_for_tcp(addr).await;

    // Client uses a different identity not in the PSK store. Daemon
    // logs `evt=mint_denied reason=client_unknown` and drops the
    // connection before completing the handshake.
    let req = b"protocol=https\nhost=github.com\npath=foo/bar\n\n";
    let resp = client_handshake_and_read_eof(addr, "ghost-vm", TEST_PSK, req).await;
    assert!(
        resp.is_empty(),
        "expected EOF, got {} bytes: {:?}",
        resp.len(),
        String::from_utf8_lossy(&resp),
    );

    paths.cleanup();
}

#[compio::test]
async fn daemon_rejects_wrong_psk() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &["vm-1"]);
    write_psks_file(&paths.psks, &[("vm-1", TEST_PSK)]);
    let server = MockServer::start().await;
    let addr = pick_free_loopback_addr();
    spawn_daemon_with_bind(&paths, server.uri(), addr).await;
    wait_for_tcp(addr).await;

    // Identity matches an enrolled client, but the PSK is wrong. The
    // Noise responder rejects the binder check on the first inbound
    // handshake message; daemon drops the connection.
    let wrong_psk = [0xcc; 32];
    let req = b"protocol=https\nhost=github.com\npath=foo/bar\n\n";
    let resp = client_handshake_and_read_eof(addr, "vm-1", wrong_psk, req).await;
    assert!(
        resp.is_empty(),
        "wrong PSK must close the connection, got: {resp:?}"
    );

    paths.cleanup();
}

#[compio::test]
async fn daemon_rejects_unknown_host() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &["vm-1"]);
    write_psks_file(&paths.psks, &[("vm-1", TEST_PSK)]);
    let server = MockServer::start().await;
    let addr = pick_free_loopback_addr();
    spawn_daemon_with_bind(&paths, server.uri(), addr).await;
    wait_for_tcp(addr).await;

    let req = b"protocol=https\nhost=evil.example\npath=foo/bar\n\n";
    let resp = client_handshake_and_read_eof(addr, "vm-1", TEST_PSK, req).await;
    assert!(resp.is_empty(), "expected EOF, got: {resp:?}");

    paths.cleanup();
}

#[compio::test]
async fn daemon_rejects_malformed_request() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &["vm-1"]);
    write_psks_file(&paths.psks, &[("vm-1", TEST_PSK)]);
    let server = MockServer::start().await;
    let addr = pick_free_loopback_addr();
    spawn_daemon_with_bind(&paths, server.uri(), addr).await;
    wait_for_tcp(addr).await;

    // Missing `path=` line.
    let req = b"protocol=https\nhost=github.com\n\n";
    let resp = client_handshake_and_read_eof(addr, "vm-1", TEST_PSK, req).await;
    assert!(resp.is_empty(), "expected EOF, got: {resp:?}");

    paths.cleanup();
}

// End-to-end Clone2Leak defence: a request with an embedded CR byte
// in a value reaches the daemon's parser, which rejects it. The
// daemon closes the connection without a response.
#[compio::test]
async fn daemon_rejects_cr_in_host_value() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &["vm-1"]);
    write_psks_file(&paths.psks, &[("vm-1", TEST_PSK)]);
    let server = MockServer::start().await;
    let addr = pick_free_loopback_addr();
    spawn_daemon_with_bind(&paths, server.uri(), addr).await;
    wait_for_tcp(addr).await;

    let req = b"protocol=https\nhost=github.com\rmalicious\npath=foo\n\n";
    let resp = client_handshake_and_read_eof(addr, "vm-1", TEST_PSK, req).await;
    assert!(
        resp.is_empty(),
        "CR in value must close the connection without a response"
    );

    paths.cleanup();
}
