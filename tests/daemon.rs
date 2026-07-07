//! End-to-end daemon tests: open TCP to the listener, run the NKpsk2
//! handshake, send a git-credential request through the transport,
//! observe the response (or a dead session).

mod common;

use wiremock::MockServer;

use common::{
    OWNER, REPO, TOKEN, client_handshake_and_read_eof, client_handshake_and_send, mount_mint_ok,
    mount_repo_ok, pick_free_loopback_addr, spawn_daemon_with_bind, test_broker_pub,
    unique_paths_full, wait_for_tcp, write_clients_json, write_psks_file,
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

    // Client uses a different identity not in the PSK store. The
    // daemon logs `evt=identity_unknown` (rate-limited) but does NOT
    // drop early: it substitutes a random PSK and answers with msg2,
    // so the failure surfaces as a decrypt error on this side —
    // indistinguishable from a wrong PSK (see the dedicated
    // indistinguishability test below).
    let req = b"protocol=https\nhost=github.com\npath=foo/bar\n\n";
    let resp = client_handshake_and_read_eof(addr, "ghost-vm", TEST_PSK, req).await;
    assert!(
        resp.is_empty(),
        "expected dead session, got {} bytes: {:?}",
        resp.len(),
        String::from_utf8_lossy(&resp),
    );
}

/// Anti-enumeration: from the wire, an unknown identity and an
/// enrolled identity with a wrong PSK must be indistinguishable. Both
/// must receive a well-formed msg2 (no early drop leaking "identity
/// exists"), and both must fail to decrypt it.
#[compio::test]
async fn daemon_unknown_identity_indistinguishable_from_wrong_psk() {
    use compio::BufResult;
    use compio::io::{AsyncRead, AsyncWriteExt};
    use symbolon::transport::{self, MAX_MESSAGE_SIZE};

    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &["vm-1"]);
    write_psks_file(&paths.psks, &[("vm-1", TEST_PSK)]);
    let server = MockServer::start().await;
    let addr = pick_free_loopback_addr();
    spawn_daemon_with_bind(&paths, server.uri(), addr).await;
    wait_for_tcp(addr).await;

    // Probe once with an unknown identity and once with an enrolled
    // identity + wrong PSK; the attacker-visible transcript shape
    // must match: msg2 arrives, msg2 length identical, decrypt fails.
    let probe = async |identity: &str, psk: [u8; 32]| -> (usize, bool) {
        let identity = symbolon::Identity::parse(identity).unwrap();
        let psk = symbolon::Psk::from(psk);
        let mut hs = transport::initiator(&psk, &test_broker_pub()).unwrap();
        let mut scratch = vec![0u8; MAX_MESSAGE_SIZE];

        let mut stream = compio::net::TcpStream::connect(addr).await.unwrap();
        let tlv = transport::encode_identity_tlv(&identity);
        let n = transport::handshake_write(&mut hs, &tlv, &mut scratch).unwrap();
        let framed = transport::frame(&scratch[..n]).unwrap();
        let BufResult(res, _) = stream.write_all(framed).await;
        res.unwrap();

        // Read msg2: 2-byte length then body.
        let read_exact = async |stream: &mut compio::net::TcpStream, n: usize| -> Vec<u8> {
            let mut out = Vec::with_capacity(n);
            while out.len() < n {
                let buf = Vec::with_capacity(n - out.len());
                let BufResult(res, mut filled) = stream.read(buf).await;
                let read = res.expect("msg2 must arrive for both probes");
                assert!(read > 0, "daemon must not close before msg2");
                filled.truncate(read);
                out.extend_from_slice(&filled);
            }
            out
        };
        let len_buf = read_exact(&mut stream, 2).await;
        let body_len = u16::from_be_bytes([len_buf[0], len_buf[1]]) as usize;
        let body = read_exact(&mut stream, body_len).await;

        let decrypt_failed = transport::handshake_read(&mut hs, &body, &mut scratch).is_err();
        (body_len, decrypt_failed)
    };

    let (len_unknown, failed_unknown) = probe("ghost-vm", TEST_PSK).await;
    let (len_wrong_psk, failed_wrong_psk) = probe("vm-1", [0xcc; 32]).await;

    assert!(failed_unknown, "unknown identity must fail msg2 decrypt");
    assert!(failed_wrong_psk, "wrong PSK must fail msg2 decrypt");
    assert_eq!(
        len_unknown, len_wrong_psk,
        "msg2 length must not leak whether the identity is enrolled"
    );
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
    // daemon's msg2 (built with the real PSK) fails to decrypt on
    // this side; the session dies without a response.
    let wrong_psk = [0xcc; 32];
    let req = b"protocol=https\nhost=github.com\npath=foo/bar\n\n";
    let resp = client_handshake_and_read_eof(addr, "vm-1", wrong_psk, req).await;
    assert!(
        resp.is_empty(),
        "wrong PSK must close the connection, got: {resp:?}"
    );
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
}
