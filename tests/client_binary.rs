//! End-to-end smoke test for the `git-credential-symbolon` binary.
//!
//! Spins up a tiny single-shot Noise responder on a random port, runs the
//! shipped binary against it, and asserts the request bytes round-trip through
//! the encrypted transport unchanged. Validates the Noise handshake wire
//! shape and the prelude framing without involving the daemon.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use symbolon::transport::{self, MAX_MESSAGE_SIZE, frame, parse_prelude};

const PSK_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PSK_BYTES: [u8; 32] = [0xaa; 32];

const REQUEST: &[u8] = b"protocol=https\nhost=github.com\npath=octocat/Hello-World\n\n";
const RESPONSE: &[u8] =
    b"protocol=https\nhost=github.com\nusername=x-access-token\npassword=ghs_TOKEN\n\n";

fn client_binary_path() -> PathBuf {
    // CARGO sets CARGO_BIN_EXE_<bin-name> at integration-test compile time
    // exactly for this use case. Hyphens in the bin name become underscores.
    PathBuf::from(env!("CARGO_BIN_EXE_git-credential-symbolon"))
}

#[test]
fn client_binary_round_trips_request_through_noise() {
    // 1. Bind a listener on a random ephemeral port.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let addr = listener.local_addr().expect("local_addr");

    // 2. Spawn a responder thread that does ONE handshake + ONE request/response.
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        // Prelude (cleartext, fixed size based on identity len).
        let mut prelude_head = [0u8; 6];
        stream.read_exact(&mut prelude_head).expect("prelude head");
        // We can't parse the head alone because parse_prelude needs the full
        // record. Read the identity bytes too.
        let id_len = prelude_head[5] as usize;
        let mut prelude = Vec::with_capacity(6 + id_len);
        prelude.extend_from_slice(&prelude_head);
        prelude.resize(6 + id_len, 0);
        stream.read_exact(&mut prelude[6..]).expect("identity tail");
        let (identity, consumed) = parse_prelude(&prelude).expect("valid prelude");
        assert_eq!(identity.as_str(), "smoke-vm");
        assert_eq!(consumed, prelude.len());

        // Build responder; the PSK we use must match the client's.
        let mut hs =
            transport::responder(&symbolon::Psk::from(PSK_BYTES)).expect("build responder");
        let mut scratch = vec![0u8; MAX_MESSAGE_SIZE];

        // -> psk, e
        let msg1 = read_framed(&mut stream);
        let _ = transport::handshake_read(&mut hs, &msg1, &mut scratch).expect("hs read 1");

        // <- e, ee
        let n = transport::handshake_write(&mut hs, &[], &mut scratch).expect("hs write 2");
        write_framed(&mut stream, &scratch[..n]);

        let mut ts = transport::into_transport(hs).expect("transport");

        // Read encrypted git-credential request, assert it matches.
        let ct = read_framed(&mut stream);
        let m = transport::transport_read(&mut ts, &ct, &mut scratch).expect("decrypt");
        assert_eq!(&scratch[..m], REQUEST);

        // Send the canned response.
        let n = transport::transport_write(&mut ts, RESPONSE, &mut scratch).expect("encrypt");
        write_framed(&mut stream, &scratch[..n]);
    });

    // 3. Write a single-line PSK file in a tempdir.
    let psk_path =
        std::env::temp_dir().join(format!("symbolon-client-test-{}.psk", ulid::Ulid::new()));
    std::fs::write(&psk_path, PSK_HEX).expect("write psk");

    // 4. Invoke the client binary.
    let mut child = Command::new(client_binary_path())
        .arg("--endpoint")
        .arg(format!("127.0.0.1:{}", addr.port()))
        .arg("--identity")
        .arg("smoke-vm")
        .arg("--psk-file")
        .arg(&psk_path)
        .arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn client");

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(REQUEST)
        .expect("write stdin");
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "client exited with {:?}, stderr: {}",
        output.status,
        stderr,
    );
    assert_eq!(output.stdout, RESPONSE, "stderr: {stderr}");

    server.join().expect("server thread");
    let _ = std::fs::remove_file(&psk_path);
}

#[test]
fn store_and_erase_actions_exit_silently() {
    let psk_path =
        std::env::temp_dir().join(format!("symbolon-client-noop-{}.psk", ulid::Ulid::new()));
    std::fs::write(&psk_path, PSK_HEX).expect("write psk");

    for action in ["store", "erase"] {
        let output = Command::new(client_binary_path())
            .arg("--endpoint")
            .arg("127.0.0.1:1") // intentionally unreachable; should not be touched
            .arg("--identity")
            .arg("noop")
            .arg("--psk-file")
            .arg(&psk_path)
            .arg(action)
            .stdin(Stdio::null())
            .output()
            .expect("spawn");
        assert!(
            output.status.success(),
            "action {action} should be a silent no-op"
        );
        assert!(output.stdout.is_empty());
    }

    let _ = std::fs::remove_file(&psk_path);
}

// Framing helpers — duplicated from the binary's own logic to keep this test
// independent of any internal helpers we might refactor.
fn read_framed(stream: &mut TcpStream) -> Vec<u8> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).expect("read length");
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).expect("read body");
    body
}

fn write_framed(stream: &mut TcpStream, payload: &[u8]) {
    let framed = frame(payload).expect("frame");
    stream.write_all(&framed).expect("write");
}
