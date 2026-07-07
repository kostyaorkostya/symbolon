//! End-to-end smoke test for the `git-credential-symbolon` binary.
//!
//! Spins up a tiny single-shot Noise responder on a random port, runs the
//! shipped binary against it, and asserts the request bytes round-trip through
//! the encrypted transport unchanged. Validates the NKpsk2 handshake wire
//! shape (identity TLV inside msg1) without involving the daemon.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use symbolon::transport::{self, MAX_MESSAGE_SIZE, PSK_SLOT, frame, parse_identity_tlv};
use symbolon::{BrokerPrivateKey, Psk};

const PSK_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PSK_BYTES: [u8; 32] = [0xaa; 32];
const BROKER_PRIV: [u8; 32] = [7u8; 32];

const REQUEST: &[u8] = b"protocol=https\nhost=github.com\npath=octocat/Hello-World\n\n";
const RESPONSE: &[u8] =
    b"protocol=https\nhost=github.com\nusername=x-access-token\npassword=ghs_TOKEN\n\n";

fn client_binary_path() -> PathBuf {
    // CARGO sets CARGO_BIN_EXE_<bin-name> at integration-test compile time
    // exactly for this use case. Hyphens in the bin name become underscores.
    PathBuf::from(env!("CARGO_BIN_EXE_git-credential-symbolon"))
}

/// One line, `broker_pub_hex:psk_hex` — the client key file format.
fn key_file_contents() -> String {
    let broker_pub = BrokerPrivateKey::from(BROKER_PRIV).derive_public();
    format!("{broker_pub}:{PSK_HEX}")
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

        let mut hs =
            transport::responder(&BrokerPrivateKey::from(BROKER_PRIV)).expect("build responder");
        let mut scratch = vec![0u8; MAX_MESSAGE_SIZE];

        // -> e, es: decrypt msg1, recover the identity TLV.
        let msg1 = read_framed(&mut stream);
        let n = transport::handshake_read(&mut hs, &msg1, &mut scratch).expect("hs read 1");
        let (identity, consumed) = parse_identity_tlv(&scratch[..n]).expect("valid TLV");
        assert_eq!(identity.as_str(), "smoke-vm");
        assert_eq!(consumed, n, "payload must be exactly one TLV");

        // PSK selected by identity; <- e, ee, psk.
        hs.set_psk(usize::from(PSK_SLOT), Psk::from(PSK_BYTES).as_bytes())
            .expect("set_psk");
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

    // 3. Write a single-line key file (`broker_pub_hex:psk_hex`) in a tempdir.
    let key_path =
        std::env::temp_dir().join(format!("symbolon-client-test-{}.key", ulid::Ulid::new()));
    std::fs::write(&key_path, key_file_contents()).expect("write key file");

    // 4. Invoke the client binary.
    let mut child = Command::new(client_binary_path())
        .arg("--endpoint")
        .arg(format!("127.0.0.1:{}", addr.port()))
        .arg("--identity")
        .arg("smoke-vm")
        .arg("--key-file")
        .arg(&key_path)
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
    let _ = std::fs::remove_file(&key_path);
}

#[test]
fn store_and_erase_actions_exit_silently() {
    let key_path =
        std::env::temp_dir().join(format!("symbolon-client-noop-{}.key", ulid::Ulid::new()));
    std::fs::write(&key_path, key_file_contents()).expect("write key file");

    for action in ["store", "erase"] {
        let output = Command::new(client_binary_path())
            .arg("--endpoint")
            .arg("127.0.0.1:1") // intentionally unreachable; should not be touched
            .arg("--identity")
            .arg("noop")
            .arg("--key-file")
            .arg(&key_path)
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

    let _ = std::fs::remove_file(&key_path);
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
