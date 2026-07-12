//! Live smoke test for the `tpm` signing backend against a software
//! TPM (swtpm). Gated on `swtpm` + tpm2-tools being installed; skips
//! cleanly otherwise (they are not part of the default toolchain).
//!
//! Flow:
//!   1. Provision an RSA-2048 unrestricted signing key at persistent
//!      handle 0x81010001, driving swtpm over TCP with tpm2-tools, and
//!      export its public key as PEM. Stop that swtpm.
//!   2. Restart swtpm on the SAME state dir exposing a `unixio` server
//!      (the raw command channel, identical framing to `/dev/tpmrm0`).
//!   3. Connect, hand the socket fd to `TpmSpawn::from_fd`, and run the
//!      real backend: `self_check` (TPM2_ReadPublic → verify RSA-2048)
//!      and `sign` (TPM2_Sign → assemble JWT).
//!   4. Verify the JWT's RS256 signature with the `rsa` crate against
//!      the exported TPM public key.
//!
//! This validates the marshaling, the response parsing, and the whole
//! digest→sign→assemble path against a real TPM implementation.

use std::net::TcpListener;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, UNIX_EPOCH};

use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use sha2::Sha256;
use symbolon::{JwtClaims, Sandboxed, SpawnedBackend, TpmSpawn};

const PERSISTENT_HANDLE: u32 = 0x8101_0001;

fn have(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn wait_for(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("swtpm socket {} did not appear", path.display());
}

/// Provision the persistent signing key, driving swtpm over TCP with
/// tpm2-tools. Writes the exported public key PEM to `pub_pem`.
fn provision(state_dir: &Path, pub_pem: &Path) {
    // tpm2-tools' `swtpm` TCTI expects the control channel at
    // `port + 1`; allocate an adjacent pair, not two random ports.
    let server = free_port();
    let ctrl = server + 1;
    let mut swtpm = Command::new("swtpm")
        .args([
            "socket",
            "--tpm2",
            "--tpmstate",
            &format!("dir={}", state_dir.display()),
            "--ctrl",
            &format!("type=tcp,port={ctrl}"),
            "--server",
            &format!("type=tcp,port={server}"),
            "--flags",
            "startup-clear",
        ])
        .spawn()
        .expect("spawn swtpm (tcp)");

    // Wait for the TCP server to accept.
    for _ in 0..200 {
        if std::net::TcpStream::connect(("127.0.0.1", server)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let tcti = format!("swtpm:host=127.0.0.1,port={server}");
    let tpm2 = |args: &[&str]| {
        let ok = Command::new(args[0])
            .args(&args[1..])
            .env("TPM2TOOLS_TCTI", &tcti)
            .current_dir(state_dir)
            .status()
            .unwrap_or_else(|e| panic!("run {}: {e}", args[0]))
            .success();
        assert!(ok, "tpm2 command failed: {args:?}");
    };
    let flush = || {
        let _ = Command::new("tpm2_flushcontext")
            .arg("-t")
            .env("TPM2TOOLS_TCTI", &tcti)
            .current_dir(state_dir)
            .status();
    };

    tpm2(&[
        "tpm2_createprimary",
        "-C",
        "o",
        "-G",
        "rsa2048",
        "-c",
        "primary.ctx",
    ]);
    flush();
    tpm2(&[
        "tpm2_create",
        "-C",
        "primary.ctx",
        "-G",
        "rsa2048",
        "-u",
        "key.pub",
        "-r",
        "key.priv",
        "-a",
        "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
    ]);
    flush();
    tpm2(&[
        "tpm2_load",
        "-C",
        "primary.ctx",
        "-u",
        "key.pub",
        "-r",
        "key.priv",
        "-c",
        "key.ctx",
    ]);
    tpm2(&[
        "tpm2_evictcontrol",
        "-C",
        "o",
        "-c",
        "key.ctx",
        "0x81010001",
    ]);
    flush();
    tpm2(&[
        "tpm2_readpublic",
        "-c",
        "0x81010001",
        "-f",
        "pem",
        "-o",
        pub_pem.to_str().unwrap(),
    ]);

    let _ = swtpm.kill();
    let _ = swtpm.wait();
}

/// Start swtpm exposing a `unixio` raw-command server on the (already
/// provisioned) state dir. Returns the child and the server socket path.
fn serve_unixio(state_dir: &Path) -> (Child, PathBuf) {
    let sock = state_dir.join("server.sock");
    let ctrl = state_dir.join("ctrl.sock");
    let child = Command::new("swtpm")
        .args([
            "socket",
            "--tpm2",
            "--tpmstate",
            &format!("dir={}", state_dir.display()),
            "--ctrl",
            &format!("type=unixio,path={}", ctrl.display()),
            "--server",
            &format!("type=unixio,path={}", sock.display()),
            "--flags",
            "startup-clear",
        ])
        .spawn()
        .expect("spawn swtpm (unixio)");
    wait_for(&sock);
    (child, sock)
}

#[compio::test]
async fn tpm_backend_signs_against_swtpm() {
    if !have("swtpm") || !have("tpm2_createprimary") || !have("tpm2_readpublic") {
        eprintln!("skipping: swtpm / tpm2-tools not installed");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("symbolon-tpm-{}", std::process::id()));
    let state = tmp.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let pub_pem = tmp.join("tpmpub.pem");

    provision(&state, &pub_pem);
    let (mut swtpm, sock) = serve_unixio(&state);

    // Connect the raw command channel and hand its fd to the backend.
    let stream = UnixStream::connect(&sock).expect("connect swtpm unixio");
    let fd = OwnedFd::from(stream);
    let backend = Box::new(TpmSpawn::from_fd(fd, PERSISTENT_HANDLE))
        .into_backend(&Sandboxed::assume_for_test());

    // self_check: TPM2_ReadPublic → verify RSA-2048 signing key.
    backend.self_check().await.expect("tpm self_check");

    // sign: TPM2_Sign → assemble JWT.
    let claims = JwtClaims::new(
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        "Iv1.tpm-test",
    );
    let jwt = backend.sign(&claims).await.expect("tpm sign");

    let _ = swtpm.kill();
    let _ = swtpm.wait();

    // Verify the RS256 signature against the TPM's public key.
    let (signing_input, sig_b64) = jwt.rsplit_once('.').expect("jwt has 3 segments");
    let sig_bytes = base64_url_decode(sig_b64);
    let pem = std::fs::read_to_string(&pub_pem).unwrap();
    let public = RsaPublicKey::from_public_key_pem(&pem).expect("parse tpm pubkey");
    let vk = VerifyingKey::<Sha256>::new(public);
    let sig = Signature::try_from(sig_bytes.as_slice()).expect("signature");
    vk.verify(signing_input.as_bytes(), &sig)
        .expect("TPM-produced JWT signature must verify against the TPM public key");

    let _ = std::fs::remove_dir_all(&tmp);
}

fn base64_url_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .expect("base64url signature")
}
