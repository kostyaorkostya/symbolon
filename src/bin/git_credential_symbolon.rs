//! `git-credential-symbolon` — client-side git-credential helper.
//!
//! Invoked by git per credential request. Reads a git-credential request from
//! stdin, opens a TCP connection to the symbolon broker, runs the Noise NKpsk2
//! initiator handshake, sends the request through the encrypted transport, and
//! writes the response to stdout.
//!
//! Synchronous std::net throughout — per-invocation lifetime is sub-second; an
//! async runtime would be pure overhead. The wire protocol lives in
//! [`symbolon::transport`]; this binary is just the I/O glue.
//!
//! Usage:
//! ```text
//! git-credential-symbolon \
//!     --endpoint broker.lan:9418 \
//!     --identity dev-vm-1 \
//!     --key-file /etc/symbolon/key get
//! ```
//!
//! The key file is one line, `broker_pub_hex:psk_hex` — the broker's
//! static X25519 public key (from `symbolon pubkey` on the broker)
//! and this client's PSK (from `symbolon github enroll`), both 64 hex
//! chars, colon-separated. Same shape as the broker-side `psks` file
//! (`identity:hex`).
//! Git always appends an `action` arg (`get`/`store`/`erase`); this helper
//! only services `get` and exits silently for the rest (store/erase are
//! no-ops by design — the broker never persists anything to the client).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use argh::FromArgs;
use hex::FromHex;

use symbolon::transport::{Initiator, SessionError, Step};
use symbolon::{BrokerPublicKey, Identity, IdentityError, Psk};

const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// git-credential helper that proxies requests over Noise NKpsk2 to a symbolon broker.
#[derive(FromArgs)]
struct Args {
    /// broker endpoint, `host:port` form
    #[argh(option)]
    endpoint: String,
    /// client identity matching the enrolled name on the broker
    #[argh(option)]
    identity: String,
    /// path to a file containing `broker_pub_hex:psk_hex` on a single line
    #[argh(option)]
    key_file: PathBuf,
    /// git-credential action (`get` / `store` / `erase`). Only `get` is honoured.
    #[argh(positional)]
    action: String,
}

fn main() -> ExitCode {
    let args: Args = argh::from_env();

    match args.action.as_str() {
        "get" => match run(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("git-credential-symbolon: {e}");
                ExitCode::from(1)
            }
        },
        // `capability` (git 2.46+) — advertise that we understand
        // the `authtype` capability so git will send
        // `capability[]=authtype` on subsequent `get` requests, which
        // unlocks the modern `authtype=Bearer` + `credential=<token>`
        // + `ephemeral=true` response shape. Format per
        // git-credential.adoc § CAPABILITY INPUT/OUTPUT FORMAT.
        "capability" => {
            let mut out = std::io::stdout().lock();
            if out.write_all(b"version 0\ncapability authtype\n").is_err() {
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        // `store` and `erase` are git's per-action calls into a
        // helper for caching; we never persist anything, so they're
        // no-ops. Any other action is also a no-op success — git
        // ignores helpers that don't recognise an action.
        _ => ExitCode::SUCCESS,
    }
}

fn run(args: &Args) -> Result<(), ClientError> {
    // Parse the identity at the argv boundary so a misconfigured
    // invocation fails with a clear "bad identity" message, not
    // through the transport layer's wire-shaped errors.
    let identity = Identity::parse(&args.identity).map_err(|source| ClientError::BadIdentity {
        raw: args.identity.clone(),
        source,
    })?;
    let (broker_pub, psk) = load_key_file(&args.key_file)?;
    let mut request = Vec::new();
    std::io::stdin()
        .read_to_end(&mut request)
        .map_err(ClientError::ReadStdin)?;

    // Build the Initiator BEFORE opening the socket. Validates the
    // key material, so a misconfigured invocation fails fast without
    // a wasted TCP roundtrip.
    let sess = Initiator::new(identity, psk, &broker_pub, request).map_err(ClientError::Session)?;

    let mut stream = connect(&args.endpoint)?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(ClientError::SetTimeout)?;
    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(ClientError::SetTimeout)?;

    let response = drive(&mut stream, sess)?;
    std::io::stdout()
        .write_all(&response)
        .map_err(ClientError::WriteStdout)?;
    Ok(())
}

fn connect(endpoint: &str) -> Result<TcpStream, ClientError> {
    let mut last_err = None;
    let addrs = endpoint
        .to_socket_addrs()
        .map_err(|source| ClientError::Resolve {
            endpoint: endpoint.to_string(),
            source,
        })?;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(ClientError::Connect {
        endpoint: endpoint.to_string(),
        source: last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses resolved")
        }),
    })
}

/// Drive the `Initiator` state machine against a blocking TCP socket
/// until it reports `Step::Done`, then return the decrypted response.
fn drive(stream: &mut TcpStream, mut sess: Initiator) -> Result<Vec<u8>, ClientError> {
    loop {
        match sess.step().map_err(ClientError::Session)? {
            Step::ReadExact { n } => {
                let mut buf = vec![0u8; n];
                stream
                    .read_exact(&mut buf)
                    .map_err(ClientError::ReadHandshake)?;
                sess.recv(&buf).map_err(ClientError::Session)?;
            }
            Step::Write(bytes) => {
                stream
                    .write_all(&bytes)
                    .map_err(ClientError::WriteHandshake)?;
                sess.wrote().map_err(ClientError::Session)?;
            }
            Step::Done => return sess.take_response().map_err(ClientError::Session),
            Step::NeedPsk { .. } | Step::Request(_) => {
                // Responder-only variants; the Initiator never emits these.
                return Err(ClientError::Session(SessionError::WrongState {
                    method: "drive",
                    state: "unexpected_initiator_step",
                }));
            }
        }
    }
}

/// Parse the client key file: one line, `broker_pub_hex:psk_hex`.
/// The colon split is on the FIRST colon; both halves are strict
/// 64-char hex.
fn load_key_file(path: &Path) -> Result<(BrokerPublicKey, Psk), ClientError> {
    let text = std::fs::read_to_string(path).map_err(|source| ClientError::ReadKeyFile {
        path: path.to_path_buf(),
        source,
    })?;
    let malformed = |detail: &'static str| ClientError::BadKeyFile {
        path: path.to_path_buf(),
        detail,
    };
    let (pub_hex, psk_hex) = text
        .trim()
        .split_once(':')
        .ok_or_else(|| malformed("expected `broker_pub_hex:psk_hex`"))?;
    let broker_pub = BrokerPublicKey::from_hex(pub_hex)
        .map_err(|_| malformed("broker public key half is not 64 hex chars"))?;
    let psk = Psk::from_hex(psk_hex).map_err(|_| malformed("PSK half is not 64 hex chars"))?;
    Ok((broker_pub, psk))
}

#[derive(Debug, thiserror::Error)]
enum ClientError {
    #[error("reading key file {} failed", path.display())]
    ReadKeyFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("key file {} is malformed: {detail}", path.display())]
    BadKeyFile { path: PathBuf, detail: &'static str },
    #[error("resolving endpoint {endpoint:?} failed")]
    Resolve {
        endpoint: String,
        #[source]
        source: std::io::Error,
    },
    #[error("connecting to {endpoint:?} failed")]
    Connect {
        endpoint: String,
        #[source]
        source: std::io::Error,
    },
    #[error("setting socket timeout failed")]
    SetTimeout(#[source] std::io::Error),
    #[error("reading git-credential request from stdin failed")]
    ReadStdin(#[source] std::io::Error),
    #[error("writing git-credential response to stdout failed")]
    WriteStdout(#[source] std::io::Error),
    #[error("writing to broker failed")]
    WriteHandshake(#[source] std::io::Error),
    #[error("reading from broker failed")]
    ReadHandshake(#[source] std::io::Error),
    #[error("Noise session error")]
    Session(#[source] SessionError),
    #[error("invalid --identity {raw:?}")]
    BadIdentity {
        raw: String,
        #[source]
        source: IdentityError,
    },
}
