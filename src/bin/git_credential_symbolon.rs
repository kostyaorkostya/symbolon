//! `git-credential-symbolon` — client-side git-credential helper.
//!
//! Invoked by git per credential request. Reads a git-credential request from
//! stdin, opens a TCP connection to the symbolon broker, runs the Noise NNpsk0
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
//!     --psk-file /etc/symbolon/psk get
//! ```
//! Git always appends an `action` arg (`get`/`store`/`erase`); this helper
//! only services `get` and exits silently for the rest (store/erase are
//! no-ops by design — the broker never persists anything to the client).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use argh::FromArgs;

use symbolon::transport::{Initiator, SessionError, Step};

const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// git-credential helper that proxies requests over Noise NNpsk0 to a symbolon broker.
#[derive(FromArgs)]
struct Args {
    /// broker endpoint, `host:port` form
    #[argh(option)]
    endpoint: String,
    /// client identity matching the enrolled name on the broker
    #[argh(option)]
    identity: String,
    /// path to a file containing the 64-hex PSK on a single line
    #[argh(option)]
    psk_file: PathBuf,
    /// git-credential action (`get` / `store` / `erase`). Only `get` is honoured.
    #[argh(positional)]
    action: String,
}

fn main() -> ExitCode {
    let args: Args = argh::from_env();

    // `store` and `erase` are git's per-action calls into a helper for caching;
    // we never persist anything, so they're no-ops.
    if args.action != "get" {
        return ExitCode::SUCCESS;
    }

    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("git-credential-symbolon: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &Args) -> Result<(), ClientError> {
    let psk = load_psk(&args.psk_file)?;
    let mut request = Vec::new();
    std::io::stdin()
        .read_to_end(&mut request)
        .map_err(ClientError::ReadStdin)?;

    // Build the Initiator BEFORE opening the socket. Validates the
    // identity charset and PSK length, so a misconfigured invocation
    // fails fast without a wasted TCP roundtrip.
    let sess = Initiator::new(&args.identity, psk, request).map_err(ClientError::Session)?;

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

fn load_psk(path: &PathBuf) -> Result<[u8; 32], ClientError> {
    let text = std::fs::read_to_string(path).map_err(|source| ClientError::ReadPsk {
        path: path.clone(),
        source,
    })?;
    let hex_str = text.trim();
    if hex_str.len() != 64 {
        return Err(ClientError::BadPskLen {
            path: path.clone(),
            got: hex_str.len(),
        });
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut out).map_err(|e| match e {
        hex::FromHexError::InvalidHexCharacter { c, .. } => ClientError::BadPskHex {
            path: path.clone(),
            byte: c as u8,
        },
        _ => ClientError::BadPskLen {
            path: path.clone(),
            got: hex_str.len(),
        },
    })?;
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
enum ClientError {
    #[error("reading PSK file {} failed", path.display())]
    ReadPsk {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("PSK file {} must contain exactly 64 hex chars (got {got})", path.display())]
    BadPskLen { path: PathBuf, got: usize },
    #[error("PSK file {} has non-hex byte 0x{byte:02x}", path.display())]
    BadPskHex { path: PathBuf, byte: u8 },
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
}
