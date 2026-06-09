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

use symbolon::transport::{
    self, MAX_MESSAGE_SIZE, TransportError, encode_prelude, frame, initiator, into_transport,
    read_frame_length,
};

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

    let mut stream = connect(&args.endpoint)?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(ClientError::SetTimeout)?;
    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(ClientError::SetTimeout)?;

    let prelude = encode_prelude(&args.identity).ok_or_else(|| ClientError::BadIdentity {
        identity: args.identity.clone(),
    })?;
    stream
        .write_all(&prelude)
        .map_err(ClientError::WriteHandshake)?;

    let response = run_session(&mut stream, &psk, &request)?;
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

fn run_session(
    stream: &mut TcpStream,
    psk: &[u8; 32],
    request: &[u8],
) -> Result<Vec<u8>, ClientError> {
    let mut hs = initiator(psk).map_err(ClientError::Transport)?;
    let mut scratch = vec![0u8; MAX_MESSAGE_SIZE];

    // -> psk, e
    let n =
        transport::handshake_write(&mut hs, &[], &mut scratch).map_err(ClientError::Transport)?;
    write_framed(stream, &scratch[..n])?;

    // <- e, ee
    let reply = read_framed(stream)?;
    let _ =
        transport::handshake_read(&mut hs, &reply, &mut scratch).map_err(ClientError::Transport)?;

    let mut ts = into_transport(hs).map_err(ClientError::Transport)?;

    let n = transport::transport_write(&mut ts, request, &mut scratch)
        .map_err(ClientError::Transport)?;
    write_framed(stream, &scratch[..n])?;

    let ciphertext = read_framed(stream)?;
    let n = transport::transport_read(&mut ts, &ciphertext, &mut scratch)
        .map_err(ClientError::Transport)?;
    Ok(scratch[..n].to_vec())
}

fn write_framed(stream: &mut TcpStream, payload: &[u8]) -> Result<(), ClientError> {
    let framed = frame(payload).map_err(ClientError::Transport)?;
    stream
        .write_all(&framed)
        .map_err(ClientError::WriteHandshake)
}

fn read_framed(stream: &mut TcpStream) -> Result<Vec<u8>, ClientError> {
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .map_err(ClientError::ReadHandshake)?;
    let len = read_frame_length(&len_buf).map_err(ClientError::Transport)?;
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(ClientError::ReadHandshake)?;
    Ok(body)
}

fn load_psk(path: &PathBuf) -> Result<[u8; 32], ClientError> {
    let text = std::fs::read_to_string(path).map_err(|source| ClientError::ReadPsk {
        path: path.clone(),
        source,
    })?;
    let hex = text.trim();
    if hex.len() != 64 {
        return Err(ClientError::BadPskLen {
            path: path.clone(),
            got: hex.len(),
        });
    }
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for i in 0..32 {
        let hi = decode_nibble(bytes[2 * i]).ok_or_else(|| ClientError::BadPskHex {
            path: path.clone(),
            byte: bytes[2 * i],
        })?;
        let lo = decode_nibble(bytes[2 * i + 1]).ok_or_else(|| ClientError::BadPskHex {
            path: path.clone(),
            byte: bytes[2 * i + 1],
        })?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn decode_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
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
    #[error("identity {identity:?} is empty, too long, or contains disallowed chars")]
    BadIdentity { identity: String },
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
    #[error("Noise transport error")]
    Transport(#[source] TransportError),
}
