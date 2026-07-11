//! `tpm` signing backend: RSA in a vTPM, in-process. The daemon
//! computes SHA-256 of the JWS signing input in Rust and sends only
//! the 32-byte digest across to the TPM; the private key never exists
//! in the daemon's address space.
//!
//! A dedicated OS-thread actor exclusively owns the device fd: one
//! `write(2)` of the full command buffer, then one `read(2)` of the
//! full response, per request. The device is opened blocking,
//! pre-sandbox (the sandbox never grants the device path, so the fd
//! must be acquired before restriction and then held for the process
//! lifetime). `O_NONBLOCK` is deliberately NOT set — the async chardev
//! path has a known poll-hang footgun; blocking I/O behind a
//! dedicated thread is the accepted design.
//!
//! Wire marshaling uses the zero-dependency `tpm2-protocol` crate for
//! command construction and response-code decoding; the two fixed-shape
//! response parameters (an RSASSA signature, a TPMT_PUBLIC key area)
//! are parsed by hand since their layouts are fully determined for an
//! RSA-2048 key. Validated against a live swtpm in the gated
//! `tests/tpm_backend.rs` smoke test.

use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::mpsc;
use std::thread::JoinHandle;

use futures_channel::oneshot;
use sha2::{Digest, Sha256};

use crate::providers::jwt_backend::{JwtBackend, JwtBackendError, JwtClaims, SpawnedBackend};
use crate::providers::jwt_rs256;

mod wire;

/// Largest TPM command/response we exchange. RSA-2048 signatures and
/// public areas are well under 1 KiB; 4 KiB matches the TCG
/// `TPM_MAX_COMMAND_SIZE` conventional cap.
const TPM_IO_BUF: usize = 4096;

/// A command datagram plus a oneshot for the raw response bytes.
struct Job {
    command: Vec<u8>,
    reply: oneshot::Sender<Result<Vec<u8>, JwtBackendError>>,
}

/// Pre-sandbox device acquisition: holds the fd and the configured
/// signing handle, not yet serving.
pub struct TpmSpawn {
    fd: OwnedFd,
    persistent_handle: u32,
}

impl TpmSpawn {
    /// Open the TPM device blocking. MUST run before the daemon
    /// sandbox (which never grants the device path).
    pub fn open(device_path: &Path, persistent_handle: u32) -> Result<Self, JwtBackendError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_path)
            .map_err(|e| {
                JwtBackendError::Construct(format!("open {}: {e}", device_path.display()))
            })?;
        Ok(Self {
            fd: OwnedFd::from(file),
            persistent_handle,
        })
    }

    /// Build from an already-connected fd. Test-only: the smoke test
    /// connects swtpm's `unixio` server socket (which speaks the same
    /// raw command/response format as the char device) and hands the
    /// fd here.
    #[doc(hidden)]
    pub fn from_fd(fd: OwnedFd, persistent_handle: u32) -> Self {
        Self {
            fd,
            persistent_handle,
        }
    }

    /// Start the fd-owning actor thread. Call after the daemon sandbox
    /// is in place so the thread inherits it (blocking read/write on
    /// the already-open device fd is unaffected).
    fn start(self) -> TpmBackend {
        let (tx, rx) = mpsc::channel::<Job>();
        let fd = self.fd;
        let thread = std::thread::Builder::new()
            .name("tpm-io".to_string())
            .spawn(move || {
                let raw = fd.as_raw_fd();
                while let Ok(job) = rx.recv() {
                    let result = transact(raw, &job.command);
                    let dead = result.is_err();
                    let _ = job.reply.send(result);
                    if dead {
                        break;
                    }
                }
                drop(fd);
            })
            .expect("spawn tpm-io thread");
        TpmBackend {
            tx: Some(tx),
            thread: Some(thread),
            persistent_handle: self.persistent_handle,
        }
    }
}

impl SpawnedBackend for TpmSpawn {
    fn into_backend(self: Box<Self>) -> Box<dyn JwtBackend> {
        Box::new(self.start())
    }
}

/// One command/response transaction: write the full command, then read
/// one response. Raw `write`/`read` (not buffered `std::fs`) so the
/// same path serves a char device and a connected unix socket
/// identically. A short write or read/write error means the device is
/// unusable — surfaced as `BackendDead`.
fn transact(fd: RawFd, command: &[u8]) -> Result<Vec<u8>, JwtBackendError> {
    write_all(fd, command)?;
    let mut buf = vec![0u8; TPM_IO_BUF];
    // SAFETY: `buf` is a valid writable slice of `buf.len()` bytes.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(JwtBackendError::Io(format!(
            "tpm read: {}",
            std::io::Error::last_os_error()
        )));
    }
    if n == 0 {
        return Err(JwtBackendError::BackendDead);
    }
    buf.truncate(n as usize);
    Ok(buf)
}

fn write_all(fd: RawFd, mut bytes: &[u8]) -> Result<(), JwtBackendError> {
    while !bytes.is_empty() {
        // SAFETY: `bytes` is a valid readable slice.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(JwtBackendError::Io(format!("tpm write: {err}")));
        }
        bytes = &bytes[n as usize..];
    }
    Ok(())
}

/// The daemon-side handle. Dropping it ends the actor loop and closes
/// the device fd.
pub struct TpmBackend {
    tx: Option<mpsc::Sender<Job>>,
    thread: Option<JoinHandle<()>>,
    persistent_handle: u32,
}

impl TpmBackend {
    /// Send a raw TPM command to the actor and await the raw response.
    async fn transact(&self, command: Vec<u8>) -> Result<Vec<u8>, JwtBackendError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .as_ref()
            .ok_or(JwtBackendError::BackendDead)?
            .send(Job {
                command,
                reply: reply_tx,
            })
            .map_err(|_| JwtBackendError::BackendDead)?;
        reply_rx.await.map_err(|_| JwtBackendError::BackendDead)?
    }
}

#[async_trait::async_trait(?Send)]
impl JwtBackend for TpmBackend {
    async fn sign(&self, claims: &JwtClaims) -> Result<String, JwtBackendError> {
        // Build the JWS signing input, hash it in-process, and send
        // ONLY the 32-byte digest to the TPM.
        let signing_input = jwt_rs256::signing_input(claims)
            .map_err(|e| JwtBackendError::Backend(e.to_string()))?;
        let digest: [u8; 32] = Sha256::digest(signing_input.as_bytes()).into();

        let command = wire::sign_command(self.persistent_handle, &digest)
            .map_err(|e| JwtBackendError::Backend(format!("build sign: {e}")))?;
        let response = self.transact(command).await?;
        let signature = wire::parse_sign(&response)
            .map_err(|e| JwtBackendError::Backend(format!("sign: {e}")))?;
        Ok(jwt_rs256::assemble_jwt(&signing_input, &signature))
    }

    async fn self_check(&self) -> Result<(), JwtBackendError> {
        let command = wire::read_public_command(self.persistent_handle)
            .map_err(|e| JwtBackendError::Backend(format!("build read_public: {e}")))?;
        let response = self.transact(command).await?;
        wire::verify_rsa2048_signing_key(&response)
            .map_err(|e| JwtBackendError::Backend(format!("read_public: {e}")))
    }
}

impl Drop for TpmBackend {
    fn drop(&mut self) {
        drop(self.tx.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
