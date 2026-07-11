//! Daemon side of the `file` signing backend. Spawns the
//! `__sign-agent` subprocess over a `SOCK_SEQPACKET` socketpair
//! (pre-sandbox, while `execve` is still permitted) and drives it from
//! a dedicated blocking OS-thread actor — SEQPACKET has no compio
//! wrapper, and the per-request `send`/`recv` is blocking anyway.
//!
//! Construction is two-phase to fit the startup order (AGENTS.md):
//! [`AgentSpawn::spawn`] forks the agent *before* the daemon sandboxes
//! itself; [`AgentSpawn::into_backend`] starts the actor thread
//! *after*, so the thread inherits the Landlock ruleset (blocking
//! `send`/`recv` on an already-open fd is unaffected by it).

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Child;
use std::sync::mpsc;
use std::thread::JoinHandle;

use futures_channel::oneshot;

use crate::providers::agent_protocol::{
    AGENT_FD_ENV, AgentRequest, AgentResponse, MAX_MESSAGE, decode, encode,
};
use crate::providers::jwt_backend::{JwtBackend, JwtBackendError, JwtClaims, SpawnedBackend};

/// A request handed to the actor thread: raw request datagram plus a
/// oneshot for the raw response datagram.
struct Job {
    request: Vec<u8>,
    reply: oneshot::Sender<Result<Vec<u8>, JwtBackendError>>,
}

/// Pre-sandbox spawn result: the daemon's socket end plus the child
/// handle, not yet serving. Held only briefly, between the fork and
/// the post-sandbox [`Self::into_backend`].
pub struct AgentSpawn {
    sock: OwnedFd,
    child: Child,
}

impl AgentSpawn {
    /// Fork the signing agent. MUST run before the daemon applies
    /// Landlock (which denies `execve`). `exe` is the current
    /// binary (`/proc/self/exe`); `key_path` is handed to the agent as
    /// `--key-file`.
    pub fn spawn(exe: &Path, key_path: &Path) -> Result<Self, JwtBackendError> {
        let (daemon_sock, child_sock) = seqpacket_pair()?;
        let child_fd = child_sock.as_raw_fd();

        let mut cmd = std::process::Command::new(exe);
        cmd.arg("__sign-agent")
            .arg("--key-file")
            .arg(key_path)
            .env(AGENT_FD_ENV, child_fd.to_string())
            // The agent has no business with the supervisor's listen
            // fds; strip the handoff env so a confused agent can't
            // reclaim them.
            .env_remove("LISTEN_PID")
            .env_remove("LISTEN_FDS")
            .env_remove("LISTEN_FDNAMES");

        // The child end is CLOEXEC (socketpair sets it); clear that on
        // exactly this fd in the forked child so it survives exec and
        // the agent can reclaim it by number. The daemon end stays
        // CLOEXEC, so it never leaks into the agent.
        // SAFETY: pre_exec runs post-fork, pre-exec, in the child. It
        // does one async-signal-safe fcntl and no allocation.
        unsafe {
            cmd.pre_exec(move || {
                let flags = libc::fcntl(child_fd, libc::F_GETFD);
                if flags < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(child_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let child = cmd
            .spawn()
            .map_err(|e| JwtBackendError::Construct(format!("spawn sign-agent: {e}")))?;
        // The fork duplicated `child_sock` into the child; the parent
        // must close ITS copy or `daemon_sock` never observes EOF when
        // the agent exits (EOF requires every writer of the peer end to
        // be closed). Scope-drop at the end of `spawn` would achieve the
        // same, but the ordering here is load-bearing enough to state.
        drop(child_sock);
        Ok(Self {
            sock: daemon_sock,
            child,
        })
    }

    fn start(self) -> AgentBackend {
        let (tx, rx) = mpsc::channel::<Job>();
        let sock = self.sock;
        let mut child = self.child;
        let thread = std::thread::Builder::new()
            .name("sign-agent-io".to_string())
            .spawn(move || {
                let fd = sock.as_raw_fd();
                let mut buf = vec![0u8; MAX_MESSAGE];
                while let Ok(job) = rx.recv() {
                    let result = round_trip(fd, &job.request, &mut buf);
                    let dead = result.is_err();
                    let _ = job.reply.send(result);
                    if dead {
                        break;
                    }
                }
                // Actor is done (channel closed on Drop, or the agent
                // died). Reap the child so it doesn't zombie; the
                // socket closes on `sock` drop, which the agent sees as
                // EOF and exits.
                drop(sock);
                let _ = child.wait();
            })
            .expect("spawn sign-agent-io thread");
        AgentBackend {
            tx: Some(tx),
            thread: Some(thread),
        }
    }
}

impl SpawnedBackend for AgentSpawn {
    fn into_backend(self: Box<Self>) -> Box<dyn JwtBackend> {
        Box::new(self.start())
    }
}

/// One blocking request/response on the socketpair. A closed or
/// errored socket means the agent died — surfaced as `BackendDead`.
fn round_trip(fd: RawFd, request: &[u8], buf: &mut [u8]) -> Result<Vec<u8>, JwtBackendError> {
    send(fd, request)?;
    let n = recv(fd, buf)?;
    if n == 0 {
        return Err(JwtBackendError::BackendDead);
    }
    Ok(buf[..n].to_vec())
}

/// The daemon-side handle. Dropping it closes the job channel, which
/// ends the actor loop, closes the socket (agent sees EOF and exits),
/// and reaps the child.
pub struct AgentBackend {
    tx: Option<mpsc::Sender<Job>>,
    thread: Option<JoinHandle<()>>,
}

impl AgentBackend {
    async fn round_trip(&self, request: AgentRequest) -> Result<AgentResponse, JwtBackendError> {
        let bytes = encode(&request).map_err(JwtBackendError::Protocol)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .as_ref()
            .ok_or(JwtBackendError::BackendDead)?
            .send(Job {
                request: bytes,
                reply: reply_tx,
            })
            .map_err(|_| JwtBackendError::BackendDead)?;
        let response_bytes = reply_rx.await.map_err(|_| JwtBackendError::BackendDead)??;
        decode(&response_bytes).map_err(JwtBackendError::Protocol)
    }
}

#[async_trait::async_trait(?Send)]
impl JwtBackend for AgentBackend {
    async fn sign(&self, claims: &JwtClaims) -> Result<String, JwtBackendError> {
        match self
            .round_trip(AgentRequest::SignJwt {
                claims: claims.clone(),
            })
            .await?
        {
            AgentResponse::Jwt(jwt) => Ok(jwt),
            AgentResponse::Error(msg) => Err(JwtBackendError::Rejected(msg)),
            AgentResponse::Pong => Err(JwtBackendError::Protocol("expected Jwt, got Pong".into())),
        }
    }

    async fn self_check(&self) -> Result<(), JwtBackendError> {
        match self.round_trip(AgentRequest::Ping).await? {
            AgentResponse::Pong => Ok(()),
            AgentResponse::Error(msg) => Err(JwtBackendError::Rejected(msg)),
            AgentResponse::Jwt(_) => {
                Err(JwtBackendError::Protocol("expected Pong, got Jwt".into()))
            }
        }
    }
}

impl Drop for AgentBackend {
    fn drop(&mut self) {
        // Close the job channel so the actor loop ends, then join.
        drop(self.tx.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// `socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0)`.
fn seqpacket_pair() -> Result<(OwnedFd, OwnedFd), JwtBackendError> {
    use std::os::fd::FromRawFd;
    let mut fds = [0 as RawFd; 2];
    // SAFETY: `fds` is a valid 2-element array; socketpair fills it.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(JwtBackendError::Construct(format!(
            "socketpair: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: both fds are freshly created and owned by us.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn send(fd: RawFd, bytes: &[u8]) -> Result<(), JwtBackendError> {
    // SAFETY: `bytes` is a valid readable slice; SEQPACKET send is one
    // atomic datagram.
    let n = unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), 0) };
    if n < 0 {
        return Err(JwtBackendError::Io(format!(
            "send: {}",
            std::io::Error::last_os_error()
        )));
    }
    if n as usize != bytes.len() {
        return Err(JwtBackendError::Io(format!(
            "short send: {n} of {}",
            bytes.len()
        )));
    }
    Ok(())
}

fn recv(fd: RawFd, buf: &mut [u8]) -> Result<usize, JwtBackendError> {
    loop {
        // SAFETY: `buf` is a valid writable slice.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(JwtBackendError::Io(format!("recv: {err}")));
        }
        return Ok(n as usize);
    }
}
