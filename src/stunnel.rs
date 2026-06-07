//! stunnel control surface: send SIGHUP to the running stunnel
//! process after we rewrite `gcb.psk`.
//!
//! Why a dedicated module: the dance is non-trivial — read pidfile,
//! open pidfd, verify comm, send signal — and it carries a load-
//! bearing security property (no signal lands on a PID-reused
//! process). Pulling it out of `admin.rs` lets us test it against a
//! real child process and gives the daemon one place to grow if we
//! ever stop signalling via PID at all (e.g. systemd
//! ExecReload=kill -HUP $MAINPID stunnel.service).
//!
//! ## TOCTOU defence (vs. the previous `kill_process(pid)` form)
//!
//! Old shape:
//! 1. read pidfile → pid
//! 2. open `/proc/<pid>/comm`, compare to "stunnel"
//! 3. `kill_process(pid, SIGHUP)`
//!
//! Between steps 2 and 3 the original stunnel could exit and the
//! kernel could recycle its PID into an unrelated process; SIGHUP
//! would then land on the wrong target.
//!
//! New shape:
//! 1. read pidfile → pid
//! 2. `pidfd_open(pid)` — returns an `OwnedFd` that **pins** the
//!    process. While the pidfd is held, the kernel won't recycle
//!    that PID (the task_struct is reference-counted by the pidfd).
//! 3. read `/proc/<pid>/comm` — guaranteed to be the same process
//!    the pidfd is bound to.
//! 4. `pidfd_send_signal(&pidfd, SIGHUP)` — targets the pidfd-bound
//!    process atomically (returns ESRCH if it has exited; no chance
//!    of landing on a recycled PID).
//!
//! See `docs/REFERENCES.md` for the kernel man pages; requires Linux
//! 5.1+ (well within our musl deployment baseline).

use std::path::PathBuf;

use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};

#[derive(Debug, thiserror::Error)]
pub enum StunnelError {
    #[error("stunnel pidfile {} is unreadable", path.display())]
    PidfileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("stunnel pidfile {} contained {raw:?} (not a valid PID)", path.display())]
    PidfileParse { path: PathBuf, raw: String },
    #[error("pidfd_open({pid}) failed")]
    PidfdOpen {
        pid: i32,
        #[source]
        source: std::io::Error,
    },
    #[error("/proc/{pid}/comm read failed")]
    CommRead {
        pid: i32,
        #[source]
        source: std::io::Error,
    },
    #[error("/proc/{pid}/comm is {actual:?} (expected \"stunnel\")")]
    CommMismatch { pid: i32, actual: String },
    #[error("pidfd_send_signal(pid={pid}, SIGHUP) failed")]
    SendSignal {
        pid: i32,
        #[source]
        source: std::io::Error,
    },
}

/// Holds the pidfile path; signals stunnel via pidfd on request.
pub struct StunnelController {
    pidfile: PathBuf,
}

impl StunnelController {
    pub fn new(pidfile: PathBuf) -> Self {
        Self { pidfile }
    }

    /// Read the pidfile, open a pidfd, verify the bound process is
    /// stunnel, then send SIGHUP through the pidfd. Closes the
    /// pidfd before returning.
    pub async fn sighup(&self) -> Result<(), StunnelError> {
        let pid_int = self.read_pidfile().await?;
        let pid = Pid::from_raw(pid_int).ok_or_else(|| StunnelError::PidfileParse {
            path: self.pidfile.clone(),
            raw: pid_int.to_string(),
        })?;

        let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(|e| StunnelError::PidfdOpen {
            pid: pid_int,
            source: std::io::Error::from(e),
        })?;

        // pidfd is held across this read, so the PID won't be
        // recycled in the gap between open and the comm check.
        let comm_path = format!("/proc/{pid_int}/comm");
        let comm_bytes =
            compio::fs::read(&comm_path)
                .await
                .map_err(|source| StunnelError::CommRead {
                    pid: pid_int,
                    source,
                })?;
        let comm = std::str::from_utf8(&comm_bytes)
            .map(str::trim)
            .unwrap_or("");
        if comm != "stunnel" {
            return Err(StunnelError::CommMismatch {
                pid: pid_int,
                actual: comm.to_string(),
            });
        }

        pidfd_send_signal(&pidfd, Signal::HUP).map_err(|e| StunnelError::SendSignal {
            pid: pid_int,
            source: std::io::Error::from(e),
        })?;
        Ok(())
    }

    async fn read_pidfile(&self) -> Result<i32, StunnelError> {
        let bytes =
            compio::fs::read(&self.pidfile)
                .await
                .map_err(|source| StunnelError::PidfileRead {
                    path: self.pidfile.clone(),
                    source,
                })?;
        let raw = String::from_utf8(bytes).map_err(|e| StunnelError::PidfileRead {
            path: self.pidfile.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
        })?;
        raw.trim()
            .parse::<i32>()
            .map_err(|_| StunnelError::PidfileParse {
                path: self.pidfile.clone(),
                raw,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    fn write_pidfile(pid: i32) -> PathBuf {
        let path = std::env::temp_dir().join(format!("gcb-stunnel-test-{}.pid", ulid::Ulid::new()));
        std::fs::write(&path, format!("{pid}\n")).unwrap();
        path
    }

    #[compio::test]
    async fn sighup_rejects_non_stunnel_comm() {
        // Spawn `sleep 30` — comm will be "sleep", not "stunnel".
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as i32;
        let pidfile = write_pidfile(pid);
        let controller = StunnelController::new(pidfile.clone());

        let res = controller.sighup().await;
        assert!(
            matches!(res, Err(StunnelError::CommMismatch { .. })),
            "got {res:?}"
        );

        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_file(&pidfile);
    }

    #[compio::test]
    async fn sighup_returns_error_for_missing_pidfile() {
        let path = std::env::temp_dir().join(format!("gcb-stunnel-nope-{}.pid", ulid::Ulid::new()));
        let controller = StunnelController::new(path);
        let res = controller.sighup().await;
        assert!(
            matches!(res, Err(StunnelError::PidfileRead { .. })),
            "got {res:?}"
        );
    }

    #[compio::test]
    async fn sighup_returns_error_for_malformed_pidfile() {
        let path = std::env::temp_dir().join(format!("gcb-stunnel-bad-{}.pid", ulid::Ulid::new()));
        std::fs::write(&path, "not-a-pid\n").unwrap();
        let controller = StunnelController::new(path.clone());
        let res = controller.sighup().await;
        assert!(
            matches!(res, Err(StunnelError::PidfileParse { .. })),
            "got {res:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[compio::test]
    async fn sighup_returns_error_for_dead_pid() {
        // Spawn and reap a child so the PID is freed before we try
        // to signal it. We can't guarantee the kernel won't have
        // already recycled it, but the typical kernel keeps PIDs
        // around long enough for this race window.
        let mut child = Command::new("true").spawn().expect("spawn true");
        let pid = child.id() as i32;
        let _ = child.wait();
        compio::time::sleep(Duration::from_millis(50)).await;
        let pidfile = write_pidfile(pid);
        let controller = StunnelController::new(pidfile.clone());

        let res = controller.sighup().await;
        // Either pidfd_open returns ESRCH (dead) or pid was reused
        // and comm doesn't match. Both are correct rejections.
        assert!(
            matches!(
                res,
                Err(StunnelError::PidfdOpen { .. })
                    | Err(StunnelError::CommMismatch { .. })
                    | Err(StunnelError::CommRead { .. })
            ),
            "got {res:?}",
        );

        let _ = std::fs::remove_file(&pidfile);
    }
}
