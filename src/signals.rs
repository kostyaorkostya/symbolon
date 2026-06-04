//! Signal-to-cancellation glue. Sits between the kernel signal
//! delivery and the daemon, which knows only about
//! `CancelToken::wait()` and `daemon::reload_clients`.
//!
//! Lives outside `crate::daemon` so daemon code stays
//! init-system-agnostic.

use std::path::PathBuf;
use std::rc::Rc;

use compio::runtime::{CancelToken, JoinHandle};
use futures_util::FutureExt;

use crate::daemon::{self, SharedState};

/// Spawns a task that races SIGTERM and SIGINT. On the first to fire
/// it cancels `shutdown` and returns the signal name through its
/// JoinHandle.
pub fn spawn_shutdown_watcher(shutdown: CancelToken) -> JoinHandle<&'static str> {
    compio::runtime::spawn(async move {
        let term = compio::signal::unix::signal(rustix::process::Signal::TERM.as_raw());
        let int = compio::signal::unix::signal(rustix::process::Signal::INT.as_raw());
        futures_util::pin_mut!(term, int);
        let sig: &'static str = futures_util::select! {
            _ = term.as_mut().fuse() => "SIGTERM",
            _ = int.as_mut().fuse() => "SIGINT",
        };
        shutdown.cancel();
        sig
    })
}

/// Spawns a task that loops on SIGHUP and calls
/// [`daemon::reload_clients`] (a free fn — `Service` is consumed by
/// `run`, so we can't go through `&self`). Exits cleanly when
/// `shutdown` fires.
pub fn spawn_sighup_handler(
    state: Rc<SharedState>,
    clients_path: PathBuf,
    shutdown: CancelToken,
) -> JoinHandle<()> {
    compio::runtime::spawn(async move {
        let sig = rustix::process::Signal::HUP.as_raw();
        loop {
            futures_util::select! {
                res = compio::signal::unix::signal(sig).fuse() => {
                    if res.is_err() {
                        break;
                    }
                    daemon::reload_clients(&state, &clients_path).await;
                }
                _ = shutdown.clone().wait().fuse() => break,
            }
        }
    })
}
