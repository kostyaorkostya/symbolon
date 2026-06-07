//! Signal-to-cancellation glue. Sits between the kernel signal
//! delivery and the daemon, which knows only about
//! `CancelToken::wait()` and `daemon::reload_clients`.
//!
//! Implementation: a single long-lived OS signal handler is
//! installed once at startup via `signal-hook-registry`, and stays
//! installed for the process lifetime. The handler is restricted to
//! async-signal-safe operations (AtomicBool store + Event::notify,
//! the same shape compio-signal uses internally). A compio task
//! awaits the Event and translates wakeups into shutdown-token
//! cancellation or clients.json reloads.
//!
//! Why not `compio-signal`: its `signal()` future re-registers the
//! handler per call and unregisters on drop, reverting the kernel
//! disposition to SigDfl between iterations. SIGHUP's default is
//! `Term` — a signal arriving in that gap would kill the daemon.
//! See `compio/compio-signal/src/unix/mod.rs:39-52` for the
//! unregister path.

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use compio::runtime::{CancelToken, JoinHandle};
use futures_util::FutureExt;
use synchrony::sync::event::Event;

use crate::daemon::{self, SharedState};

/// Install long-lived handlers for SIGTERM + SIGINT, spawn the task
/// that waits on either and cancels `shutdown`. Returns the task's
/// JoinHandle, whose Output is the signal name.
pub fn spawn_shutdown_watcher(shutdown: CancelToken) -> JoinHandle<&'static str> {
    let event = Arc::new(Event::new());
    let term_pending = Arc::new(AtomicBool::new(false));
    let int_pending = Arc::new(AtomicBool::new(false));

    // SAFETY: closures only touch AtomicBool (lock-free) and
    // event_listener::Event::notify (lock-free atomic ops in the
    // hot path). Both are async-signal-safe per the precedent set
    // by compio-signal's own handler.
    unsafe {
        let pending = term_pending.clone();
        let ev = event.clone();
        let _ = signal_hook_registry::register(libc::SIGTERM, move || {
            pending.store(true, Ordering::Relaxed);
            ev.notify(usize::MAX);
        });
        let pending = int_pending.clone();
        let ev = event.clone();
        let _ = signal_hook_registry::register(libc::SIGINT, move || {
            pending.store(true, Ordering::Relaxed);
            ev.notify(usize::MAX);
        });
    }

    compio::runtime::spawn(async move {
        loop {
            // Register listener BEFORE checking flags. This closes
            // the race where a signal handler fires between our
            // flag-check and our listen() call.
            let listener = event.listen();
            if term_pending.load(Ordering::Relaxed) || int_pending.load(Ordering::Relaxed) {
                drop(listener);
            } else {
                listener.await;
            }
            let sig = if term_pending.swap(false, Ordering::Relaxed) {
                "SIGTERM"
            } else if int_pending.swap(false, Ordering::Relaxed) {
                "SIGINT"
            } else {
                continue;
            };
            shutdown.cancel();
            return sig;
        }
    })
}

/// Install a long-lived handler for SIGHUP, spawn the task that
/// reloads `clients.json` on each delivery. Exits cleanly when
/// `shutdown` fires.
pub fn spawn_sighup_handler(
    state: Rc<SharedState>,
    clients_path: PathBuf,
    shutdown: CancelToken,
) -> JoinHandle<()> {
    let event = Arc::new(Event::new());
    let pending = Arc::new(AtomicBool::new(false));

    // SAFETY: same as spawn_shutdown_watcher above.
    unsafe {
        let pending = pending.clone();
        let ev = event.clone();
        let _ = signal_hook_registry::register(libc::SIGHUP, move || {
            pending.store(true, Ordering::Relaxed);
            ev.notify(usize::MAX);
        });
    }

    compio::runtime::spawn(async move {
        loop {
            let listener = event.listen();
            let already_pending = pending.load(Ordering::Relaxed);
            if !already_pending {
                futures_util::select! {
                    _ = listener.fuse() => {}
                    _ = shutdown.clone().wait().fuse() => return,
                }
            }
            if pending.swap(false, Ordering::Relaxed) {
                daemon::reload_clients(&state, &clients_path).await;
            }
        }
    })
}
