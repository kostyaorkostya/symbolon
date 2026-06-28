//! Signal-to-cancellation glue. SIGTERM/SIGINT cancel a
//! `CancelToken`; the module is intentionally ignorant of what
//! downstream code does with that cancellation.
//!
//! Implementation: a single long-lived OS signal handler is
//! installed once at startup via `signal-hook-registry`, and stays
//! installed for the process lifetime. The handler is restricted to
//! async-signal-safe operations (`AtomicBool::store` +
//! `AtomicWaker::wake` — both lock-free, no allocation, reentrant).
//! Same shape compio-signal uses internally
//! (`compio/compio-signal/src/unix/mod.rs:15-26`), unbundled here so
//! the notifier survives multiple deliveries (compio-signal's
//! AsyncFlag is consume-on-wait).
//!
//! A compio task awaits the notifier and translates wakeups into
//! shutdown-token cancellation.
//!
//! Why not `compio-signal`: its `signal()` future re-registers the
//! handler per call and unregisters on drop, reverting the kernel
//! disposition to SigDfl between iterations — a SIGTERM arriving in
//! that gap would kill the daemon without giving the shutdown loop
//! a chance to drain. See `compio/compio-signal/src/unix/mod.rs:39-52`
//! for the unregister path.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use compio::runtime::{CancelToken, JoinHandle};
use futures_util::task::AtomicWaker;

/// Long-lived signal notifier: signal handler calls `notify()`,
/// async waiters call `notified().await`. Cleared on each take, so
/// the same instance handles an arbitrary number of deliveries.
///
/// Both `notify` and the swap+register inside `Notified::poll` are
/// lock-free CAS operations on top of `AtomicBool` and
/// `AtomicWaker`. No allocation, no mutex, fully reentrant — safe to
/// call from a signal handler.
#[derive(Default)]
struct SignalNotifier {
    set: AtomicBool,
    waker: AtomicWaker,
}

impl SignalNotifier {
    fn notify(&self) {
        self.set.store(true, Ordering::Release);
        self.waker.wake();
    }

    fn notified(self: Arc<Self>) -> Notified {
        Notified { n: self }
    }
}

struct Notified {
    n: Arc<SignalNotifier>,
}

impl Future for Notified {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.n.set.swap(false, Ordering::AcqRel) {
            return Poll::Ready(());
        }
        self.n.waker.register(cx.waker());
        if self.n.set.swap(false, Ordering::AcqRel) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// Install long-lived handlers for SIGTERM + SIGINT, spawn the task
/// that waits on either and cancels `shutdown`. Returns the task's
/// JoinHandle, whose Output is the signal name.
///
/// Errors from `signal-hook-registry::register` are propagated;
/// failing here means we cannot honour SIGTERM/SIGINT and the
/// caller should treat it as fatal.
pub fn spawn_shutdown_watcher(shutdown: CancelToken) -> io::Result<JoinHandle<&'static str>> {
    let notifier = Arc::new(SignalNotifier::default());
    let term_pending = Arc::new(AtomicBool::new(false));
    let int_pending = Arc::new(AtomicBool::new(false));

    register_async_signal(libc::SIGTERM, term_pending.clone(), notifier.clone())?;
    register_async_signal(libc::SIGINT, int_pending.clone(), notifier.clone())?;

    Ok(compio::runtime::spawn(async move {
        loop {
            if term_pending.swap(false, Ordering::Acquire) {
                shutdown.cancel();
                return "SIGTERM";
            }
            if int_pending.swap(false, Ordering::Acquire) {
                shutdown.cancel();
                return "SIGINT";
            }
            notifier.clone().notified().await;
        }
    }))
}

/// Install an async-signal-safe handler that sets `pending=true` and
/// notifies the shared notifier. The handler is permanent
/// (registered once, never unregistered) and only performs lock-free
/// atomic operations.
fn register_async_signal(
    sig: i32,
    pending: Arc<AtomicBool>,
    notifier: Arc<SignalNotifier>,
) -> io::Result<()> {
    // SAFETY: closure only touches AtomicBool::store (lock-free) and
    // SignalNotifier::notify (AtomicBool::store + AtomicWaker::wake,
    // both lock-free and alloc-free). Matches compio-signal's own
    // handler at compio/compio-signal/src/unix/mod.rs:15-26.
    unsafe {
        signal_hook_registry::register(sig, move || {
            pending.store(true, Ordering::Release);
            notifier.notify();
        })?;
    }
    Ok(())
}
