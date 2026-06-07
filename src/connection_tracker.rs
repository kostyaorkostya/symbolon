//! Per-connection task bookkeeping with a bounded drain on shutdown.
//!
//! Shape modeled after tokio-util's `TaskTracker` paired with
//! `CancellationToken` (see `tokio/tokio-util/src/task/task_tracker.rs`
//! in the reference clone). Adapted to compio's single-threaded
//! runtime: `thin_cell::unsync::ThinCell<usize>` for the active
//! counter (one-word equivalent of `Rc<RefCell<usize>>`), and
//! `synchrony::sync::event::Event` for the empty notification (the
//! multi-thread variant — `notify` is `&self`).
//!
//! Usage: build with `new(cancel, per_handler_timeout, drain_deadline)`,
//! `spawn(handler)` to launch a connection handler, then
//! `drain(self)` on shutdown to wait for handlers to finish
//! (bounded by `drain_deadline`).
//!
//! Per-handler shutdown observation is NOT delivered through this
//! tracker — handlers reach into `GitHubProvider.cancel` (a clone
//! of the same shutdown token) for the HTTPS calls that dominate
//! their wall-clock time. Short-running UDS reads are bounded by
//! `per_handler_timeout` and by stunnel closing the upstream
//! connection on its own shutdown.

use std::rc::Rc;
use std::time::{Duration, Instant};

use synchrony::sync::event::Event;
use thin_cell::unsync::ThinCell;

pub(crate) struct ConnectionTracker {
    active: ThinCell<usize>,
    empty: Rc<Event>,
    per_handler_timeout: Duration,
    drain_deadline: Duration,
}

/// RAII increment/decrement of the active-handler counter.
/// `Token::new` increments; `Drop` decrements and notifies `empty`
/// when the count returns to zero. Living inside the spawned future
/// makes the decrement panic-safe — a handler panic still runs
/// local `Drop`s, so `drain` is not stuck waiting for a notification
/// that will never come. (Mirror of tokio-util's `TaskTrackerToken`.)
struct Token {
    active: ThinCell<usize>,
    empty: Rc<Event>,
}

impl Token {
    fn new(active: ThinCell<usize>, empty: Rc<Event>) -> Self {
        *active.borrow() += 1;
        Self { active, empty }
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        let mut a = self.active.borrow();
        *a -= 1;
        if *a == 0 {
            self.empty.notify(usize::MAX);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DrainStats {
    /// Per-tracker drain time. Only read by tests; the daemon
    /// reports a wider shutdown window measured by the caller.
    #[allow(dead_code)]
    pub drain_ms: u64,
    pub inflight_drained: usize,
    pub drain_complete: bool,
}

impl ConnectionTracker {
    pub(crate) fn new(per_handler_timeout: Duration, drain_deadline: Duration) -> Self {
        Self {
            active: ThinCell::new(0),
            empty: Rc::new(Event::new()),
            per_handler_timeout,
            drain_deadline,
        }
    }

    /// Spawn a connection handler bounded by `per_handler_timeout`.
    /// The handler is detached; the tracker counts in-flight
    /// handlers and notifies `drain` when the count returns to zero.
    pub(crate) fn spawn<F>(&self, handler: F)
    where
        F: AsyncFnOnce() + 'static,
    {
        let token = Token::new(self.active.clone(), self.empty.clone());
        let timeout = self.per_handler_timeout;
        compio::runtime::spawn(async move {
            // Move token into the future so its Drop fires on
            // normal exit, on timeout, AND on panic.
            let _token = token;
            let _ = compio::time::timeout(timeout, handler()).await;
        })
        .detach();
    }

    /// Consume the tracker, waiting up to `drain_deadline` for all
    /// outstanding handlers to finish. After the deadline, spawned
    /// tasks keep running until their own `per_handler_timeout`
    /// expires; they are not forcibly cancelled by `drain`.
    pub(crate) async fn drain(self) -> DrainStats {
        let start = Instant::now();
        let initial = *self.active.borrow();
        let drain_complete = loop {
            // Register listener BEFORE the active-count check so a
            // decrement-to-zero between the check and the await
            // cannot lose the notification.
            let listener = self.empty.listen();
            if *self.active.borrow() == 0 {
                break true;
            }
            let elapsed = start.elapsed();
            if elapsed >= self.drain_deadline {
                break false;
            }
            let remaining = self.drain_deadline - elapsed;
            if compio::time::timeout(remaining, listener).await.is_err() {
                break false;
            }
        };
        let final_count = *self.active.borrow();
        DrainStats {
            drain_ms: start.elapsed().as_millis() as u64,
            inflight_drained: initial.saturating_sub(final_count),
            drain_complete,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[compio::test]
    async fn drain_returns_immediately_when_no_handlers_spawned() {
        let tracker = ConnectionTracker::new(Duration::from_secs(1), Duration::from_secs(1));
        let stats = tracker.drain().await;
        assert_eq!(stats.inflight_drained, 0);
        assert!(stats.drain_complete);
    }

    #[compio::test]
    async fn drain_waits_for_handlers_to_finish() {
        let tracker = ConnectionTracker::new(Duration::from_secs(5), Duration::from_secs(5));
        tracker.spawn(async || {
            compio::time::sleep(Duration::from_millis(50)).await;
        });
        let stats = tracker.drain().await;
        assert_eq!(stats.inflight_drained, 1);
        assert!(stats.drain_complete);
        assert!(stats.drain_ms >= 40);
    }

    #[compio::test]
    async fn drain_deadline_expires_with_incomplete_status() {
        let tracker = ConnectionTracker::new(Duration::from_secs(60), Duration::from_millis(50));
        tracker.spawn(async || {
            compio::time::sleep(Duration::from_secs(60)).await;
        });
        let stats = tracker.drain().await;
        assert!(!stats.drain_complete, "drain should have timed out");
    }

    // Without the RAII Token, a panicking handler would leave the
    // active counter inflated and `drain` would hang waiting for an
    // empty notification that never fires. With the Token, the
    // decrement runs in the handler future's local Drop chain.
    #[compio::test]
    async fn drain_completes_after_handler_panic() {
        let tracker = ConnectionTracker::new(Duration::from_secs(5), Duration::from_secs(2));
        tracker.spawn(async || {
            panic!("handler boom");
        });
        // Give the spawned task a chance to run and panic.
        compio::time::sleep(Duration::from_millis(50)).await;
        let stats = tracker.drain().await;
        assert!(stats.drain_complete, "drain should complete after panic");
    }
}
