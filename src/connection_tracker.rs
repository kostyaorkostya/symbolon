//! Per-connection task bookkeeping with a bounded drain on shutdown.
//!
//! Shape modeled after tokio-util's `TaskTracker` paired with
//! `CancellationToken` (see `tokio/tokio-util/src/task/task_tracker.rs`
//! in the reference clone). Adapted to compio's single-threaded
//! runtime: `Rc<RefCell<usize>>` for the active counter instead of
//! atomics, and `synchrony::sync::event::Event` for the empty
//! notification (the multi-thread variant — `notify` is `&self`).
//!
//! Usage: build with `new(cancel, per_handler_timeout, drain_deadline)`,
//! `spawn(handler)` to launch a connection handler that gets a clone
//! of the cancel token, then `drain(self)` on shutdown to wait for
//! handlers to finish (bounded by `drain_deadline`).

use std::cell::RefCell;
use std::future::Future;
use std::rc::Rc;
use std::time::{Duration, Instant};

use compio::runtime::CancelToken;
use synchrony::sync::event::Event;

pub(crate) struct ConnectionTracker {
    cancel: CancelToken,
    active: Rc<RefCell<usize>>,
    empty: Rc<Event>,
    per_handler_timeout: Duration,
    drain_deadline: Duration,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DrainStats {
    pub drain_ms: u64,
    pub inflight_drained: usize,
    pub drain_complete: bool,
}

impl ConnectionTracker {
    pub(crate) fn new(
        cancel: CancelToken,
        per_handler_timeout: Duration,
        drain_deadline: Duration,
    ) -> Self {
        Self {
            cancel,
            active: Rc::new(RefCell::new(0)),
            empty: Rc::new(Event::new()),
            per_handler_timeout,
            drain_deadline,
        }
    }

    /// Spawn a connection handler. The handler receives a clone of
    /// the cancel token; it may use that to race per-operation
    /// awaits against shutdown. The handler is also wrapped in a
    /// hard `per_handler_timeout` to bound stuck connections.
    pub(crate) fn spawn<F, Fut>(&self, handler: F)
    where
        F: FnOnce(CancelToken) -> Fut + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        *self.active.borrow_mut() += 1;
        let active = self.active.clone();
        let empty = self.empty.clone();
        let cancel = self.cancel.clone();
        let timeout = self.per_handler_timeout;
        compio::runtime::spawn(async move {
            let _ = compio::time::timeout(timeout, handler(cancel)).await;
            let mut a = active.borrow_mut();
            *a -= 1;
            if *a == 0 {
                empty.notify(usize::MAX);
            }
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
        let drained = initial.saturating_sub(*self.active.borrow());
        DrainStats {
            drain_ms: start.elapsed().as_millis() as u64,
            inflight_drained: drained,
            drain_complete,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[compio::test]
    async fn drain_returns_immediately_when_no_handlers_spawned() {
        let cancel = CancelToken::new();
        let tracker =
            ConnectionTracker::new(cancel, Duration::from_secs(1), Duration::from_secs(1));
        let stats = tracker.drain().await;
        assert_eq!(stats.inflight_drained, 0);
        assert!(stats.drain_complete);
    }

    #[compio::test]
    async fn drain_waits_for_handlers_to_finish() {
        let cancel = CancelToken::new();
        let tracker =
            ConnectionTracker::new(cancel, Duration::from_secs(5), Duration::from_secs(5));
        tracker.spawn(|_| async {
            compio::time::sleep(Duration::from_millis(50)).await;
        });
        let stats = tracker.drain().await;
        assert_eq!(stats.inflight_drained, 1);
        assert!(stats.drain_complete);
        assert!(stats.drain_ms >= 40);
    }

    #[compio::test]
    async fn drain_deadline_expires_with_incomplete_status() {
        let cancel = CancelToken::new();
        let tracker =
            ConnectionTracker::new(cancel, Duration::from_secs(60), Duration::from_millis(50));
        tracker.spawn(|_| async {
            compio::time::sleep(Duration::from_secs(60)).await;
        });
        let stats = tracker.drain().await;
        assert!(!stats.drain_complete, "drain should have timed out");
    }
}
