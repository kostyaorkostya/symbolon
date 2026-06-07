//! Single dedicated OS thread for CPU-bound work that mustn't run
//! on the compio runtime thread. Submit closures via [`CpuWorker::run`];
//! results come back through a `futures_channel::oneshot`.
//!
//! Why this exists vs `compio::runtime::spawn_blocking`:
//! compio's blocking pool lazily spawns threads and idles them out
//! after 60 s — for sparse callers, every call after the idle reap
//! pays a ~100-200 µs thread-spawn cost. A dedicated worker thread
//! sidesteps that and shows up with a deterministic name in
//! `top -H` / `ps -L`. See AGENTS.md "Concurrency notes" for the
//! full rationale.
//!
//! One thread per [`CpuWorker`]. If you need parallelism, construct
//! multiple workers; this primitive does not pool internally.
//!
//! Per-call overhead: one boxed-closure allocation, one `mpsc::send`,
//! one oneshot reply. ~5-10 µs on commodity hardware; negligible
//! for any millisecond-scale CPU work.

use std::sync::mpsc;
use std::thread::JoinHandle;

use futures_channel::oneshot;

type Job = Box<dyn FnOnce() + Send + 'static>;

pub struct CpuWorker {
    tx: Option<mpsc::Sender<Job>>,
    // Some until Drop joins the worker thread.
    thread: Option<JoinHandle<()>>,
}

#[derive(Debug, thiserror::Error)]
#[error("CPU worker thread is no longer running")]
pub struct WorkerDead;

impl CpuWorker {
    /// Spawn a new worker thread named `name` (visible in
    /// `/proc/<pid>/task` and `top -H`).
    pub fn new(name: impl Into<String>) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::channel::<Job>();
        let thread = std::thread::Builder::new()
            .name(name.into())
            .spawn(move || worker_loop(rx))?;
        Ok(Self {
            tx: Some(tx),
            thread: Some(thread),
        })
    }

    /// Submit a closure for execution on the worker thread; await
    /// its return value.
    pub async fn run<R>(&self, f: impl FnOnce() -> R + Send + 'static) -> Result<R, WorkerDead>
    where
        R: Send + 'static,
    {
        let (reply_tx, reply_rx) = oneshot::channel();
        let job: Job = Box::new(move || {
            // Caller's future may have been cancelled before the
            // reply lands; drop the result silently in that case.
            let _ = reply_tx.send(f());
        });
        let tx = self.tx.as_ref().ok_or(WorkerDead)?;
        tx.send(job).map_err(|_| WorkerDead)?;
        reply_rx.await.map_err(|_| WorkerDead)
    }
}

impl Drop for CpuWorker {
    /// Structured-concurrency: close the channel so the worker's
    /// recv returns Err, then join the thread before returning. No
    /// background threads outlive the last `Rc<CpuWorker>` clone.
    /// Panics from the worker thread are not propagated (they
    /// already would have surfaced via `WorkerDead` to the awaiter
    /// of the panicking job — see `worker_dead_when_thread_panics`).
    fn drop(&mut self) {
        drop(self.tx.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn worker_loop(rx: mpsc::Receiver<Job>) {
    while let Ok(job) = rx.recv() {
        job();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[compio::test]
    async fn run_returns_closure_result() {
        let w = CpuWorker::new("gcb-test-worker").unwrap();
        let r: i32 = w.run(|| 1 + 2).await.unwrap();
        assert_eq!(r, 3);
    }

    #[compio::test]
    async fn run_moves_captured_state() {
        let w = CpuWorker::new("gcb-test-worker-2").unwrap();
        let v: [u8; 3] = [1, 2, 3];
        let sum: u8 = w.run(move || v.iter().sum()).await.unwrap();
        assert_eq!(sum, 6);
    }

    #[compio::test]
    async fn worker_dead_when_thread_panics() {
        // A panicking job unwinds the worker thread (panic = unwind
        // in dev profile; release is panic = abort, so this test is
        // dev-profile only). The oneshot reply Sender is dropped
        // during unwind, surfacing as `WorkerDead` to the awaiter.
        // A subsequent `run` also fails because the receiver is
        // gone with the thread.
        let w = CpuWorker::new("gcb-test-worker-3").unwrap();
        let res: Result<(), WorkerDead> = w.run(|| panic!("boom")).await;
        assert!(res.is_err());
        let res2: Result<i32, WorkerDead> = w.run(|| 1).await;
        assert!(res2.is_err());
    }
}
