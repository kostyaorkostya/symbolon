//! Token-bucket rate limiter for log-event flooding control.
//!
//! Single consumer today: the `identity_unknown` warn in
//! `daemon::handle_connection`. Unknown-identity probes are
//! attacker-triggerable at line rate; without a cap they can flood
//! the operator's journal. The bucket bounds the event rate while a
//! suppressed-count keeps the log stream honest about what was
//! dropped.
//!
//! Time is abstract, same philosophy as `TtlCache`: a `fn() -> T`
//! clock baked in at construction. Making that possible without
//! numeric bounds is why this is implemented as GCRA (the
//! virtual-scheduling formulation of a token bucket, RFC 2697's
//! ancestor from ATM traffic contracts): instead of counting tokens
//! — which needs elapsed-time division for refill — it tracks the
//! *theoretical arrival time* of the next conforming event. The only
//! operations on time are `Ord` and instant-plus-duration
//! (`T: Add<D, Output = T>`), satisfied by `Instant`/`Duration` in
//! the daemon and by plain integers in tests.

use std::cmp::max;
use std::ops::Add;

pub struct TokenBucket<T, D> {
    clock: fn() -> T,
    /// Sustained rate: one event per `refill_interval`.
    refill_interval: D,
    /// Burst allowance expressed in time: a bucket that admits a
    /// burst of N events has tolerance `(N - 1) * refill_interval`.
    /// Precomputed by the caller — keeping the multiplication out of
    /// this type is what keeps `D`'s bounds at `Copy`.
    burst_tolerance: D,
    /// Theoretical arrival time of the next conforming event. An
    /// event at `now` conforms iff `tat <= now + burst_tolerance`;
    /// each conforming event pushes `tat` forward one interval from
    /// `max(tat, now)`. Long idle periods pull `max(tat, now)` down
    /// to `now`, which restores the full burst — no token counter to
    /// cap, no remainder to carry.
    tat: T,
    /// Events rejected since the last accepted one. Reported (and
    /// reset) on the next accept so operators can see the gap size.
    suppressed: u64,
}

impl<T, D> TokenBucket<T, D>
where
    T: Copy + Ord + Add<D, Output = T>,
    D: Copy,
{
    pub fn new(refill_interval: D, burst_tolerance: D, clock: fn() -> T) -> Self {
        Self {
            clock,
            refill_interval,
            burst_tolerance,
            tat: clock(),
            suppressed: 0,
        }
    }

    /// Try to admit one event. `Some(suppressed)` means the caller
    /// may proceed (log the event); `suppressed` is how many events
    /// were rejected since the previous accept — include it in the
    /// log line when non-zero. `None` means suppress.
    pub fn try_acquire(&mut self) -> Option<u64> {
        let now = (self.clock)();
        if self.tat <= now + self.burst_tolerance {
            self.tat = max(self.tat, now) + self.refill_interval;
            Some(std::mem::take(&mut self.suppressed))
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        static NOW: Cell<u64> = const { Cell::new(0) };
    }

    fn test_clock() -> u64 {
        NOW.with(|c| c.get())
    }

    fn set_time(t: u64) {
        NOW.with(|c| c.set(t));
    }

    /// Burst of 2, then one event per 6 ticks sustained.
    fn bucket() -> TokenBucket<u64, u64> {
        set_time(0);
        TokenBucket::new(6, 6, test_clock)
    }

    #[test]
    fn allows_up_to_burst_then_suppresses() {
        let mut b = bucket();
        assert_eq!(b.try_acquire(), Some(0));
        assert_eq!(b.try_acquire(), Some(0));
        assert_eq!(b.try_acquire(), None);
        assert_eq!(b.try_acquire(), None);
    }

    #[test]
    fn refill_reports_suppressed_count() {
        let mut b = bucket();
        assert_eq!(b.try_acquire(), Some(0));
        assert_eq!(b.try_acquire(), Some(0));
        for _ in 0..5 {
            assert_eq!(b.try_acquire(), None);
        }
        // One refill interval later: one slot back, and the accept
        // reports the 5 suppressed events.
        set_time(6);
        assert_eq!(b.try_acquire(), Some(5));
        assert_eq!(b.try_acquire(), None);
    }

    #[test]
    fn burst_caps_after_long_idle() {
        let mut b = bucket();
        // A long quiet period must not bank more than the burst.
        set_time(600);
        assert_eq!(b.try_acquire(), Some(0));
        assert_eq!(b.try_acquire(), Some(0));
        assert_eq!(b.try_acquire(), None);
    }

    #[test]
    fn sustained_rate_is_one_per_interval() {
        set_time(0);
        // Burst of 1 (zero tolerance): strict one-per-interval.
        let mut b: TokenBucket<u64, u64> = TokenBucket::new(6, 0, test_clock);
        assert_eq!(b.try_acquire(), Some(0));
        assert_eq!(b.try_acquire(), None);
        // A late arrival (9 = 1.5 intervals) is admitted, and the
        // spacing clock restarts from ITS timestamp — GCRA carries
        // no partial-interval credit (`max(tat, now)`); that is what
        // bounds the burst after idle without a token counter.
        set_time(9);
        assert_eq!(b.try_acquire(), Some(1));
        assert_eq!(b.try_acquire(), None);
        // Not at 12 (old-schedule phase) but at 15 (9 + interval).
        set_time(12);
        assert_eq!(b.try_acquire(), None);
        set_time(15);
        assert_eq!(b.try_acquire(), Some(2));
    }
}
