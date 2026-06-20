//! Singleflight + TTL cache: at most one in-flight resolve per
//! key, with cached results served until they expire.
//!
//! Used by providers (currently `providers::github`) to coalesce
//! concurrent repository-id resolutions while keeping the result
//! memoised between mints. Lives at the crate root rather than
//! under `providers/` because the data structure is provider-
//! independent: a future GitLab/Gitea/Forgejo provider with the
//! same lookup-then-mint shape would use it unchanged.
//!
//! Both concerns share one `HashMap` allocation: `Cached` entries
//! serve as the memo (with `expires_at`); `InFlight` entries
//! serve as the singleflight marker (with the `Event` waiters
//! listen on).

use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::Hash;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use synchrony::sync::event::Event;

pub(crate) struct SingleflightCache<K, V>(RefCell<HashMap<K, StoreEntry<V>>>);

impl<K, V> Default for SingleflightCache<K, V> {
    fn default() -> Self {
        Self(RefCell::new(HashMap::new()))
    }
}

enum StoreEntry<V> {
    Cached { value: V, expires_at: SystemTime },
    // Singleflight marker. The resolver notifies on completion;
    // waiters re-check the store. `Event` is the multi-listener
    // primitive — `AsyncFlag::wait` would only wake one waiter.
    InFlight(Rc<Event>),
}

enum Claim<V> {
    /// A fresh `Cached` entry covered the key — caller uses this value.
    Hit(V),
    /// Another caller is already resolving this key — await this
    /// event, then re-`claim` to read the result.
    Wait(Rc<Event>),
    /// This caller owns the resolve. Run the work, then commit on
    /// success or let `InFlightGuard` invalidate on Drop.
    Resolve(Rc<Event>),
}

impl<K, V> SingleflightCache<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    /// Singleflight + cache lookup wrapped as one call: returns a
    /// fresh `Cached` value if one exists; otherwise admits this
    /// caller to perform the resolve while concurrent callers for
    /// the same key wait. The supplied `resolve` is invoked at
    /// most once per (key, resolution-cycle). Success populates
    /// the cache until `now + ttl`; failure invalidates the in-
    /// flight marker so the next caller re-resolves.
    pub(crate) async fn with<E>(
        &self,
        key: &K,
        now: SystemTime,
        ttl: Duration,
        resolve: impl AsyncFnOnce() -> Result<V, E>,
    ) -> Result<V, E> {
        loop {
            match self.claim(key, now) {
                Claim::Hit(value) => return Ok(value),
                Claim::Wait(ev) => {
                    // Re-check via the loop; the resolver may have
                    // landed a Cached entry, evicted on failure, or
                    // raced ahead leaving Cached already expired.
                    ev.listen().await;
                }
                Claim::Resolve(ev) => {
                    // RAII guard defaults to Failed (release_failed
                    // on Drop) so a cancelled or errored resolve
                    // wakes waiters automatically. `commit_done`
                    // transitions to Done (release_done on Drop).
                    let guard = InFlightGuard::new(self, key.clone(), ev);
                    let result = resolve().await;
                    if let Ok(value) = &result {
                        guard.commit_done(value.clone(), now + ttl);
                    }
                    return result;
                }
            }
        }
    }

    /// Drop a `Cached` entry without touching any singleflight
    /// state. Useful when an external signal (e.g. a follow-up
    /// 404 from the provider) tells the caller the cached value
    /// is stale and the next request should re-resolve.
    pub(crate) fn invalidate(&self, key: &K) {
        self.0.borrow_mut().remove(key);
    }

    /// Atomic test-and-set. Returns `Hit` on a fresh `Cached`
    /// entry, `Wait` when another task is already resolving (with
    /// that resolver's completion event), or `Resolve` when this
    /// caller should perform the resolve (with a fresh event the
    /// caller's `release_*` will notify on).
    fn claim(&self, key: &K, now: SystemTime) -> Claim<V> {
        let mut entries = self.0.borrow_mut();
        match entries.get(key) {
            Some(StoreEntry::Cached { value, expires_at }) if *expires_at > now => {
                Claim::Hit(value.clone())
            }
            Some(StoreEntry::InFlight(ev)) => Claim::Wait(Rc::clone(ev)),
            _ => {
                let ev = Rc::new(Event::new());
                entries.insert(key.clone(), StoreEntry::InFlight(Rc::clone(&ev)));
                Claim::Resolve(ev)
            }
        }
    }

    /// Release a successful singleflight claim: replace the
    /// `InFlight` marker with a fresh `Cached` entry and wake all
    /// waiters so they re-`claim` and get the new `Hit`.
    fn release_done(&self, key: &K, value: V, expires_at: SystemTime, event: &Event) {
        self.0
            .borrow_mut()
            .insert(key.clone(), StoreEntry::Cached { value, expires_at });
        event.notify(usize::MAX);
    }

    /// Release a failed singleflight claim: drop the entry and
    /// wake waiters so they re-`claim`, see no entry, and
    /// themselves get `Resolve` (one of them re-runs the work).
    fn release_failed(&self, key: &K, event: &Event) {
        self.0.borrow_mut().remove(key);
        event.notify(usize::MAX);
    }
}

/// RAII shell around a `Claim::Resolve` outcome. Drops default
/// to `release_failed`; an explicit `commit_done` consumes the
/// guard and transitions to `release_done`. Either way, the
/// matching release happens automatically — a panic, `?`-
/// propagation, or async cancellation between claim and outcome
/// cannot leak the in-flight marker.
struct InFlightGuard<'a, K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    store: &'a SingleflightCache<K, V>,
    key: K,
    event: Rc<Event>,
    resolution: Resolution<V>,
}

enum Resolution<V> {
    Failed,
    Done(V, SystemTime),
}

impl<'a, K, V> InFlightGuard<'a, K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    fn new(store: &'a SingleflightCache<K, V>, key: K, event: Rc<Event>) -> Self {
        Self {
            store,
            key,
            event,
            resolution: Resolution::Failed,
        }
    }

    /// Mark the resolve as successful. Consumes the guard so
    /// double-commit is impossible.
    fn commit_done(mut self, value: V, expires_at: SystemTime) {
        self.resolution = Resolution::Done(value, expires_at);
    }
}

impl<K, V> Drop for InFlightGuard<'_, K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    fn drop(&mut self) {
        // `mem::replace` moves the V out of `&mut self` without
        // cloning; `Failed` is the harmless placeholder we leave
        // behind in a value about to be dropped anyway.
        match std::mem::replace(&mut self.resolution, Resolution::Failed) {
            Resolution::Done(value, exp) => {
                self.store.release_done(&self.key, value, exp, &self.event);
            }
            Resolution::Failed => self.store.release_failed(&self.key, &self.event),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn t(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn assert_hit(action: Claim<u64>, expected: u64) {
        match action {
            Claim::Hit(v) => assert_eq!(v, expected),
            Claim::Wait(_) => panic!("expected Hit, got Wait"),
            Claim::Resolve(_) => panic!("expected Hit, got Resolve"),
        }
    }

    fn assert_resolve(action: Claim<u64>) {
        match action {
            Claim::Resolve(_) => {}
            Claim::Hit(_) => panic!("expected Resolve, got Hit"),
            Claim::Wait(_) => panic!("expected Resolve, got Wait"),
        }
    }

    /// Throwaway notifier for tests that pre-populate `Cached`
    /// entries without going through the real singleflight claim
    /// flow. No waiters are listening, so `notify` is a no-op.
    fn fake_event() -> Event {
        Event::new()
    }

    #[test]
    fn cache_done_hit_within_ttl() {
        let cache: SingleflightCache<String, u64> = SingleflightCache::default();
        let now = t(1_000_000);
        let key = "foo/bar".to_string();
        cache.release_done(&key, 42, now + Duration::from_secs(600), &fake_event());
        assert_hit(cache.claim(&key, now), 42);
        assert_hit(cache.claim(&key, now + Duration::from_secs(599)), 42);
    }

    #[test]
    fn cache_done_miss_when_expired() {
        let cache: SingleflightCache<String, u64> = SingleflightCache::default();
        let now = t(1_000_000);
        let key = "foo/bar".to_string();
        cache.release_done(&key, 42, now + Duration::from_secs(600), &fake_event());
        // Expired entry yields Resolve (the new caller takes
        // ownership of refreshing it).
        assert_resolve(cache.claim(&key, now + Duration::from_secs(601)));
    }

    #[test]
    fn cache_invalidate_removes_entry() {
        let cache: SingleflightCache<String, u64> = SingleflightCache::default();
        let now = t(1_000_000);
        let key = "foo/bar".to_string();
        cache.release_done(&key, 42, now + Duration::from_secs(600), &fake_event());
        cache.invalidate(&key);
        assert_resolve(cache.claim(&key, now));
    }

    #[test]
    fn cache_singleflight_second_caller_waits() {
        let cache: SingleflightCache<String, u64> = SingleflightCache::default();
        let now = t(1_000_000);
        let key = "foo/bar".to_string();
        // First caller claims an in-flight slot.
        assert_resolve(cache.claim(&key, now));
        // Second caller for same key gets a Wait, sharing the
        // first caller's event. Don't call notify (the test only
        // verifies the state-machine transition).
        match cache.claim(&key, now) {
            Claim::Wait(_) => {}
            Claim::Hit(_) => panic!("expected Wait, got Hit"),
            Claim::Resolve(_) => panic!("expected Wait, got Resolve"),
        }
    }

    #[test]
    fn inflight_guard_drop_invalidates_and_notifies() {
        let cache: SingleflightCache<String, u64> = SingleflightCache::default();
        let now = t(1_000_000);
        let key = "foo/bar".to_string();
        let ev = match cache.claim(&key, now) {
            Claim::Resolve(ev) => ev,
            _ => panic!("expected initial Resolve"),
        };
        // Simulate the resolver future being dropped mid-flight:
        // the guard goes out of scope without being committed.
        {
            let _guard = InFlightGuard::new(&cache, key.clone(), ev);
        }
        // Cache must be empty and a new caller must get Resolve.
        assert_resolve(cache.claim(&key, now));
    }

    #[test]
    fn inflight_guard_commit_done_puts_entry() {
        let cache: SingleflightCache<String, u64> = SingleflightCache::default();
        let now = t(1_000_000);
        let key = "foo/bar".to_string();
        let ev = match cache.claim(&key, now) {
            Claim::Resolve(ev) => ev,
            _ => panic!("expected initial Resolve"),
        };
        {
            let guard = InFlightGuard::new(&cache, key.clone(), ev);
            // Resolve succeeded; commit_done transitions the guard
            // to `Done`. On drop, the cache receives release_done
            // and waiters are notified.
            guard.commit_done(42, now + Duration::from_secs(600));
        }
        // Subsequent callers Hit the committed entry.
        assert_hit(cache.claim(&key, now), 42);
    }
}
