//! Singleflight memo: at most one in-flight resolve per key, with
//! the resolved value cached for the lifetime of the store (no
//! TTL).
//!
//! Used by providers (currently `providers::github`) to coalesce
//! concurrent repository-id resolutions and reuse the result on
//! subsequent mints. Lives at the crate root rather than under
//! `providers/` because the data structure is provider-
//! independent: a future GitLab/Gitea/Forgejo provider with the
//! same lookup-then-mint shape would use it unchanged.
//!
//! Staleness is handled out-of-band by the caller via
//! `invalidate()` — e.g. the GitHub provider invalidates a
//! cached repo-id when a follow-up mint returns 404 (delete-and-
//! recreate at the same path changes the underlying numeric id).
//! There is no time-driven expiry, deliberately: the 404 path is
//! the authoritative signal, and a TTL would only paper over a
//! bug in that path.

use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::Hash;
use std::rc::Rc;

use synchrony::sync::event::Event;

pub(crate) struct SingleflightCache<K, V>(RefCell<HashMap<K, StoreEntry<V>>>);

impl<K, V> Default for SingleflightCache<K, V> {
    fn default() -> Self {
        Self(RefCell::new(HashMap::new()))
    }
}

enum StoreEntry<V> {
    Memo(V),
    // Singleflight marker. The resolver notifies on completion;
    // waiters re-check the store. `Event` is the multi-listener
    // primitive — `AsyncFlag::wait` would only wake one waiter.
    InFlight(Rc<Event>),
}

enum Claim<V> {
    /// A memoised entry covered the key — caller uses this value.
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
    /// Singleflight + memo lookup wrapped as one call: returns
    /// the memoised value if one exists; otherwise admits this
    /// caller to perform the resolve while concurrent callers for
    /// the same key wait. The supplied `resolve` is invoked at
    /// most once per (key, resolution-cycle). Success populates
    /// the memo; failure invalidates the in-flight marker so the
    /// next caller re-resolves.
    pub(crate) async fn with<E>(
        &self,
        key: &K,
        resolve: impl AsyncFnOnce() -> Result<V, E>,
    ) -> Result<V, E> {
        loop {
            match self.claim(key) {
                Claim::Hit(value) => return Ok(value),
                Claim::Wait(ev) => {
                    // Re-check via the loop; the resolver may have
                    // landed a Memo entry or evicted on failure.
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
                        guard.commit_done(value.clone());
                    }
                    return result;
                }
            }
        }
    }

    /// Drop a memoised entry without touching any singleflight
    /// state. The authoritative staleness signal — e.g. the
    /// GitHub provider calls this when a follow-up mint returns
    /// 404, meaning the cached repo-id no longer refers to a
    /// reachable repository.
    pub(crate) fn invalidate(&self, key: &K) {
        self.0.borrow_mut().remove(key);
    }

    /// Atomic test-and-set. Returns `Hit` on a memoised entry,
    /// `Wait` when another task is already resolving (with that
    /// resolver's completion event), or `Resolve` when this
    /// caller should perform the resolve (with a fresh event the
    /// caller's `release_*` will notify on).
    fn claim(&self, key: &K) -> Claim<V> {
        let mut entries = self.0.borrow_mut();
        match entries.get(key) {
            Some(StoreEntry::Memo(value)) => Claim::Hit(value.clone()),
            Some(StoreEntry::InFlight(ev)) => Claim::Wait(Rc::clone(ev)),
            None => {
                let ev = Rc::new(Event::new());
                entries.insert(key.clone(), StoreEntry::InFlight(Rc::clone(&ev)));
                Claim::Resolve(ev)
            }
        }
    }

    /// Release a successful singleflight claim: replace the
    /// `InFlight` marker with a `Memo` entry and wake all waiters
    /// so they re-`claim` and get the new `Hit`.
    fn release_done(&self, key: &K, value: V, event: &Event) {
        self.0
            .borrow_mut()
            .insert(key.clone(), StoreEntry::Memo(value));
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
/// to `release_failed` (`result = None`); an explicit
/// `commit_done` consumes the guard and transitions to
/// `release_done` (`result = Some`). Either way, the matching
/// release happens automatically — a panic, `?`-propagation, or
/// async cancellation between claim and outcome cannot leak the
/// in-flight marker.
struct InFlightGuard<'a, K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    store: &'a SingleflightCache<K, V>,
    key: K,
    event: Rc<Event>,
    result: Option<V>,
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
            result: None,
        }
    }

    /// Mark the resolve as successful. Consumes the guard so
    /// double-commit is impossible.
    fn commit_done(mut self, value: V) {
        self.result = Some(value);
    }
}

impl<K, V> Drop for InFlightGuard<'_, K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    fn drop(&mut self) {
        match self.result.take() {
            Some(value) => self.store.release_done(&self.key, value, &self.event),
            None => self.store.release_failed(&self.key, &self.event),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Throwaway notifier for tests that pre-populate `Memo`
    /// entries without going through the real singleflight claim
    /// flow. No waiters are listening, so `notify` is a no-op.
    fn fake_event() -> Event {
        Event::new()
    }

    #[test]
    fn memo_hit_after_release() {
        let cache: SingleflightCache<String, u64> = SingleflightCache::default();
        let key = "foo/bar".to_string();
        cache.release_done(&key, 42, &fake_event());
        assert_hit(cache.claim(&key), 42);
    }

    #[test]
    fn invalidate_removes_entry() {
        let cache: SingleflightCache<String, u64> = SingleflightCache::default();
        let key = "foo/bar".to_string();
        cache.release_done(&key, 42, &fake_event());
        cache.invalidate(&key);
        assert_resolve(cache.claim(&key));
    }

    #[test]
    fn singleflight_second_caller_waits() {
        let cache: SingleflightCache<String, u64> = SingleflightCache::default();
        let key = "foo/bar".to_string();
        // First caller claims an in-flight slot.
        assert_resolve(cache.claim(&key));
        // Second caller for same key gets a Wait, sharing the
        // first caller's event. Don't call notify (the test only
        // verifies the state-machine transition).
        match cache.claim(&key) {
            Claim::Wait(_) => {}
            Claim::Hit(_) => panic!("expected Wait, got Hit"),
            Claim::Resolve(_) => panic!("expected Wait, got Resolve"),
        }
    }

    #[test]
    fn inflight_guard_drop_invalidates_and_notifies() {
        let cache: SingleflightCache<String, u64> = SingleflightCache::default();
        let key = "foo/bar".to_string();
        let ev = match cache.claim(&key) {
            Claim::Resolve(ev) => ev,
            _ => panic!("expected initial Resolve"),
        };
        // Simulate the resolver future being dropped mid-flight:
        // the guard goes out of scope without being committed.
        {
            let _guard = InFlightGuard::new(&cache, key.clone(), ev);
        }
        // Cache must be empty and a new caller must get Resolve.
        assert_resolve(cache.claim(&key));
    }

    #[test]
    fn inflight_guard_commit_done_puts_entry() {
        let cache: SingleflightCache<String, u64> = SingleflightCache::default();
        let key = "foo/bar".to_string();
        let ev = match cache.claim(&key) {
            Claim::Resolve(ev) => ev,
            _ => panic!("expected initial Resolve"),
        };
        {
            let guard = InFlightGuard::new(&cache, key.clone(), ev);
            // Resolve succeeded; commit_done transitions the guard
            // to `Done`. On drop, the cache receives release_done
            // and waiters are notified.
            guard.commit_done(42);
        }
        // Subsequent callers Hit the committed entry.
        assert_hit(cache.claim(&key), 42);
    }
}
