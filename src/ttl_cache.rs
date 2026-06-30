//! TTL-aware in-memory cache with an embedded clock.
//!
//! Entries expire at a caller-supplied `expires_at: T` instant.
//! The cache needs only `T: Ord` — no wall-clock dependency lives
//! here; the caller supplies a `fn() -> T` at construction.
//!
//! Both [`TtlCache::get_with_expiry`] and [`TtlCache::insert`] sweep
//! all expired entries before acting, keeping memory bounded without
//! a background task.
//!
//! [`TtlCache::invalidate`] removes an entry from the map immediately;
//! the corresponding expiration-queue entry is left as a tombstone and
//! discarded at the next sweep.
//!
//! Single-threaded use only (`RefCell`). Fits naturally in a compio
//! task. Lives at the crate root rather than under `providers/` because
//! the data structure is provider-independent: a future GitLab/Gitea/
//! Forgejo provider with the same mint shape would use it unchanged.

use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::hash_map::Entry;
use std::collections::{BinaryHeap, HashMap};
use std::hash::Hash;

pub struct TtlCache<K, V, T> {
    clock: fn() -> T,
    inner: RefCell<Inner<K, V, T>>,
}

struct Inner<K, V, T> {
    entries: HashMap<K, (V, T)>,
    // Min-heap via `Reverse`: top is the earliest-expiring key.
    // `BinaryHeap` is a max-heap; `Reverse` inverts that so `peek`
    // and `pop` surface the soonest-to-expire entry first.
    expirations: BinaryHeap<Reverse<(T, K)>>,
}

impl<K, V, T> TtlCache<K, V, T>
where
    K: Hash + Eq + Clone + Ord,
    T: Ord + Clone,
{
    pub fn new(clock: fn() -> T) -> Self {
        Self {
            clock,
            inner: RefCell::new(Inner {
                entries: HashMap::new(),
                expirations: BinaryHeap::new(),
            }),
        }
    }

    /// Sweep expired entries, then return the cached value and its
    /// expiry if `key` is present and not yet expired.
    pub fn get_with_expiry(&self, key: &K) -> Option<(V, T)>
    where
        V: Clone,
    {
        let now = (self.clock)();
        let mut inner = self.inner.borrow_mut();
        inner.sweep(&now);
        inner.entries.get(key).map(|(v, t)| (v.clone(), t.clone()))
    }

    /// Sweep expired entries, then insert `value` expiring at
    /// `expires_at`, replacing any existing entry for `key`.
    pub fn insert(&self, key: K, value: V, expires_at: T) {
        let now = (self.clock)();
        let mut inner = self.inner.borrow_mut();
        inner.sweep(&now);
        inner
            .expirations
            .push(Reverse((expires_at.clone(), key.clone())));
        inner.entries.insert(key, (value, expires_at));
    }

    /// Remove the entry for `key` immediately. The expiration-queue
    /// entry is left as a tombstone and discarded at the next sweep.
    pub fn invalidate(&self, key: &K) {
        self.inner.borrow_mut().entries.remove(key);
    }
}

impl<K, V, T> Inner<K, V, T>
where
    K: Hash + Eq + Ord,
    T: Ord,
{
    /// Drain all expiration-queue entries whose deadline ≤ `now`,
    /// evicting the map entry when the stored expiry still matches.
    /// Stale tombstones left by `invalidate` or by a re-insert with
    /// a newer expiry are discarded silently.
    fn sweep(&mut self, now: &T) {
        while self
            .expirations
            .peek()
            .is_some_and(|Reverse((t, _))| t <= now)
        {
            let Reverse((expires_at, k)) = self.expirations.pop().unwrap();
            if let Entry::Occupied(e) = self.entries.entry(k) {
                if e.get().1 == expires_at {
                    e.remove();
                }
            }
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

    #[test]
    fn miss_on_empty() {
        set_time(0);
        let cache: TtlCache<String, u32, u64> = TtlCache::new(test_clock);
        assert_eq!(cache.get_with_expiry(&"k".to_string()), None);
    }

    #[test]
    fn hit_before_expiry() {
        set_time(0);
        let cache: TtlCache<String, u32, u64> = TtlCache::new(test_clock);
        cache.insert("k".to_string(), 42, 100);
        assert_eq!(cache.get_with_expiry(&"k".to_string()), Some((42, 100)));
    }

    #[test]
    fn miss_at_expiry() {
        set_time(0);
        let cache: TtlCache<String, u32, u64> = TtlCache::new(test_clock);
        cache.insert("k".to_string(), 42, 100);
        set_time(100);
        assert_eq!(cache.get_with_expiry(&"k".to_string()), None);
    }

    #[test]
    fn miss_after_expiry() {
        set_time(0);
        let cache: TtlCache<String, u32, u64> = TtlCache::new(test_clock);
        cache.insert("k".to_string(), 42, 100);
        set_time(200);
        assert_eq!(cache.get_with_expiry(&"k".to_string()), None);
    }

    #[test]
    fn invalidate_removes_entry() {
        set_time(0);
        let cache: TtlCache<String, u32, u64> = TtlCache::new(test_clock);
        cache.insert("k".to_string(), 42, 100);
        cache.invalidate(&"k".to_string());
        assert_eq!(cache.get_with_expiry(&"k".to_string()), None);
    }

    #[test]
    fn reinsert_updates_value_and_expiry() {
        set_time(0);
        let cache: TtlCache<String, u32, u64> = TtlCache::new(test_clock);
        cache.insert("k".to_string(), 1, 50);
        cache.insert("k".to_string(), 2, 200);
        // Second insert wins.
        assert_eq!(cache.get_with_expiry(&"k".to_string()), Some((2, 200)));
        // Old stale heap entry (t=50) swept without evicting the new one.
        set_time(75);
        assert_eq!(cache.get_with_expiry(&"k".to_string()), Some((2, 200)));
        // New entry expires at 200.
        set_time(200);
        assert_eq!(cache.get_with_expiry(&"k".to_string()), None);
    }

    #[test]
    fn insert_sweeps_other_expired_entries() {
        set_time(0);
        let cache: TtlCache<String, u32, u64> = TtlCache::new(test_clock);
        cache.insert("a".to_string(), 1, 50);
        cache.insert("b".to_string(), 2, 200);
        set_time(100);
        cache.insert("c".to_string(), 3, 300);
        // "a" was evicted by the sweep inside insert.
        assert_eq!(cache.get_with_expiry(&"a".to_string()), None);
        assert_eq!(cache.get_with_expiry(&"b".to_string()), Some((2, 200)));
        assert_eq!(cache.get_with_expiry(&"c".to_string()), Some((3, 300)));
    }

    #[test]
    fn stale_tombstone_after_invalidate_does_not_evict_reinserted_entry() {
        set_time(0);
        let cache: TtlCache<String, u32, u64> = TtlCache::new(test_clock);
        cache.insert("k".to_string(), 1, 50);
        // Leaves a stale heap tombstone at (50, "k").
        cache.invalidate(&"k".to_string());
        cache.insert("k".to_string(), 2, 200);
        // Advance past the stale tombstone's deadline.
        set_time(75);
        // Stale tombstone swept; re-inserted entry (expiry=200) survives.
        assert_eq!(cache.get_with_expiry(&"k".to_string()), Some((2, 200)));
    }
}
