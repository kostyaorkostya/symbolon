//! In-memory PSK store backed by the on-disk `psks` file.
//!
//! File format:
//! ```text
//! identity:hex_psk
//! identity:hex_psk
//! ...
//! ```
//! Each line: ASCII identity, single `:`, 64 hex characters (32-byte PSK).
//! Trailing newlines are tolerated; blank lines are skipped.
//!
//! The store owns the canonical in-memory copy. Writes go through
//! `atomic_write` (tempfile + fsync + rename + fsync parent) so the daemon
//! can crash mid-update without leaving the file half-written.
//!
//! Identity validation is delegated to [`crate::identity::Identity`]
//! — the same type the wire prelude parser and the admin enroll
//! handler use — so a manually-edited file with garbage can't sneak
//! past the load.

use std::collections::HashMap;
use std::fmt::Write as _;

use hex::FromHex;

use crate::identity::{Identity, IdentityError};
use crate::psk::Psk;

/// Failure modes for `PskStore::parse`. None of these variants carry the
/// PSK file path: the caller knows it (it just read the file). The
/// `daemon::DaemonError::LoadPsks` wrapper stamps the path once at the
/// load boundary, so the rendered chain reads "failed to load PSK file
/// at /var/lib/symbolon/psks: line 3: missing `:` separator".
#[derive(Debug, thiserror::Error)]
pub enum PskStoreError {
    #[error("PSK file is not valid UTF-8")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("line {line}: missing `:` separator")]
    MissingSeparator { line: usize },
    #[error("line {line}: invalid identity")]
    BadIdentity {
        line: usize,
        #[source]
        source: IdentityError,
    },
    #[error("line {line}: invalid PSK hex")]
    BadPskHex {
        line: usize,
        #[source]
        source: hex::FromHexError,
    },
    #[error("line {line}: duplicate identity {identity}")]
    DuplicateIdentity { line: usize, identity: Identity },
}

/// In-memory map from identity → 32-byte PSK. The post-storage
/// defence against page exfiltration is operator-side per AGENTS.md
/// invariant #14: `mlockall(MCL_CURRENT|MCL_FUTURE)` (no swap) plus
/// `LimitCORE=0` in the systemd unit (no coredump).
#[derive(Debug, Default)]
pub struct PskStore {
    entries: HashMap<Identity, Psk>,
}

impl PskStore {
    /// Construct an empty store. Used when the on-disk file does not yet exist
    /// (fresh deployment). Mirrors `Default` for generic-code callers; both
    /// coexist per Rust's "provide `new` and `Default`" convention.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a PSK file's contents into a store. Errors carry the line
    /// number only; the caller stamps the file path at its boundary
    /// (see `PskStoreError` doc).
    pub fn parse(text: &str) -> Result<Self, PskStoreError> {
        let mut entries: HashMap<Identity, Psk> = HashMap::new();
        for (idx, raw) in text.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                continue;
            }
            let (id_str, hex) = line
                .split_once(':')
                .ok_or(PskStoreError::MissingSeparator { line: line_no })?;
            let id = Identity::parse(id_str).map_err(|source| PskStoreError::BadIdentity {
                line: line_no,
                source,
            })?;
            let psk = Psk::from_hex(hex).map_err(|source| PskStoreError::BadPskHex {
                line: line_no,
                source,
            })?;
            match entries.entry(id) {
                std::collections::hash_map::Entry::Occupied(occ) => {
                    return Err(PskStoreError::DuplicateIdentity {
                        line: line_no,
                        identity: occ.key().clone(),
                    });
                }
                std::collections::hash_map::Entry::Vacant(vac) => {
                    vac.insert(psk);
                }
            }
        }
        Ok(Self { entries })
    }

    /// Look up a PSK by identity. Returns `None` if the identity is not enrolled.
    /// Accepts `&str` via `Identity: Borrow<str>` so the hot path can pass the
    /// raw identity string from `Step::NeedPsk` without re-allocating.
    pub fn lookup(&self, identity: &str) -> Option<&Psk> {
        self.entries.get(identity)
    }

    /// Insert or replace an identity's PSK.
    pub fn insert(&mut self, identity: Identity, psk: Psk) {
        self.entries.insert(identity, psk);
    }

    /// Remove an identity. Returns whether anything was removed.
    pub fn remove(&mut self, identity: &str) -> bool {
        self.entries.remove(identity).is_some()
    }

    /// Number of enrolled identities.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Render the store to the on-disk file format. Identities are emitted in
    /// sorted order so the file is deterministic (helps diff-based audit).
    pub fn render(&self) -> String {
        let mut entries: Vec<(&Identity, &Psk)> = self.entries.iter().collect();
        entries.sort_unstable_by_key(|(k, _)| *k);
        // Per-line upper bound: identity + ':' + hex(psk) + '\n'.
        const LINE_MAX: usize = Identity::MAX_LEN + 1 + Psk::HEX_LEN + 1;
        let mut out = String::with_capacity(entries.len() * LINE_MAX);
        for (k, psk) in entries {
            writeln!(out, "{k}:{psk:x}").expect("write into String is infallible");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> Identity {
        Identity::parse(s).expect("test identity must be valid")
    }

    fn hex_str(p: Psk) -> String {
        format!("{p:x}")
    }

    fn psk_a() -> Psk {
        Psk::from([0xAA; 32])
    }

    fn psk_b() -> Psk {
        Psk::from([0xBB; 32])
    }

    #[test]
    fn parse_empty_returns_empty_store() {
        let store = PskStore::parse("").unwrap();
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn parse_round_trip() {
        let mut store = PskStore::new();
        store.insert(id("alpha"), psk_a());
        store.insert(id("beta"), psk_b());
        let rendered = store.render();

        let reparsed = PskStore::parse(&rendered).unwrap();
        assert_eq!(reparsed.lookup("alpha"), Some(&psk_a()));
        assert_eq!(reparsed.lookup("beta"), Some(&psk_b()));
        assert_eq!(reparsed.len(), 2);
    }

    #[test]
    fn render_is_sorted_deterministic() {
        let mut s1 = PskStore::new();
        s1.insert(id("b"), psk_a());
        s1.insert(id("a"), psk_a());
        let mut s2 = PskStore::new();
        s2.insert(id("a"), psk_a());
        s2.insert(id("b"), psk_a());
        assert_eq!(s1.render(), s2.render());
        assert!(s1.render().starts_with("a:"));
    }

    #[test]
    fn parse_skips_blank_lines() {
        let text = format!(
            "\n\nalpha:{}\n\n\nbeta:{}\n",
            hex_str(psk_a()),
            hex_str(psk_b())
        );
        let store = PskStore::parse(&text).unwrap();
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn parse_handles_crlf_line_endings() {
        let text = format!("alpha:{}\r\n", hex_str(psk_a()));
        let store = PskStore::parse(&text).unwrap();
        assert_eq!(store.lookup("alpha"), Some(&psk_a()));
    }

    #[test]
    fn parse_rejects_missing_separator() {
        assert!(matches!(
            PskStore::parse("alpha-without-colon\n"),
            Err(PskStoreError::MissingSeparator { line: 1 })
        ));
    }

    #[test]
    fn parse_rejects_bad_identity_charset() {
        let text = format!("bad ident:{}\n", hex_str(psk_a()));
        assert!(matches!(
            PskStore::parse(&text),
            Err(PskStoreError::BadIdentity {
                line: 1,
                source: IdentityError::BadCharset { byte: b' ', .. },
            })
        ));
    }

    #[test]
    fn parse_rejects_empty_identity() {
        let text = format!(":{}\n", hex_str(psk_a()));
        assert!(matches!(
            PskStore::parse(&text),
            Err(PskStoreError::BadIdentity {
                line: 1,
                source: IdentityError::BadLen { got: 0 },
            })
        ));
    }

    #[test]
    fn parse_rejects_short_hex() {
        assert!(matches!(
            PskStore::parse("alpha:abcd\n"),
            Err(PskStoreError::BadPskHex {
                line: 1,
                source: hex::FromHexError::InvalidStringLength,
            })
        ));
    }

    #[test]
    fn parse_rejects_non_hex_chars() {
        let text = format!("alpha:{}\n", "g".repeat(64));
        assert!(matches!(
            PskStore::parse(&text),
            Err(PskStoreError::BadPskHex {
                line: 1,
                source: hex::FromHexError::InvalidHexCharacter { c: 'g', .. },
            })
        ));
    }

    #[test]
    fn parse_rejects_duplicate_identity() {
        let text = format!("alpha:{}\nalpha:{}\n", hex_str(psk_a()), hex_str(psk_b()));
        assert!(matches!(
            PskStore::parse(&text),
            Err(PskStoreError::DuplicateIdentity { line: 2, .. })
        ));
    }

    #[test]
    fn insert_then_remove_then_lookup() {
        let mut s = PskStore::new();
        s.insert(id("x"), psk_a());
        assert_eq!(s.lookup("x"), Some(&psk_a()));
        assert!(s.remove("x"));
        assert_eq!(s.lookup("x"), None);
        assert!(!s.remove("x"));
    }

    #[test]
    fn insert_replaces() {
        let mut s = PskStore::new();
        s.insert(id("x"), psk_a());
        s.insert(id("x"), psk_b());
        assert_eq!(s.lookup("x"), Some(&psk_b()));
    }
}
