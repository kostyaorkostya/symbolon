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
//! Identity charset matches [`crate::transport::Identity`] exactly:
//! `[A-Za-z0-9._-]+`, 1..=64 bytes. Loading enforces this so a manually-
//! edited file with garbage doesn't get partially imported.

use std::collections::HashMap;

use derive_more::From;

use crate::transport::{MAX_IDENTITY_LEN, is_identity_byte};

const PSK_LEN: usize = 32;

/// 32-byte pre-shared key with a deliberately redacted `Debug`
/// impl. Without the newtype, the raw `[u8; 32]` inside `PskStore`
/// (which derives `Debug`) would print every byte whenever an
/// operator-side log line dumped the store, even though the
/// operator-side mitigation (mlockall + LimitCORE=0) only covers
/// swap and coredumps — not deliberate `Debug` formatting.
#[derive(Clone, Copy, PartialEq, Eq, From)]
pub struct Psk([u8; PSK_LEN]);

impl std::fmt::Debug for Psk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Psk(<redacted>)")
    }
}

impl Psk {
    pub fn as_bytes(&self) -> &[u8; PSK_LEN] {
        &self.0
    }
    pub fn into_bytes(self) -> [u8; PSK_LEN] {
        self.0
    }
}

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
    #[error("line {line}: identity is empty or longer than 64 bytes")]
    BadIdentityLen { line: usize },
    #[error(
        "line {line}: identity byte 0x{byte:02x} at offset {offset} is outside \
         charset [A-Za-z0-9._-]"
    )]
    BadIdentityChar {
        line: usize,
        offset: usize,
        byte: u8,
    },
    #[error("line {line}: PSK hex must be exactly 64 chars (got {got})")]
    BadPskHexLen { line: usize, got: usize },
    #[error("line {line}: PSK hex contains non-hex byte 0x{byte:02x}")]
    BadPskHex { line: usize, byte: u8 },
    #[error("line {line}: duplicate identity {identity:?}")]
    DuplicateIdentity { line: usize, identity: String },
}

/// In-memory map from identity → 32-byte PSK. The post-storage
/// defence against page exfiltration is operator-side per AGENTS.md
/// invariant #14: `mlockall(MCL_CURRENT|MCL_FUTURE)` (no swap) plus
/// `LimitCORE=0` in the systemd unit (no coredump).
#[derive(Debug, Default)]
pub struct PskStore {
    entries: HashMap<String, Psk>,
}

impl PskStore {
    /// Construct an empty store. Used when the on-disk file does not yet exist
    /// (fresh deployment).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parse a PSK file's contents into a store. Errors carry the line
    /// number only; the caller stamps the file path at its boundary
    /// (see `PskStoreError` doc).
    pub fn parse(text: &str) -> Result<Self, PskStoreError> {
        let mut entries: HashMap<String, Psk> = HashMap::new();
        for (idx, raw) in text.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                continue;
            }
            let (id, hex) = line
                .split_once(':')
                .ok_or(PskStoreError::MissingSeparator { line: line_no })?;
            validate_identity(id, line_no)?;
            let psk = decode_psk_hex(hex, line_no)?;
            if entries.insert(id.to_string(), psk).is_some() {
                return Err(PskStoreError::DuplicateIdentity {
                    line: line_no,
                    identity: id.to_string(),
                });
            }
        }
        Ok(Self { entries })
    }

    /// Look up a PSK by identity. Returns `None` if the identity is not enrolled.
    pub fn lookup(&self, identity: &str) -> Option<&Psk> {
        self.entries.get(identity)
    }

    /// Insert or replace an identity's PSK.
    pub fn insert(&mut self, identity: String, psk: Psk) {
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
        let mut keys: Vec<&str> = self.entries.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut out = String::with_capacity(keys.len() * (MAX_IDENTITY_LEN + 1 + PSK_LEN * 2 + 1));
        for k in keys {
            let psk = self.entries.get(k).expect("key from same map");
            out.push_str(k);
            out.push(':');
            out.push_str(&hex::encode(psk.as_bytes()));
            out.push('\n');
        }
        out
    }
}

fn validate_identity(id: &str, line: usize) -> Result<(), PskStoreError> {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_IDENTITY_LEN {
        return Err(PskStoreError::BadIdentityLen { line });
    }
    for (offset, &b) in bytes.iter().enumerate() {
        if !is_identity_byte(b) {
            return Err(PskStoreError::BadIdentityChar {
                line,
                offset,
                byte: b,
            });
        }
    }
    Ok(())
}

fn decode_psk_hex(hex_str: &str, line: usize) -> Result<Psk, PskStoreError> {
    if hex_str.len() != PSK_LEN * 2 {
        return Err(PskStoreError::BadPskHexLen {
            line,
            got: hex_str.len(),
        });
    }
    let mut out = [0u8; PSK_LEN];
    hex::decode_to_slice(hex_str, &mut out).map_err(|e| match e {
        hex::FromHexError::InvalidHexCharacter { c, .. } => PskStoreError::BadPskHex {
            line,
            byte: c as u8,
        },
        // Length already validated above; OddLength / InvalidStringLength
        // are unreachable here. Surface as BadPskHexLen if reached.
        _ => PskStoreError::BadPskHexLen {
            line,
            got: hex_str.len(),
        },
    })?;
    Ok(Psk::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psk_a() -> Psk {
        Psk::from([0xAA; 32])
    }

    fn psk_b() -> Psk {
        Psk::from([0xBB; 32])
    }

    fn hex_of(psk: Psk) -> String {
        psk.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn parse_empty_returns_empty_store() {
        let store = PskStore::parse("").unwrap();
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn parse_round_trip() {
        let mut store = PskStore::empty();
        store.insert("alpha".to_string(), psk_a());
        store.insert("beta".to_string(), psk_b());
        let rendered = store.render();

        let reparsed = PskStore::parse(&rendered).unwrap();
        assert_eq!(reparsed.lookup("alpha"), Some(&psk_a()));
        assert_eq!(reparsed.lookup("beta"), Some(&psk_b()));
        assert_eq!(reparsed.len(), 2);
    }

    #[test]
    fn render_is_sorted_deterministic() {
        let mut s1 = PskStore::empty();
        s1.insert("b".to_string(), psk_a());
        s1.insert("a".to_string(), psk_a());
        let mut s2 = PskStore::empty();
        s2.insert("a".to_string(), psk_a());
        s2.insert("b".to_string(), psk_a());
        assert_eq!(s1.render(), s2.render());
        assert!(s1.render().starts_with("a:"));
    }

    #[test]
    fn parse_skips_blank_lines() {
        let text = format!(
            "\n\nalpha:{}\n\n\nbeta:{}\n",
            hex_of(psk_a()),
            hex_of(psk_b())
        );
        let store = PskStore::parse(&text).unwrap();
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn parse_handles_crlf_line_endings() {
        let text = format!("alpha:{}\r\n", hex_of(psk_a()));
        let store = PskStore::parse(&text).unwrap();
        assert_eq!(store.lookup("alpha"), Some(&psk_a()));
    }

    #[test]
    fn parse_rejects_missing_separator() {
        assert!(matches!(
            PskStore::parse("alpha-without-colon\n"),
            Err(PskStoreError::MissingSeparator { line: 1, .. })
        ));
    }

    #[test]
    fn parse_rejects_bad_identity_charset() {
        let text = format!("bad ident:{}\n", hex_of(psk_a()));
        assert!(matches!(
            PskStore::parse(&text),
            Err(PskStoreError::BadIdentityChar {
                line: 1,
                byte: b' ',
                ..
            })
        ));
    }

    #[test]
    fn parse_rejects_empty_identity() {
        let text = format!(":{}\n", hex_of(psk_a()));
        assert!(matches!(
            PskStore::parse(&text),
            Err(PskStoreError::BadIdentityLen { line: 1, .. })
        ));
    }

    #[test]
    fn parse_rejects_short_hex() {
        assert!(matches!(
            PskStore::parse("alpha:abcd\n"),
            Err(PskStoreError::BadPskHexLen {
                line: 1,
                got: 4,
                ..
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
                byte: b'g',
                ..
            })
        ));
    }

    #[test]
    fn parse_rejects_duplicate_identity() {
        let text = format!("alpha:{}\nalpha:{}\n", hex_of(psk_a()), hex_of(psk_b()));
        assert!(matches!(
            PskStore::parse(&text),
            Err(PskStoreError::DuplicateIdentity { line: 2, .. })
        ));
    }

    #[test]
    fn insert_then_remove_then_lookup() {
        let mut s = PskStore::empty();
        s.insert("x".to_string(), psk_a());
        assert_eq!(s.lookup("x"), Some(&psk_a()));
        assert!(s.remove("x"));
        assert_eq!(s.lookup("x"), None);
        assert!(!s.remove("x"));
    }

    #[test]
    fn insert_replaces() {
        let mut s = PskStore::empty();
        s.insert("x".to_string(), psk_a());
        s.insert("x".to_string(), psk_b());
        assert_eq!(s.lookup("x"), Some(&psk_b()));
    }
}
