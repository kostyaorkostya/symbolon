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
use std::path::{Path, PathBuf};

const PSK_LEN: usize = 32;
const MAX_IDENTITY_LEN: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum PskStoreError {
    #[error("reading {} failed", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("PSK file {} is not valid UTF-8", path.display())]
    Utf8 {
        path: PathBuf,
        #[source]
        source: std::str::Utf8Error,
    },
    #[error("PSK file {} line {line}: missing `:` separator", path.display())]
    MissingSeparator { path: PathBuf, line: usize },
    #[error("PSK file {} line {line}: identity is empty or longer than 64 bytes", path.display())]
    BadIdentityLen { path: PathBuf, line: usize },
    #[error(
        "PSK file {} line {line}: identity byte 0x{byte:02x} at offset {offset} is outside \
         charset [A-Za-z0-9._-]",
        path.display()
    )]
    BadIdentityChar {
        path: PathBuf,
        line: usize,
        offset: usize,
        byte: u8,
    },
    #[error("PSK file {} line {line}: PSK hex must be exactly 64 chars (got {got})", path.display())]
    BadPskHexLen {
        path: PathBuf,
        line: usize,
        got: usize,
    },
    #[error("PSK file {} line {line}: PSK hex contains non-hex byte 0x{byte:02x}", path.display())]
    BadPskHex {
        path: PathBuf,
        line: usize,
        byte: u8,
    },
    #[error("PSK file {} line {line}: duplicate identity {identity:?}", path.display())]
    DuplicateIdentity {
        path: PathBuf,
        line: usize,
        identity: String,
    },
}

/// In-memory map from identity → 32-byte PSK. The post-storage
/// defence against page exfiltration is operator-side per AGENTS.md
/// invariant #14: `mlockall(MCL_CURRENT|MCL_FUTURE)` (no swap) plus
/// `LimitCORE=0` in the systemd unit (no coredump).
#[derive(Debug, Default)]
pub struct PskStore {
    entries: HashMap<String, [u8; PSK_LEN]>,
}

impl PskStore {
    /// Construct an empty store. Used when the on-disk file does not yet exist
    /// (fresh deployment).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parse a PSK file's contents into a store. Caller passes `path` only for
    /// error context.
    pub fn parse(text: &str, path: &Path) -> Result<Self, PskStoreError> {
        let mut entries: HashMap<String, [u8; PSK_LEN]> = HashMap::new();
        for (idx, raw) in text.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                continue;
            }
            let (id, hex) =
                line.split_once(':')
                    .ok_or_else(|| PskStoreError::MissingSeparator {
                        path: path.to_path_buf(),
                        line: line_no,
                    })?;
            validate_identity(id, path, line_no)?;
            let psk = decode_psk_hex(hex, path, line_no)?;
            if entries.insert(id.to_string(), psk).is_some() {
                return Err(PskStoreError::DuplicateIdentity {
                    path: path.to_path_buf(),
                    line: line_no,
                    identity: id.to_string(),
                });
            }
        }
        Ok(Self { entries })
    }

    /// Look up a PSK by identity. Returns `None` if the identity is not enrolled.
    pub fn lookup(&self, identity: &str) -> Option<&[u8; PSK_LEN]> {
        self.entries.get(identity)
    }

    /// Insert or replace an identity's PSK.
    pub fn insert(&mut self, identity: String, psk: [u8; PSK_LEN]) {
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
        let mut keys: Vec<&String> = self.entries.keys().collect();
        keys.sort();
        let mut out = String::with_capacity(keys.len() * (MAX_IDENTITY_LEN + 1 + PSK_LEN * 2 + 1));
        for k in keys {
            let psk = self.entries.get(k).expect("key from same map");
            out.push_str(k);
            out.push(':');
            out.push_str(&hex::encode(psk));
            out.push('\n');
        }
        out
    }
}

fn validate_identity(id: &str, path: &Path, line: usize) -> Result<(), PskStoreError> {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_IDENTITY_LEN {
        return Err(PskStoreError::BadIdentityLen {
            path: path.to_path_buf(),
            line,
        });
    }
    for (offset, &b) in bytes.iter().enumerate() {
        if !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
            return Err(PskStoreError::BadIdentityChar {
                path: path.to_path_buf(),
                line,
                offset,
                byte: b,
            });
        }
    }
    Ok(())
}

fn decode_psk_hex(hex_str: &str, path: &Path, line: usize) -> Result<[u8; PSK_LEN], PskStoreError> {
    if hex_str.len() != PSK_LEN * 2 {
        return Err(PskStoreError::BadPskHexLen {
            path: path.to_path_buf(),
            line,
            got: hex_str.len(),
        });
    }
    let mut out = [0u8; PSK_LEN];
    hex::decode_to_slice(hex_str, &mut out).map_err(|e| match e {
        hex::FromHexError::InvalidHexCharacter { c, .. } => PskStoreError::BadPskHex {
            path: path.to_path_buf(),
            line,
            byte: c as u8,
        },
        // Length already validated above; OddLength / InvalidStringLength
        // are unreachable here. Surface as BadPskHexLen if reached.
        _ => PskStoreError::BadPskHexLen {
            path: path.to_path_buf(),
            line,
            got: hex_str.len(),
        },
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "/test/psks";

    fn p() -> &'static Path {
        Path::new(PATH)
    }

    fn psk_a() -> [u8; 32] {
        [0xAA; 32]
    }

    fn psk_b() -> [u8; 32] {
        [0xBB; 32]
    }

    fn hex_of(psk: [u8; 32]) -> String {
        psk.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn parse_empty_returns_empty_store() {
        let store = PskStore::parse("", p()).unwrap();
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn parse_round_trip() {
        let mut store = PskStore::empty();
        store.insert("alpha".to_string(), psk_a());
        store.insert("beta".to_string(), psk_b());
        let rendered = store.render();

        let reparsed = PskStore::parse(&rendered, p()).unwrap();
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
        let store = PskStore::parse(&text, p()).unwrap();
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn parse_handles_crlf_line_endings() {
        let text = format!("alpha:{}\r\n", hex_of(psk_a()));
        let store = PskStore::parse(&text, p()).unwrap();
        assert_eq!(store.lookup("alpha"), Some(&psk_a()));
    }

    #[test]
    fn parse_rejects_missing_separator() {
        assert!(matches!(
            PskStore::parse("alpha-without-colon\n", p()),
            Err(PskStoreError::MissingSeparator { line: 1, .. })
        ));
    }

    #[test]
    fn parse_rejects_bad_identity_charset() {
        let text = format!("bad ident:{}\n", hex_of(psk_a()));
        assert!(matches!(
            PskStore::parse(&text, p()),
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
            PskStore::parse(&text, p()),
            Err(PskStoreError::BadIdentityLen { line: 1, .. })
        ));
    }

    #[test]
    fn parse_rejects_short_hex() {
        assert!(matches!(
            PskStore::parse("alpha:abcd\n", p()),
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
            PskStore::parse(&text, p()),
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
            PskStore::parse(&text, p()),
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
