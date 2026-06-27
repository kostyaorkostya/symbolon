//! Validated client-identity newtype shared by every code path that
//! names a client: the Noise prelude (wire), the PSK store (file),
//! the admin enroll/revoke surface (CLI), and the daemon's in-memory
//! tables. Construction goes through one function (`Identity::parse`)
//! so the validation rule cannot drift between callers.
//!
//! Identity rule: `1..=Identity::MAX_LEN` bytes, charset
//! `[A-Za-z0-9._-]`. The charset rejects CR/LF/NUL/whitespace/`:`
//! by construction, which is what the git-credential parser and PSK
//! file format both rely on (AGENTS.md invariant #12 in spirit).
//!
//! `Debug` is deliberately redacted (mirrors the [`crate::psk::Psk`]
//! pattern) so debug-printing any struct that carries an `Identity`
//! — `PskStore`, `Step::NeedPsk`, `RState::NeedPsk`, an
//! `EnrolledClient` — never spills the client name through the
//! `{:?}` channel. Audit logging uses `Display` (`%identity`) and
//! prints the value, which is the intended audit surface.

use std::borrow::Borrow;

use derive_more::Display;

/// Validation failures from [`Identity::parse`].
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("identity length {got} out of range (1..={})", Identity::MAX_LEN)]
    BadLen { got: usize },
    #[error("identity byte 0x{byte:02x} at offset {offset} is outside charset [A-Za-z0-9._-]")]
    BadCharset { offset: usize, byte: u8 },
}

/// Owned, validated client identity. The only constructor is
/// [`Identity::parse`]; holding an `Identity` proves the validation
/// rule was applied.
///
/// `Debug` is redacted on purpose — see the module doc.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Display)]
pub struct Identity(String);

impl Identity {
    /// Maximum identity byte length. Bounds the on-wire prelude so a
    /// malformed peer can never make us pull more than `6 + MAX_LEN`
    /// bytes before rejecting.
    pub const MAX_LEN: usize = 64;

    /// Validate `s` against the identity rule and wrap it. The
    /// single source of truth for the rule — every caller that
    /// builds an `Identity` from raw bytes (wire parser, PSK file
    /// loader, admin enroll handler) goes through here.
    pub fn parse(s: &str) -> Result<Self, IdentityError> {
        let bytes = s.as_bytes();
        if bytes.is_empty() || bytes.len() > Self::MAX_LEN {
            return Err(IdentityError::BadLen { got: bytes.len() });
        }
        if let Some((offset, &byte)) = bytes
            .iter()
            .enumerate()
            .find(|&(_, &b)| !b.is_ascii_alphanumeric() && !matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(IdentityError::BadCharset { offset, byte });
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Identity(<redacted>)")
    }
}

/// Enables `HashMap<Identity, _>::get(&str)` and `.remove(&str)` so
/// callers that hold the raw identity bytes (PSK store's `lookup`/
/// `remove`, daemon's enroll-rollback) can probe the map without
/// constructing an owned `Identity` first.
impl Borrow<str> for Identity {
    fn borrow(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_valid_identities() {
        for id in [
            "a",
            "dev-vm-1",
            "client.42",
            "a_b_c",
            "x".repeat(64).as_str(),
        ] {
            Identity::parse(id).unwrap_or_else(|e| panic!("expected {id:?} to parse: {e:?}"));
        }
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(matches!(
            Identity::parse(""),
            Err(IdentityError::BadLen { got: 0 })
        ));
    }

    #[test]
    fn parse_rejects_too_long() {
        let id = "a".repeat(Identity::MAX_LEN + 1);
        assert!(matches!(
            Identity::parse(&id),
            Err(IdentityError::BadLen { got }) if got == Identity::MAX_LEN + 1
        ));
    }

    #[test]
    fn parse_rejects_bad_charset() {
        for (id, bad) in [
            ("with space", b' '),
            ("has:colon", b':'),
            ("has\nlf", b'\n'),
            ("has\rcr", b'\r'),
            ("has\0nul", 0x00),
            ("slash/path", b'/'),
        ] {
            match Identity::parse(id) {
                Err(IdentityError::BadCharset { byte, .. }) => assert_eq!(byte, bad),
                other => panic!("expected BadCharset for {id:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_rejects_non_ascii() {
        assert!(matches!(
            Identity::parse("över-äscii"),
            Err(IdentityError::BadCharset { .. })
        ));
    }

    #[test]
    fn debug_is_redacted_display_is_not() {
        let id = Identity::parse("dev-vm-1").unwrap();
        assert_eq!(format!("{id:?}"), "Identity(<redacted>)");
        assert_eq!(format!("{id}"), "dev-vm-1");
    }

    #[test]
    fn hashmap_lookup_by_str_via_borrow() {
        use std::collections::HashMap;
        let mut m: HashMap<Identity, u32> = HashMap::new();
        m.insert(Identity::parse("alpha").unwrap(), 1);
        assert_eq!(m.get("alpha"), Some(&1));
        assert_eq!(m.get("beta"), None);
    }
}
