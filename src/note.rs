//! Free-form operator note attached to an enrolled client. Stored
//! verbatim in `clients.json`, shown in the `list` admin output.
//!
//! Validation rule: 1..=[`Note::MAX_LEN`] bytes, no control
//! codepoints (`char::is_control`). Notes are human-readable
//! operator annotations; controls (ASCII 0x00-0x1F + 0x7F, plus
//! Unicode C1 controls U+0080-U+009F) are either dangerous
//! (CR/LF/NUL = Clone2Leak-class line injection if a future wire
//! format ever serialises notes as `key=value\n` lines) or
//! aesthetically broken (BEL, backspace, etc. mangle terminal
//! output). Length cap defends against accidental paste-of-large-
//! blob via `--note`.
//!
//! Construction goes through one function (`Note::parse`) so the
//! validation rule cannot drift between callers (CLI argv, admin
//! wire deserialise, `clients.json` load).

use serde::{Deserialize, Serialize};

/// Validation failures from [`Note::parse`].
#[derive(Debug, thiserror::Error)]
pub enum NoteError {
    #[error("note length {got} out of range (1..={})", Note::MAX_LEN)]
    BadLen { got: usize },
    #[error("note control char U+{:04X} at byte offset {offset}", *ch as u32)]
    BadControl { offset: usize, ch: char },
}

/// Operator note: a validated `String` with the CR/LF/NUL exclusion
/// rule. The only constructor is [`Note::parse`].
///
/// Serde uses `try_from`/`into` so deserialise re-runs `Note::parse`
/// and serialise emits the bare string.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct Note(String);

impl Note {
    /// Cap on raw byte length. Operator-typed notes are short by
    /// convention; the cap defends against an accidental
    /// paste-of-large-blob via `--note` (admin protocol is UID-gated
    /// so this is belt-and-suspenders, not security-load-bearing).
    pub const MAX_LEN: usize = 256;

    /// Validate `s` against the note rule and wrap it. Single source
    /// of truth for the rule — CLI argv parse, admin wire
    /// deserialise, and `clients.json` load all go through here.
    pub fn parse(s: &str) -> Result<Self, NoteError> {
        let len = s.len();
        if len == 0 || len > Self::MAX_LEN {
            return Err(NoteError::BadLen { got: len });
        }
        if let Some((offset, ch)) = s.char_indices().find(|(_, c)| c.is_control()) {
            return Err(NoteError::BadControl { offset, ch });
        }
        Ok(Self(s.to_string()))
    }
}

impl From<Note> for String {
    fn from(n: Note) -> Self {
        n.0
    }
}

impl TryFrom<String> for Note {
    type Error = NoteError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_typical_notes() {
        for s in ["a", "provisioned 2026-05-01", "hello world!"] {
            Note::parse(s).unwrap_or_else(|e| panic!("expected {s:?} to parse: {e:?}"));
        }
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(matches!(Note::parse(""), Err(NoteError::BadLen { got: 0 })));
    }

    #[test]
    fn parse_rejects_too_long() {
        let s = "a".repeat(Note::MAX_LEN + 1);
        assert!(matches!(
            Note::parse(&s),
            Err(NoteError::BadLen { got }) if got == Note::MAX_LEN + 1
        ));
    }

    #[test]
    fn parse_rejects_control_chars() {
        // Includes CR/LF/NUL (the line-injection class) plus other
        // control codepoints (BEL, BS, DEL, U+0080 C1 control) that
        // are valid UTF-8 but never wanted in an operator note.
        for (s, bad) in [
            ("has\rcr", '\r'),
            ("has\nlf", '\n'),
            ("has\0nul", '\0'),
            ("has\x07bel", '\x07'),
            ("has\x7fdel", '\x7f'),
            ("has\u{0085}nel", '\u{0085}'),
        ] {
            match Note::parse(s) {
                Err(NoteError::BadControl { ch, .. }) => assert_eq!(ch, bad),
                other => panic!("expected BadControl for {s:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_accepts_non_ascii_text() {
        // Valid UTF-8 with no control codepoints — emoji, CJK,
        // accented Latin — all fine.
        for s in ["café", "日本語", "🦀 rust"] {
            Note::parse(s).unwrap_or_else(|e| panic!("expected {s:?} to parse: {e:?}"));
        }
    }
}
