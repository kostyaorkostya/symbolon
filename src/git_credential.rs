//! git-credential helper wire protocol: parse the `key=value` request
//! block and emit the `username` / `password` / `password_expiry_utc`
//! response.
//!
//! Single responsibility: protocol translation. Host dispatch and mint
//! logic live elsewhere; this module does no I/O and no logging.
//!
//! # Security: CR/LF rejection (mandatory)
//!
//! Per `docs/PROTOCOLS.md` and AGENTS.md invariant #12, the parser
//! rejects any field value containing a 0x0D (CR) or 0x0A (LF) byte.
//! Bare LF is valid only as a line terminator. This defends against
//! the Clone2Leak class (CVE-2024-52006, CVE-2024-50338, CVE-2025-23040),
//! where a crafted URL injects an extra protocol line to redirect
//! credentials to an attacker-controlled host. The caller (the daemon)
//! is expected to close the connection without a response on any
//! `Err` and log `evt=mint_denied reason=malformed_request`.

use std::io::Write;
use std::time::SystemTime;

#[derive(Debug)]
pub struct Request {
    pub protocol: String,
    pub host: String,
    pub path: String,
    /// True iff the client declared `capability[]=authtype` in the
    /// request, indicating it understands the modern response shape
    /// (`authtype`, `credential`, `ephemeral`). Git 2.46+ sends this
    /// after we advertise `capability authtype` on the `capability`
    /// action. Older clients omit the line and we fall back to the
    /// legacy `username`/`password` shape.
    pub client_supports_authtype: bool,
}

#[derive(Debug)]
pub struct Response {
    pub username: String,
    pub password: String,
    pub password_expiry_utc: SystemTime,
}

impl Response {
    /// Validate-and-construct. All wire-emit invariants are checked
    /// here so [`Response::encode`] can be infallible:
    /// - `username` and `password` must not contain CR (0x0D), LF
    ///   (0x0A), or NUL (0x00) — Clone2Leak-class defence applied
    ///   symmetrically with the request parser (AGENTS.md #12).
    /// - `password_expiry_utc` must be ≥ UNIX_EPOCH (we render it as
    ///   seconds-since-epoch).
    pub fn new(
        username: String,
        password: String,
        password_expiry_utc: SystemTime,
    ) -> Result<Self, GitCredentialError> {
        Self::check_field("username", &username)?;
        Self::check_field("password", &password)?;
        if password_expiry_utc < std::time::UNIX_EPOCH {
            return Err(GitCredentialError::PreEpochExpiry);
        }
        Ok(Self {
            username,
            password,
            password_expiry_utc,
        })
    }

    /// Render `password_expiry_utc` as seconds-since-epoch for the
    /// admin/log wire shape. Infallible by construction —
    /// [`Response::new`] rejects pre-epoch input.
    pub fn password_expiry_unix_secs(&self) -> u64 {
        self.password_expiry_utc
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Response::new rejects pre-epoch input")
            .as_secs()
    }

    /// Reject CR/LF/NUL inside a value that will be emitted as a
    /// `key=value\n` line. Same Clone2Leak-class defence the request
    /// parser enforces on inbound bytes (AGENTS.md invariant #12).
    fn check_field(field: &'static str, value: &str) -> Result<(), GitCredentialError> {
        for &b in value.as_bytes() {
            if matches!(b, 0x00 | 0x0D | 0x0A) {
                return Err(GitCredentialError::ResponseControlByte { field });
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GitCredentialError {
    #[error("request block is not terminated by a blank line or EOF after a `\\n`")]
    UnterminatedBlock,
    #[error("trailing bytes after the empty terminator line")]
    TrailingBytes,
    #[error("malformed line {line_no}: missing '=' separator")]
    MissingSeparator { line_no: usize },
    #[error("empty key on line {line_no}")]
    EmptyKey { line_no: usize },
    #[error("empty value for required key '{key}'")]
    EmptyValue { key: &'static str },
    #[error("duplicate '{key}' field")]
    DuplicateKey { key: &'static str },
    #[error("required key '{key}' missing")]
    MissingRequiredKey { key: &'static str },
    #[error("forbidden control byte 0x{byte:02x} on line {line_no} at offset {offset}")]
    ControlByteInLine {
        line_no: usize,
        offset: usize,
        byte: u8,
    },
    #[error("value for '{key}' is not valid UTF-8")]
    InvalidUtf8 { key: &'static str },
    #[error("response field '{field}' contains a forbidden control byte")]
    ResponseControlByte { field: &'static str },
    #[error("password_expiry_utc is before the UNIX epoch")]
    PreEpochExpiry,
    #[error("value for '{key}' exceeds {max} bytes")]
    ValueTooLong { key: &'static str, max: usize },
    #[error("request block exceeds {max} bytes")]
    RequestTooLarge { max: usize },
}

impl Request {
    /// Per-value byte cap. Real-world host/path values run hundreds of
    /// bytes at most; this defends against pathological values without
    /// restricting any plausible repo URL.
    const MAX_VALUE_BYTES: usize = 4 * 1024;

    /// Absolute parser ceiling for the entire request block. Direct
    /// callers (fuzz harnesses, in-process tests) hit this; the daemon
    /// enforces a tighter per-connection `WIRE_READ_BUDGET` on the
    /// read loop before bytes even reach this parser (see
    /// `src/daemon.rs`).
    pub const PARSER_HARD_MAX: usize = 64 * 1024;

    /// Parse a git-credential request block.
    ///
    /// The format is a sequence of `key=value\n` lines terminated by an
    /// empty line (`\n\n`). Recognised keys are `protocol`, `host`, and
    /// `path`; unknown keys (e.g. `wwwauth[]`, `capability[]`) are
    /// accepted and ignored per `gitcredentials(7)`. `path` has a single
    /// trailing `.git` suffix stripped per `docs/PROTOCOLS.md` § "`path`
    /// handling".
    ///
    /// CR (0x0D) and NUL (0x00) bytes in any recognised key's value are
    /// rejected (Clone2Leak defence — see the module-level docs).
    /// Returns `Err` on any deviation; the daemon closes the connection
    /// without a response on any error from this function.
    pub fn parse(input: &[u8]) -> Result<Self, GitCredentialError> {
        if input.len() > Self::PARSER_HARD_MAX {
            return Err(GitCredentialError::RequestTooLarge {
                max: Self::PARSER_HARD_MAX,
            });
        }
        // Per `git/Documentation/git-credential.adoc` § "The format"
        // and `git/credential.c::credential_read`, the attribute list
        // is "terminated by a blank line or end-of-file". Git itself
        // never writes the blank-line form — `credential_write` emits
        // `key=value\n` lines then `fclose`s the helper's stdin —
        // so EOF after a final `\n` is the shape we see in
        // production. Accept both.
        let block_end = match input.windows(2).position(|w| w == b"\n\n") {
            Some(pos) => {
                if pos + 2 < input.len() {
                    return Err(GitCredentialError::TrailingBytes);
                }
                pos
            }
            None => {
                if input.is_empty() || !input.ends_with(b"\n") {
                    return Err(GitCredentialError::UnterminatedBlock);
                }
                input.len() - 1
            }
        };

        let block = &input[..block_end];

        let mut protocol: Option<String> = None;
        let mut host: Option<String> = None;
        let mut path: Option<String> = None;
        let mut client_supports_authtype = false;

        for (i, line) in block.split(|&c| c == b'\n').enumerate() {
            let line_no = i + 1;
            // Clone2Leak defence (AGENTS.md #12): forbid CR/NUL anywhere
            // on the line before we even tokenize. Stricter than checking
            // values only — keys are produced by git itself and never
            // legitimately carry these bytes, so rejecting them in
            // unrecognized keys / capability values is harmless.
            if let Some((offset, &byte)) = line
                .iter()
                .enumerate()
                .find(|&(_, &b)| matches!(b, 0x00 | 0x0D))
            {
                return Err(GitCredentialError::ControlByteInLine {
                    line_no,
                    offset,
                    byte,
                });
            }
            let (key_bytes, value_bytes) = line
                .iter()
                .position(|&c| c == b'=')
                .map(|p| (&line[..p], &line[p + 1..]))
                .ok_or(GitCredentialError::MissingSeparator { line_no })?;

            // Dispatch on key. Recognized keys bind a `(name, slot)` for
            // value validation below; `capability[]` mutates the flag
            // inline and continues; unknown / empty keys terminate the
            // iteration (empty = error, unknown = ignored per
            // `gitcredentials(7)` extensibility).
            let (key, slot) = match key_bytes {
                b"" => return Err(GitCredentialError::EmptyKey { line_no }),
                b"capability[]" => {
                    // Repeating array key. Empty value `capability[]=` is
                    // the spec-defined "reset" that clears earlier flags
                    // (git-credential.adoc array semantics); other
                    // capabilities (e.g. `state`) ignored.
                    match value_bytes {
                        b"" => client_supports_authtype = false,
                        b"authtype" => client_supports_authtype = true,
                        _ => {}
                    }
                    continue;
                }
                b"protocol" => ("protocol", &mut protocol),
                b"host" => ("host", &mut host),
                b"path" => ("path", &mut path),
                // Unknown keys accepted and ignored (`wwwauth[]`, etc.).
                // Whitespace-around-`=` (e.g. `host `) lands here too;
                // so does `url=` shorthand which we don't implement.
                _ => continue,
            };

            if slot.is_some() {
                return Err(GitCredentialError::DuplicateKey { key });
            }

            if value_bytes.len() > Self::MAX_VALUE_BYTES {
                return Err(GitCredentialError::ValueTooLong {
                    key,
                    max: Self::MAX_VALUE_BYTES,
                });
            }
            if value_bytes.is_empty() {
                return Err(GitCredentialError::EmptyValue { key });
            }

            let value = std::str::from_utf8(value_bytes)
                .map_err(|_| GitCredentialError::InvalidUtf8 { key })?
                .to_string();
            *slot = Some(value);
        }

        let protocol =
            protocol.ok_or(GitCredentialError::MissingRequiredKey { key: "protocol" })?;
        let host = host.ok_or(GitCredentialError::MissingRequiredKey { key: "host" })?;
        let path_raw = path.ok_or(GitCredentialError::MissingRequiredKey { key: "path" })?;

        // Strip a single trailing literal `.git` suffix (PROTOCOLS.md
        // "`path` handling"). If that strip empties the path, the request
        // is malformed — treat the same as an empty `path=` value.
        let path = match path_raw.strip_suffix(".git") {
            Some("") => return Err(GitCredentialError::EmptyValue { key: "path" }),
            Some(stripped) => stripped.to_string(),
            None => path_raw,
        };

        Ok(Self {
            protocol,
            host,
            path,
            client_supports_authtype,
        })
    }
}

impl Response {
    /// Emit the response shape git-credential expects. Infallible by
    /// construction: [`Response::new`] has already validated all
    /// fields.
    ///
    /// Always emits the legacy `username=x-access-token` +
    /// `password=<token>` shape — the only auth scheme `github.com`'s
    /// git-HTTP smart-HTTP backend accepts. The modern
    /// `authtype=Bearer credential=<token>` shape (which
    /// `git/http.c::http_append_auth_header` would render as
    /// `Authorization: Bearer <token>`) is accepted by GitHub's REST
    /// API at `api.github.com` but rejected by `github.com` git-HTTP
    /// with HTTP 401, surfaced to the user as
    /// `remote: invalid credentials`. Verified empirically (curl with
    /// `-H "Authorization: Bearer …"` → 401, with `-u x-access-token:…`
    /// → 200). `git-credential-manager` (Microsoft, bundled with
    /// git-for-Windows) takes the same posture for the same reason.
    ///
    /// When the client advertised `capability[]=authtype` in the
    /// request, we additionally:
    /// - Echo `capability[]=authtype` so the response is allowed to
    ///   carry the modern-only `ephemeral` attribute (per
    ///   git-credential.adoc § "capability" gating).
    /// - Emit `ephemeral=true` so downstream chained helpers
    ///   (`credential.helper=cache` / `=store`) do NOT persist this
    ///   one-hour token to disk / the in-memory cache.
    ///
    /// When the client did not advertise the capability, we omit
    /// both — they would be silently ignored by pre-2.46 git anyway,
    /// but emitting them outside the negotiated handshake is
    /// spec-incorrect.
    pub fn encode(&self, out: &mut Vec<u8>, client_supports_authtype: bool) {
        let expiry_secs = self.password_expiry_unix_secs();

        if client_supports_authtype {
            out.extend_from_slice(b"capability[]=authtype\n");
        }
        out.extend_from_slice(b"username=");
        out.extend_from_slice(self.username.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(b"password=");
        out.extend_from_slice(self.password.as_bytes());
        out.push(b'\n');
        if client_supports_authtype {
            out.extend_from_slice(b"ephemeral=true\n");
        }
        // `write!` on Vec<u8> via io::Write formats `expiry_secs`
        // directly into the buffer with no intermediate String.
        // Vec<u8>'s io::Write impl never errors, so the expect is
        // truly unreachable.
        write!(out, "password_expiry_utc={expiry_secs}\n\n")
            .expect("Vec<u8>'s io::Write is infallible");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn resp(username: &str, password: &str, expiry_secs: u64) -> Response {
        Response::new(
            username.to_string(),
            password.to_string(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(expiry_secs),
        )
        .expect("test inputs are valid")
    }

    #[test]
    fn parse_minimal_request_ok() {
        let input = b"protocol=https\nhost=github.com\npath=octocat/Spoon-Knife\n\n";
        let req = Request::parse(input).unwrap();
        assert_eq!(req.protocol, "https");
        assert_eq!(req.host, "github.com");
        assert_eq!(req.path, "octocat/Spoon-Knife");
        assert!(!req.client_supports_authtype);
    }

    #[test]
    fn parse_authtype_capability_sets_flag() {
        let input = b"capability[]=authtype\nprotocol=https\nhost=github.com\npath=o/r\n\n";
        let req = Request::parse(input).unwrap();
        assert!(req.client_supports_authtype);
    }

    #[test]
    fn parse_other_capability_does_not_set_flag() {
        // `state` is a valid capability we don't implement; declaring
        // it must not toggle the authtype flag.
        let input = b"capability[]=state\nprotocol=https\nhost=github.com\npath=o/r\n\n";
        let req = Request::parse(input).unwrap();
        assert!(!req.client_supports_authtype);
    }

    #[test]
    fn parse_empty_capability_resets_flag() {
        // git-credential array semantics: empty value resets the list.
        let input =
            b"capability[]=authtype\ncapability[]=\nprotocol=https\nhost=github.com\npath=o/r\n\n";
        let req = Request::parse(input).unwrap();
        assert!(!req.client_supports_authtype);
    }

    #[test]
    fn parse_strips_dot_git_suffix() {
        let input = b"protocol=https\nhost=github.com\npath=octocat/Spoon-Knife.git\n\n";
        let req = Request::parse(input).unwrap();
        assert_eq!(req.path, "octocat/Spoon-Knife");
    }

    #[test]
    fn parse_does_not_strip_inner_dot_git() {
        let input = b"protocol=https\nhost=github.com\npath=a.gitfoo/b\n\n";
        let req = Request::parse(input).unwrap();
        assert_eq!(req.path, "a.gitfoo/b");
    }

    #[test]
    fn parse_accepts_unknown_keys() {
        let input = b"protocol=https\nhost=github.com\npath=foo\nwwwauth[]=Bearer realm=x\ncapability[]=authtype\n\n";
        let req = Request::parse(input).unwrap();
        assert_eq!(req.host, "github.com");
        assert_eq!(req.path, "foo");
    }

    #[test]
    fn parse_preserves_host_case_byte_exact() {
        let input = b"protocol=https\nhost=GitHub.Com\npath=foo\n\n";
        let req = Request::parse(input).unwrap();
        assert_eq!(req.host, "GitHub.Com");
    }

    #[test]
    fn parse_rejects_cr_in_host_value() {
        // Clone2Leak: attacker tries to inject a second line via CR.
        let input = b"protocol=https\nhost=github.com\rmalicious=1\npath=p\n\n";
        let err = Request::parse(input).unwrap_err();
        assert!(
            matches!(
                err,
                GitCredentialError::ControlByteInLine { byte: 0x0D, .. }
            ),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn parse_rejects_embedded_lf_via_missing_separator() {
        // An LF byte mid-"value" ends the line; the bytes that follow
        // surface as a malformed line, not a value.
        let input = b"host=foo\nbar\nprotocol=https\npath=p\n\n";
        let err = Request::parse(input).unwrap_err();
        assert!(
            matches!(err, GitCredentialError::MissingSeparator { line_no: 2 }),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn new_rejects_cr_in_password() {
        let err = Response::new(
            "u".to_string(),
            "tok\ren".to_string(),
            SystemTime::UNIX_EPOCH,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::ResponseControlByte { field: "password" }
        ));
    }

    #[test]
    fn new_rejects_lf_in_username() {
        let err = Response::new(
            "u\ninject".to_string(),
            "p".to_string(),
            SystemTime::UNIX_EPOCH,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::ResponseControlByte { field: "username" }
        ));
    }

    #[test]
    fn parse_rejects_missing_protocol() {
        let input = b"host=github.com\npath=foo\n\n";
        let err = Request::parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::MissingRequiredKey { key: "protocol" }
        ));
    }

    #[test]
    fn parse_rejects_missing_host() {
        let input = b"protocol=https\npath=foo\n\n";
        let err = Request::parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::MissingRequiredKey { key: "host" }
        ));
    }

    #[test]
    fn parse_rejects_missing_path() {
        let input = b"protocol=https\nhost=github.com\n\n";
        let err = Request::parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::MissingRequiredKey { key: "path" }
        ));
    }

    #[test]
    fn parse_rejects_duplicate_host() {
        let input = b"protocol=https\nhost=foo.com\nhost=bar.com\npath=p\n\n";
        let err = Request::parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::DuplicateKey { key: "host" }
        ));
    }

    #[test]
    fn parse_rejects_duplicate_path() {
        let input = b"protocol=https\nhost=github.com\npath=a\npath=b\n\n";
        let err = Request::parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::DuplicateKey { key: "path" }
        ));
    }

    #[test]
    fn parse_rejects_empty_host_value() {
        let input = b"protocol=https\nhost=\npath=foo\n\n";
        let err = Request::parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::EmptyValue { key: "host" }
        ));
    }

    #[test]
    fn parse_rejects_nul_in_path() {
        let input = b"protocol=https\nhost=github.com\npath=foo\x00bar\n\n";
        let err = Request::parse(input).unwrap_err();
        assert!(
            matches!(
                err,
                GitCredentialError::ControlByteInLine { byte: 0x00, .. }
            ),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn parse_rejects_non_utf8_value() {
        let input = b"protocol=https\nhost=foo\xFFbar\npath=p\n\n";
        let err = Request::parse(input).unwrap_err();
        assert!(
            matches!(err, GitCredentialError::InvalidUtf8 { key } if key == "host"),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn parse_rejects_missing_separator() {
        let input = b"protocol=https\nhost-bad\npath=p\n\n";
        let err = Request::parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::MissingSeparator { line_no: 2 }
        ));
    }

    #[test]
    fn parse_rejects_empty_key() {
        let input = b"protocol=https\n=value\npath=p\n\n";
        let err = Request::parse(input).unwrap_err();
        assert!(matches!(err, GitCredentialError::EmptyKey { line_no: 2 }));
    }

    #[test]
    fn parse_accepts_eof_terminator_no_blank_line() {
        // The shape `git/credential.c::credential_write` actually
        // emits — `key=value\n` lines then `fclose`. No blank line.
        let input = b"protocol=https\nhost=github.com\npath=octocat/Spoon-Knife\n";
        let req = Request::parse(input).expect("EOF after final \\n is a valid terminator");
        assert_eq!(req.host, "github.com");
        assert_eq!(req.path, "octocat/Spoon-Knife");
    }

    #[test]
    fn parse_rejects_unterminated_block_no_final_newline() {
        // Last line missing its trailing `\n` — would mean git was
        // killed mid-write, or a hand-crafted attack. Not a valid
        // terminator under either the blank-line or EOF spec form.
        let input = b"protocol=https\nhost=github.com\npath=p";
        let err = Request::parse(input).unwrap_err();
        assert!(matches!(err, GitCredentialError::UnterminatedBlock));
    }

    #[test]
    fn parse_rejects_empty_input() {
        let err = Request::parse(b"").unwrap_err();
        assert!(matches!(err, GitCredentialError::UnterminatedBlock));
    }

    #[test]
    fn parse_rejects_trailing_bytes_after_blank_line() {
        let input = b"protocol=https\nhost=github.com\npath=p\n\nextra\n";
        let err = Request::parse(input).unwrap_err();
        assert!(matches!(err, GitCredentialError::TrailingBytes));
    }

    #[test]
    fn parse_rejects_url_shorthand_as_missing_host() {
        // `url=` shorthand is not supported. It lands in the
        // unknown-key path, so `host=` is absent and the parser
        // surfaces MissingRequiredKey { key: "host" }.
        let input = b"protocol=https\nurl=https://github.com/owner/repo\n\n";
        let err = Request::parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::MissingRequiredKey { key: "host" }
        ));
    }

    #[test]
    fn parse_rejects_whitespace_around_equals_as_missing_host() {
        // `host = x` parses as key `b"host "` (with trailing space),
        // which is unknown and ignored.
        let input = b"protocol=https\nhost = github.com\npath=foo\n\n";
        let err = Request::parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::MissingRequiredKey { key: "host" }
        ));
    }

    #[test]
    fn emit_round_trips_minimal_response() {
        let r = resp("x-access-token", "ghs_xxxxxxxxxxx", 1_700_000_000);
        let mut out = Vec::new();
        r.encode(&mut out, false);
        assert_eq!(
            out,
            b"username=x-access-token\npassword=ghs_xxxxxxxxxxx\npassword_expiry_utc=1700000000\n\n"
        );
    }

    #[test]
    fn emit_appends_to_nonempty_buffer() {
        let r = resp("u", "p", 1);
        let mut out = b"junk".to_vec();
        r.encode(&mut out, false);
        assert_eq!(&out[..4], b"junk");
        assert_eq!(
            &out[4..],
            b"username=u\npassword=p\npassword_expiry_utc=1\n\n"
        );
    }

    #[test]
    fn emit_renders_expiry_as_unix_seconds() {
        let r = resp("u", "p", 42);
        let mut out = Vec::new();
        r.encode(&mut out, false);
        let body = std::str::from_utf8(&out).unwrap();
        assert!(body.contains("password_expiry_utc=42\n"));
    }

    #[test]
    fn new_rejects_pre_epoch_expiry() {
        let err = Response::new(
            "u".to_string(),
            "p".to_string(),
            SystemTime::UNIX_EPOCH - Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(matches!(err, GitCredentialError::PreEpochExpiry));
    }

    #[test]
    fn encode_emits_basic_even_when_authtype_negotiated() {
        // Regression: github.com's git-HTTP backend only accepts HTTP
        // Basic — `Authorization: Bearer <token>` is rejected with
        // 401 ("remote: invalid credentials"). So even when the
        // client advertised `capability[]=authtype` (git 2.46+), we
        // emit `username`/`password` for git to render as Basic via
        // libcurl `CURLOPT_USERPWD`. The `authtype=Bearer` /
        // `credential=` lines that would land in
        // `http.c::http_append_auth_header` MUST NOT be present.
        let r = resp("x-access-token", "ghs_xxxxxxxxxxx", 1_700_000_000);
        let mut out = Vec::new();
        r.encode(&mut out, true);
        let body = std::str::from_utf8(&out).unwrap();
        assert!(
            body.contains("username=x-access-token\n"),
            "Basic-auth username field missing; got: {body}"
        );
        assert!(
            body.contains("password=ghs_xxxxxxxxxxx\n"),
            "Basic-auth password field missing; got: {body}"
        );
        assert!(
            !body.contains("authtype="),
            "must not emit `authtype=…`; got: {body}"
        );
        assert!(
            !body.contains("credential="),
            "must not emit `credential=…`; got: {body}"
        );
    }

    #[test]
    fn encode_emits_ephemeral_only_when_capability_negotiated() {
        let r = resp("x-access-token", "ghs_tok", 1);

        // Without capability: no ephemeral hint, no capability echo.
        let mut without = Vec::new();
        r.encode(&mut without, false);
        let body_without = std::str::from_utf8(&without).unwrap();
        assert!(!body_without.contains("ephemeral="));
        assert!(!body_without.contains("capability[]=authtype"));

        // With capability: both the echo and the hint must appear.
        // Spec ties `ephemeral` to the authtype capability gate, so
        // we may only emit it after the client opts in.
        let mut with = Vec::new();
        r.encode(&mut with, true);
        let body_with = std::str::from_utf8(&with).unwrap();
        assert!(body_with.contains("capability[]=authtype\n"));
        assert!(body_with.contains("ephemeral=true\n"));
    }

    #[test]
    fn new_rejects_cr_in_token() {
        // The token goes through the same CR/LF/NUL guard as the
        // legacy `password` field — a malformed token must never
        // be wrappable in a `Response` and so can never produce an
        // extra wire line.
        let err = Response::new(
            "x-access-token".to_string(),
            "ghs_xxx\rextra=line".to_string(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::ResponseControlByte { field: "password" }
        ));
    }

    #[test]
    fn parse_accepts_value_just_under_max() {
        let host = "h".repeat(Request::MAX_VALUE_BYTES);
        let input = format!("protocol=https\nhost={host}\npath=p\n\n").into_bytes();
        let req = Request::parse(&input).unwrap();
        assert_eq!(req.host.len(), Request::MAX_VALUE_BYTES);
    }

    #[test]
    fn parse_rejects_value_just_over_max() {
        let host = "h".repeat(Request::MAX_VALUE_BYTES + 1);
        let input = format!("protocol=https\nhost={host}\npath=p\n\n").into_bytes();
        let err = Request::parse(&input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::ValueTooLong { key: "host", .. }
        ));
    }

    #[test]
    fn parse_rejects_request_just_over_max() {
        // Build a block one byte past the request cap. The cap is
        // checked before any line scanning, so we don't need a
        // well-formed inner shape.
        let input = vec![b'x'; Request::PARSER_HARD_MAX + 1];
        let err = Request::parse(&input).unwrap_err();
        assert!(matches!(err, GitCredentialError::RequestTooLarge { .. }));
    }
}
