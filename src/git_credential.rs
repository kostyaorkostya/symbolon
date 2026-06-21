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

use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone)]
pub struct Response {
    pub username: String,
    pub password: String,
    pub password_expiry_utc: SystemTime,
}

#[derive(Debug, thiserror::Error)]
pub enum GitCredentialError {
    #[error("request block is not terminated by an empty line")]
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
    #[error("CR byte (0x0D) in value for '{key}'")]
    CarriageReturnInValue { key: &'static str },
    #[error("NUL byte (0x00) in value for '{key}'")]
    NulInValue { key: &'static str },
    #[error("value for '{key}' is not valid UTF-8")]
    InvalidUtf8 { key: &'static str },
    #[error("response field '{field}' contains a forbidden control byte")]
    ResponseControlByte { field: &'static str },
    #[error("password_expiry_utc is before the UNIX epoch")]
    EmitInvalidExpiry,
    #[error("value for '{key}' exceeds {max} bytes")]
    ValueTooLong { key: &'static str, max: usize },
    #[error("request block exceeds {max} bytes")]
    RequestTooLarge { max: usize },
}

/// Hard ceilings for git-credential request parsing. Real-world
/// inputs are tens of bytes; legitimate hosts/paths run hundreds at
/// most. Bounded to defend against pathological inputs (e.g. a
/// runaway value buffer) without restricting any plausible repo URL.
///
/// `PARSER_HARD_MAX` is the absolute parser ceiling for direct
/// callers (fuzz harnesses, in-process tests). The daemon enforces
/// a tighter per-connection `WIRE_READ_BUDGET` on the read loop
/// before bytes even reach this parser; see `src/daemon.rs`.
pub const MAX_VALUE_BYTES: usize = 4 * 1024;
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
pub fn parse(input: &[u8]) -> Result<Request, GitCredentialError> {
    if input.len() > PARSER_HARD_MAX {
        return Err(GitCredentialError::RequestTooLarge {
            max: PARSER_HARD_MAX,
        });
    }
    let term_pos = input
        .windows(2)
        .position(|w| w == b"\n\n")
        .ok_or(GitCredentialError::UnterminatedBlock)?;
    if term_pos + 2 < input.len() {
        return Err(GitCredentialError::TrailingBytes);
    }

    let block = &input[..term_pos];

    let mut protocol: Option<String> = None;
    let mut host: Option<String> = None;
    let mut path: Option<String> = None;
    let mut client_supports_authtype = false;

    for (i, line) in block.split(|&c| c == b'\n').enumerate() {
        let line_no = i + 1;
        let eq_pos = line
            .iter()
            .position(|&c| c == b'=')
            .ok_or(GitCredentialError::MissingSeparator { line_no })?;
        let key_bytes = &line[..eq_pos];
        let value_bytes = &line[eq_pos + 1..];

        if key_bytes.is_empty() {
            return Err(GitCredentialError::EmptyKey { line_no });
        }

        // `capability[]` is the only repeating array key we inspect.
        // Multiple lines like `capability[]=authtype\ncapability[]=state\n`
        // are all valid; we track whether `authtype` appeared. Empty
        // value `capability[]=` is the spec-defined "reset" for the
        // array and clears any earlier flags (per git-credential.adoc
        // array semantics).
        if key_bytes == b"capability[]" {
            if value_bytes.is_empty() {
                client_supports_authtype = false;
            } else if value_bytes == b"authtype" {
                client_supports_authtype = true;
            }
            // Other capabilities (e.g. `state`) ignored — we don't
            // implement them.
            continue;
        }

        // Unknown keys are accepted and ignored: `gitcredentials(7)`
        // is extensible (`wwwauth[]`, etc.). Whitespace-around-`=`
        // requests also land here as unknown keys (e.g. `host ` with
        // a trailing space), and `url=` shorthand is rejected
        // implicitly by the same path.
        let (key, slot) = match key_bytes {
            b"protocol" => ("protocol", &mut protocol),
            b"host" => ("host", &mut host),
            b"path" => ("path", &mut path),
            _ => continue,
        };

        if value_bytes.len() > MAX_VALUE_BYTES {
            return Err(GitCredentialError::ValueTooLong {
                key,
                max: MAX_VALUE_BYTES,
            });
        }

        for &b in value_bytes {
            match b {
                0x00 => return Err(GitCredentialError::NulInValue { key }),
                0x0D => return Err(GitCredentialError::CarriageReturnInValue { key }),
                _ => {}
            }
        }

        if value_bytes.is_empty() {
            return Err(GitCredentialError::EmptyValue { key });
        }
        if slot.is_some() {
            return Err(GitCredentialError::DuplicateKey { key });
        }

        let value = std::str::from_utf8(value_bytes)
            .map_err(|_| GitCredentialError::InvalidUtf8 { key })?
            .to_string();
        *slot = Some(value);
    }

    let protocol = protocol.ok_or(GitCredentialError::MissingRequiredKey { key: "protocol" })?;
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

    Ok(Request {
        protocol,
        host,
        path,
        client_supports_authtype,
    })
}

/// Emit the response shape git-credential expects. When
/// `client_supports_authtype` is true (negotiated via
/// `capability[]=authtype` in the request), emit the modern
/// `authtype=Bearer` + `credential=<token>` + `ephemeral=true`
/// shape; otherwise emit the legacy `username`/`password` shape
/// for git ≤ 2.45.
///
/// The modern shape:
/// - **`authtype=Bearer` + `credential=<token>`** produces the
///   `Authorization: Bearer <token>` header git constructs in
///   `http.c::http_append_auth_header` — the same form GitHub's
///   REST API documents (the git-HTTP frontend accepts it too,
///   though that's not explicitly documented).
/// - **`ephemeral=true`** tells downstream credential helpers
///   (cache, store) NOT to persist the credential — load-bearing
///   for our 1-hour-TTL installation tokens.
/// - `username` is omitted: when `credential` is set, the
///   git-credential spec says `username` / `password` are not used.
pub(crate) fn write_response(
    resp: &Response,
    client_supports_authtype: bool,
    out: &mut Vec<u8>,
) -> Result<(), GitCredentialError> {
    check_response_field("password", &resp.password)?;

    let expiry_secs = resp
        .password_expiry_utc
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| GitCredentialError::EmitInvalidExpiry)?
        .as_secs();
    let expiry_str = expiry_secs.to_string();

    if client_supports_authtype {
        // Modern shape (git 2.46+ after authtype capability negotiation).
        // The token in `resp.password` IS the bearer credential.
        out.extend_from_slice(b"capability[]=authtype\n");
        out.extend_from_slice(b"authtype=Bearer\n");
        out.extend_from_slice(b"credential=");
        out.extend_from_slice(resp.password.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(b"ephemeral=true\n");
        out.extend_from_slice(b"password_expiry_utc=");
        out.extend_from_slice(expiry_str.as_bytes());
        out.push(b'\n');
        out.push(b'\n');
    } else {
        check_response_field("username", &resp.username)?;
        // Legacy shape (git ≤ 2.45 or any client that didn't
        // declare authtype capability). The `username` is always
        // `x-access-token` for GitHub installation tokens.
        out.extend_from_slice(b"username=");
        out.extend_from_slice(resp.username.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(b"password=");
        out.extend_from_slice(resp.password.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(b"password_expiry_utc=");
        out.extend_from_slice(expiry_str.as_bytes());
        out.push(b'\n');
        out.push(b'\n');
    }

    Ok(())
}

fn check_response_field(field: &'static str, value: &str) -> Result<(), GitCredentialError> {
    for &b in value.as_bytes() {
        if matches!(b, 0x00 | 0x0D | 0x0A) {
            return Err(GitCredentialError::ResponseControlByte { field });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn resp(username: &str, password: &str, expiry_secs: u64) -> Response {
        Response {
            username: username.to_string(),
            password: password.to_string(),
            password_expiry_utc: SystemTime::UNIX_EPOCH + Duration::from_secs(expiry_secs),
        }
    }

    #[test]
    fn parse_minimal_request_ok() {
        let input = b"protocol=https\nhost=github.com\npath=octocat/Spoon-Knife\n\n";
        let req = parse(input).unwrap();
        assert_eq!(req.protocol, "https");
        assert_eq!(req.host, "github.com");
        assert_eq!(req.path, "octocat/Spoon-Knife");
        assert!(!req.client_supports_authtype);
    }

    #[test]
    fn parse_authtype_capability_sets_flag() {
        let input = b"capability[]=authtype\nprotocol=https\nhost=github.com\npath=o/r\n\n";
        let req = parse(input).unwrap();
        assert!(req.client_supports_authtype);
    }

    #[test]
    fn parse_other_capability_does_not_set_flag() {
        // `state` is a valid capability we don't implement; declaring
        // it must not toggle the authtype flag.
        let input = b"capability[]=state\nprotocol=https\nhost=github.com\npath=o/r\n\n";
        let req = parse(input).unwrap();
        assert!(!req.client_supports_authtype);
    }

    #[test]
    fn parse_empty_capability_resets_flag() {
        // git-credential array semantics: empty value resets the list.
        let input =
            b"capability[]=authtype\ncapability[]=\nprotocol=https\nhost=github.com\npath=o/r\n\n";
        let req = parse(input).unwrap();
        assert!(!req.client_supports_authtype);
    }

    #[test]
    fn parse_strips_dot_git_suffix() {
        let input = b"protocol=https\nhost=github.com\npath=octocat/Spoon-Knife.git\n\n";
        let req = parse(input).unwrap();
        assert_eq!(req.path, "octocat/Spoon-Knife");
    }

    #[test]
    fn parse_does_not_strip_inner_dot_git() {
        let input = b"protocol=https\nhost=github.com\npath=a.gitfoo/b\n\n";
        let req = parse(input).unwrap();
        assert_eq!(req.path, "a.gitfoo/b");
    }

    #[test]
    fn parse_accepts_unknown_keys() {
        let input = b"protocol=https\nhost=github.com\npath=foo\nwwwauth[]=Bearer realm=x\ncapability[]=authtype\n\n";
        let req = parse(input).unwrap();
        assert_eq!(req.host, "github.com");
        assert_eq!(req.path, "foo");
    }

    #[test]
    fn parse_preserves_host_case_byte_exact() {
        let input = b"protocol=https\nhost=GitHub.Com\npath=foo\n\n";
        let req = parse(input).unwrap();
        assert_eq!(req.host, "GitHub.Com");
    }

    #[test]
    fn parse_rejects_cr_in_host_value() {
        // Clone2Leak: attacker tries to inject a second line via CR.
        let input = b"protocol=https\nhost=github.com\rmalicious=1\npath=p\n\n";
        let err = parse(input).unwrap_err();
        assert!(
            matches!(err, GitCredentialError::CarriageReturnInValue { key } if key == "host"),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn parse_rejects_embedded_lf_via_missing_separator() {
        // An LF byte mid-"value" ends the line; the bytes that follow
        // surface as a malformed line, not a value.
        let input = b"host=foo\nbar\nprotocol=https\npath=p\n\n";
        let err = parse(input).unwrap_err();
        assert!(
            matches!(err, GitCredentialError::MissingSeparator { line_no: 2 }),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn emit_rejects_cr_in_password() {
        let r = resp("u", "tok\ren", 0);
        let mut out = Vec::new();
        let err = write_response(&r, false, &mut out).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::ResponseControlByte { field: "password" }
        ));
    }

    #[test]
    fn emit_rejects_lf_in_username() {
        let r = resp("u\ninject", "p", 0);
        let mut out = Vec::new();
        let err = write_response(&r, false, &mut out).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::ResponseControlByte { field: "username" }
        ));
    }

    #[test]
    fn parse_rejects_missing_protocol() {
        let input = b"host=github.com\npath=foo\n\n";
        let err = parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::MissingRequiredKey { key: "protocol" }
        ));
    }

    #[test]
    fn parse_rejects_missing_host() {
        let input = b"protocol=https\npath=foo\n\n";
        let err = parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::MissingRequiredKey { key: "host" }
        ));
    }

    #[test]
    fn parse_rejects_missing_path() {
        let input = b"protocol=https\nhost=github.com\n\n";
        let err = parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::MissingRequiredKey { key: "path" }
        ));
    }

    #[test]
    fn parse_rejects_duplicate_host() {
        let input = b"protocol=https\nhost=foo.com\nhost=bar.com\npath=p\n\n";
        let err = parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::DuplicateKey { key: "host" }
        ));
    }

    #[test]
    fn parse_rejects_duplicate_path() {
        let input = b"protocol=https\nhost=github.com\npath=a\npath=b\n\n";
        let err = parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::DuplicateKey { key: "path" }
        ));
    }

    #[test]
    fn parse_rejects_empty_host_value() {
        let input = b"protocol=https\nhost=\npath=foo\n\n";
        let err = parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::EmptyValue { key: "host" }
        ));
    }

    #[test]
    fn parse_rejects_nul_in_path() {
        let input = b"protocol=https\nhost=github.com\npath=foo\x00bar\n\n";
        let err = parse(input).unwrap_err();
        assert!(
            matches!(err, GitCredentialError::NulInValue { key } if key == "path"),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn parse_rejects_non_utf8_value() {
        let input = b"protocol=https\nhost=foo\xFFbar\npath=p\n\n";
        let err = parse(input).unwrap_err();
        assert!(
            matches!(err, GitCredentialError::InvalidUtf8 { key } if key == "host"),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn parse_rejects_missing_separator() {
        let input = b"protocol=https\nhost-bad\npath=p\n\n";
        let err = parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::MissingSeparator { line_no: 2 }
        ));
    }

    #[test]
    fn parse_rejects_empty_key() {
        let input = b"protocol=https\n=value\npath=p\n\n";
        let err = parse(input).unwrap_err();
        assert!(matches!(err, GitCredentialError::EmptyKey { line_no: 2 }));
    }

    #[test]
    fn parse_rejects_unterminated_block() {
        let input = b"protocol=https\nhost=github.com\npath=p\n";
        let err = parse(input).unwrap_err();
        assert!(matches!(err, GitCredentialError::UnterminatedBlock));
    }

    #[test]
    fn parse_rejects_trailing_bytes_after_blank_line() {
        let input = b"protocol=https\nhost=github.com\npath=p\n\nextra\n";
        let err = parse(input).unwrap_err();
        assert!(matches!(err, GitCredentialError::TrailingBytes));
    }

    #[test]
    fn parse_rejects_url_shorthand_as_missing_host() {
        // `url=` shorthand is not supported. It lands in the
        // unknown-key path, so `host=` is absent and the parser
        // surfaces MissingRequiredKey { key: "host" }.
        let input = b"protocol=https\nurl=https://github.com/owner/repo\n\n";
        let err = parse(input).unwrap_err();
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
        let err = parse(input).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::MissingRequiredKey { key: "host" }
        ));
    }

    #[test]
    fn emit_round_trips_minimal_response() {
        let r = resp("x-access-token", "ghs_xxxxxxxxxxx", 1_700_000_000);
        let mut out = Vec::new();
        write_response(&r, false, &mut out).unwrap();
        assert_eq!(
            out,
            b"username=x-access-token\npassword=ghs_xxxxxxxxxxx\npassword_expiry_utc=1700000000\n\n"
        );
    }

    #[test]
    fn emit_appends_to_nonempty_buffer() {
        let r = resp("u", "p", 1);
        let mut out = b"junk".to_vec();
        write_response(&r, false, &mut out).unwrap();
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
        write_response(&r, false, &mut out).unwrap();
        let body = std::str::from_utf8(&out).unwrap();
        assert!(body.contains("password_expiry_utc=42\n"));
    }

    #[test]
    fn emit_rejects_pre_epoch_expiry() {
        let r = Response {
            username: "u".to_string(),
            password: "p".to_string(),
            password_expiry_utc: SystemTime::UNIX_EPOCH - Duration::from_secs(1),
        };
        let mut out = Vec::new();
        let err = write_response(&r, false, &mut out).unwrap_err();
        assert!(matches!(err, GitCredentialError::EmitInvalidExpiry));
    }

    #[test]
    fn emit_modern_shape_when_authtype_negotiated() {
        let r = resp("x-access-token", "ghs_xxxxxxxxxxx", 1_700_000_000);
        let mut out = Vec::new();
        write_response(&r, true, &mut out).unwrap();
        assert_eq!(
            out,
            b"capability[]=authtype\n\
              authtype=Bearer\n\
              credential=ghs_xxxxxxxxxxx\n\
              ephemeral=true\n\
              password_expiry_utc=1700000000\n\
              \n"
        );
    }

    #[test]
    fn emit_modern_shape_omits_username() {
        // Spec: when `credential` is set, `username`/`password` are
        // not used. The `resp.username` value (always
        // "x-access-token" for us) must NOT leak into the wire.
        let r = resp("x-access-token", "ghs_tok", 1);
        let mut out = Vec::new();
        write_response(&r, true, &mut out).unwrap();
        let body = std::str::from_utf8(&out).unwrap();
        assert!(!body.contains("username="));
        assert!(!body.contains("password=")); // distinct from `password_expiry_utc`
        assert!(body.contains("ephemeral=true\n"));
    }

    #[test]
    fn emit_modern_rejects_cr_in_token() {
        // The token goes through the same CR/LF/NUL guard as the
        // legacy `password` field — a malformed token must never
        // produce an extra wire line.
        let r = resp("x-access-token", "ghs_xxx\rextra=line", 1);
        let mut out = Vec::new();
        let err = write_response(&r, true, &mut out).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::ResponseControlByte { field: "password" }
        ));
    }

    #[test]
    fn parse_accepts_value_just_under_max() {
        let host = "h".repeat(MAX_VALUE_BYTES);
        let input = format!("protocol=https\nhost={host}\npath=p\n\n").into_bytes();
        let req = parse(&input).unwrap();
        assert_eq!(req.host.len(), MAX_VALUE_BYTES);
    }

    #[test]
    fn parse_rejects_value_just_over_max() {
        let host = "h".repeat(MAX_VALUE_BYTES + 1);
        let input = format!("protocol=https\nhost={host}\npath=p\n\n").into_bytes();
        let err = parse(&input).unwrap_err();
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
        let input = vec![b'x'; PARSER_HARD_MAX + 1];
        let err = parse(&input).unwrap_err();
        assert!(matches!(err, GitCredentialError::RequestTooLarge { .. }));
    }
}
