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

// Transitional: nothing in the crate calls `parse` or `write_response`
// yet — `daemon` and `admin` are still stubs. Remove this allow when
// those modules land and start calling into this one.
#![allow(dead_code)]

use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) protocol: String,
    pub(crate) host: String,
    pub(crate) path: String,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub username: String,
    pub password: String,
    pub password_expiry_utc: SystemTime,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum GitCredentialError {
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
    CarriageReturnInValue { key: String },
    #[error("NUL byte (0x00) in value for '{key}'")]
    NulInValue { key: String },
    #[error("value for '{key}' is not valid UTF-8")]
    InvalidUtf8 { key: String },
    #[error("response field '{field}' contains a forbidden control byte")]
    ResponseControlByte { field: &'static str },
    #[error("password_expiry_utc is before the UNIX epoch")]
    EmitInvalidExpiry,
}

pub(crate) fn parse(input: &[u8]) -> Result<Request, GitCredentialError> {
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

    if !block.is_empty() {
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

            // Unknown keys are accepted and ignored: `gitcredentials(7)`
            // is extensible (`wwwauth[]`, `capability[]`, etc.).
            // Whitespace-around-`=` requests also land here as unknown
            // keys (e.g. `host ` with a trailing space), and `url=`
            // shorthand is rejected implicitly by the same path.
            let key_static: &'static str = match key_bytes {
                b"protocol" => "protocol",
                b"host" => "host",
                b"path" => "path",
                _ => continue,
            };

            for &b in value_bytes {
                match b {
                    0x00 => {
                        return Err(GitCredentialError::NulInValue {
                            key: key_static.to_string(),
                        });
                    }
                    0x0D => {
                        return Err(GitCredentialError::CarriageReturnInValue {
                            key: key_static.to_string(),
                        });
                    }
                    _ => {}
                }
            }

            if value_bytes.is_empty() {
                return Err(GitCredentialError::EmptyValue { key: key_static });
            }

            let value = std::str::from_utf8(value_bytes)
                .map_err(|_| GitCredentialError::InvalidUtf8 {
                    key: key_static.to_string(),
                })?
                .to_string();

            let slot = match key_static {
                "protocol" => &mut protocol,
                "host" => &mut host,
                "path" => &mut path,
                _ => unreachable!(),
            };
            if slot.is_some() {
                return Err(GitCredentialError::DuplicateKey { key: key_static });
            }
            *slot = Some(value);
        }
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
    })
}

pub(crate) fn write_response(resp: &Response, out: &mut Vec<u8>) -> Result<(), GitCredentialError> {
    check_response_field("username", &resp.username)?;
    check_response_field("password", &resp.password)?;

    let expiry_secs = resp
        .password_expiry_utc
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| GitCredentialError::EmitInvalidExpiry)?
        .as_secs();

    out.extend_from_slice(b"username=");
    out.extend_from_slice(resp.username.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(b"password=");
    out.extend_from_slice(resp.password.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(b"password_expiry_utc=");
    out.extend_from_slice(expiry_secs.to_string().as_bytes());
    out.push(b'\n');
    out.push(b'\n');

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

    #[test]
    fn parse_minimal_request_ok() {
        let input = b"protocol=https\nhost=github.com\npath=octocat/Spoon-Knife\n\n";
        let req = parse(input).unwrap();
        assert_eq!(req.protocol, "https");
        assert_eq!(req.host, "github.com");
        assert_eq!(req.path, "octocat/Spoon-Knife");
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
            matches!(err, GitCredentialError::CarriageReturnInValue { ref key } if key == "host"),
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
        let resp = Response {
            username: "u".to_string(),
            password: "tok\ren".to_string(),
            password_expiry_utc: SystemTime::UNIX_EPOCH,
        };
        let mut out = Vec::new();
        let err = write_response(&resp, &mut out).unwrap_err();
        assert!(matches!(
            err,
            GitCredentialError::ResponseControlByte { field: "password" }
        ));
    }

    #[test]
    fn emit_rejects_lf_in_username() {
        let resp = Response {
            username: "u\ninject".to_string(),
            password: "p".to_string(),
            password_expiry_utc: SystemTime::UNIX_EPOCH,
        };
        let mut out = Vec::new();
        let err = write_response(&resp, &mut out).unwrap_err();
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
            matches!(err, GitCredentialError::NulInValue { ref key } if key == "path"),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn parse_rejects_non_utf8_value() {
        let input = b"protocol=https\nhost=foo\xFFbar\npath=p\n\n";
        let err = parse(input).unwrap_err();
        assert!(
            matches!(err, GitCredentialError::InvalidUtf8 { ref key } if key == "host"),
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
        let resp = Response {
            username: "x-access-token".to_string(),
            password: "ghs_xxxxxxxxxxx".to_string(),
            password_expiry_utc: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        };
        let mut out = Vec::new();
        write_response(&resp, &mut out).unwrap();
        assert_eq!(
            out,
            b"username=x-access-token\npassword=ghs_xxxxxxxxxxx\npassword_expiry_utc=1700000000\n\n"
        );
    }

    #[test]
    fn emit_appends_to_nonempty_buffer() {
        let resp = Response {
            username: "u".to_string(),
            password: "p".to_string(),
            password_expiry_utc: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        };
        let mut out = b"junk".to_vec();
        write_response(&resp, &mut out).unwrap();
        assert_eq!(&out[..4], b"junk");
        assert_eq!(
            &out[4..],
            b"username=u\npassword=p\npassword_expiry_utc=1\n\n"
        );
    }

    #[test]
    fn emit_renders_expiry_as_unix_seconds() {
        let resp = Response {
            username: "u".to_string(),
            password: "p".to_string(),
            password_expiry_utc: SystemTime::UNIX_EPOCH + Duration::from_secs(42),
        };
        let mut out = Vec::new();
        write_response(&resp, &mut out).unwrap();
        let body = std::str::from_utf8(&out).unwrap();
        assert!(body.contains("password_expiry_utc=42\n"));
    }

    #[test]
    fn emit_rejects_pre_epoch_expiry() {
        let resp = Response {
            username: "u".to_string(),
            password: "p".to_string(),
            password_expiry_utc: SystemTime::UNIX_EPOCH - Duration::from_secs(1),
        };
        let mut out = Vec::new();
        let err = write_response(&resp, &mut out).unwrap_err();
        assert!(matches!(err, GitCredentialError::EmitInvalidExpiry));
    }
}
