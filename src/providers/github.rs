//! GitHub provider: App JWT signing, repository-ID resolution (with
//! TTL cache), and installation-access-token minting.
//!
//! Per-mint scope is hard-coded to `repository_ids: [<one>]` plus
//! `permissions: {contents: write, metadata: read}` (AGENTS.md
//! invariants #4 and #5). The App private key is loaded once at
//! provider construction and held in memory; rotation requires a
//! restart.
//!
//! See `docs/PROTOCOLS.md` ("GitHub provider outbound") for the
//! wire-level contract.

// Transitional: nothing in the crate calls into this module yet —
// `daemon` is still a stub. Remove this allow when the dispatch
// path lands.
#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

use crate::config::ProviderGithub;
use crate::git_credential;

const GITHUB_API_VERSION: &str = "2022-11-28";
const ACCEPT_HEADER: &str = "application/vnd.github+json";
const CACHE_TTL: Duration = Duration::from_secs(600);
const JWT_LEEWAY_PAST: u64 = 60;
const JWT_LIFETIME: u64 = 540;

pub struct GitHubProvider {
    host: String,
    api_base: String,
    app_id: u64,
    installation_id: u64,
    encoding_key: EncodingKey,
    client: cyper::Client,
    user_agent: String,
    clock: fn() -> SystemTime,
    repo_ids: RepoIdCache,
}

#[derive(Default)]
struct RepoIdCache(RefCell<HashMap<String, CachedRepoId>>);

#[derive(Copy, Clone)]
struct CachedRepoId {
    id: u64,
    expires_at: SystemTime,
}

#[derive(Debug, thiserror::Error)]
pub enum GithubError {
    #[error("failed to read PEM key at {}", path.display())]
    PemRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse PEM key at {}", path.display())]
    PemParse {
        path: PathBuf,
        #[source]
        source: jsonwebtoken::errors::Error,
    },
    #[error("failed to sign JWT")]
    JwtSign(#[source] jsonwebtoken::errors::Error),
    #[error("HTTP transport error")]
    Http(#[source] cyper::Error),
    #[error("malformed response from {context}")]
    JsonParse {
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("missing field '{field}' in {context} response")]
    MissingField {
        context: &'static str,
        field: &'static str,
    },
    #[error("malformed `expires_at`: {0}")]
    BadExpiresAt(String),
    #[error("malformed owner/repo path: {0}")]
    MalformedPath(String),
    #[error("unauthorized (401) — App key may be invalid or revoked")]
    Unauthorized,
    #[error("forbidden (403) — likely missing User-Agent or App lacks permission")]
    Forbidden,
    #[error("repository '{path}' not found or App lacks access")]
    RepoNotFound { path: String },
    #[error("rate limited (429)")]
    RateLimited,
    #[error("server error from provider: {0}")]
    ServerError(u16),
    #[error("unexpected provider status: {0}")]
    UnexpectedStatus(u16),
}

impl From<cyper::Error> for GithubError {
    fn from(e: cyper::Error) -> Self {
        GithubError::Http(e)
    }
}

impl GitHubProvider {
    pub fn new(cfg: &ProviderGithub) -> Result<Self, GithubError> {
        Self::with_overrides(cfg, None, SystemTime::now)
    }

    /// Test-only ctor. External code should use [`new`].
    #[doc(hidden)]
    pub fn with_overrides(
        cfg: &ProviderGithub,
        api_base_override: Option<String>,
        clock: fn() -> SystemTime,
    ) -> Result<Self, GithubError> {
        let pem_bytes =
            std::fs::read(&cfg.private_key_path).map_err(|source| GithubError::PemRead {
                path: cfg.private_key_path.clone(),
                source,
            })?;
        let encoding_key =
            EncodingKey::from_rsa_pem(&pem_bytes).map_err(|source| GithubError::PemParse {
                path: cfg.private_key_path.clone(),
                source,
            })?;
        let api_base = api_base_override
            .unwrap_or_else(|| cfg.api_base.clone())
            .trim_end_matches('/')
            .to_string();

        Ok(Self {
            host: cfg.host.clone(),
            api_base,
            app_id: cfg.app_id,
            installation_id: cfg.installation_id,
            encoding_key,
            client: cyper::Client::new(),
            user_agent: format!("gcb/{}", env!("CARGO_PKG_VERSION")),
            clock,
            repo_ids: RepoIdCache::default(),
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub async fn mint(&self, path: &str) -> Result<git_credential::Response, GithubError> {
        let (owner, repo) = split_owner_repo(path)?;
        let key = format!(
            "{}/{}",
            owner.to_ascii_lowercase(),
            repo.to_ascii_lowercase()
        );
        let now = (self.clock)();

        let repo_id = match self.repo_ids.lookup(&key, now) {
            Some(id) => id,
            None => {
                let id = self.resolve_repo_id(owner, repo).await?;
                self.repo_ids.insert(&key, id, now + CACHE_TTL);
                id
            }
        };

        match self.mint_token(repo_id, path).await {
            Ok((token, expires_at)) => Ok(git_credential::Response {
                username: "x-access-token".to_string(),
                password: token,
                password_expiry_utc: expires_at,
            }),
            Err(GithubError::RepoNotFound { path: p }) => {
                // Repo deleted/recreated since the resolve — drop the
                // cached id so the next mint re-resolves.
                self.repo_ids.invalidate(&key);
                Err(GithubError::RepoNotFound { path: p })
            }
            Err(e) => Err(e),
        }
    }

    async fn resolve_repo_id(&self, owner: &str, repo: &str) -> Result<u64, GithubError> {
        let jwt = self.sign_jwt_now()?;
        let url = format!("{}/repos/{}/{}", self.api_base, owner, repo);
        let resp = self
            .client
            .get(&url)?
            .bearer_auth(&jwt)?
            .header("Accept", ACCEPT_HEADER)?
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)?
            .header("User-Agent", &self.user_agent)?
            .send()
            .await?;
        let status = resp.status().as_u16();
        match status {
            200 => {}
            401 => return Err(GithubError::Unauthorized),
            403 => return Err(GithubError::Forbidden),
            404 => {
                return Err(GithubError::RepoNotFound {
                    path: format!("{owner}/{repo}"),
                });
            }
            429 => return Err(GithubError::RateLimited),
            500..=599 => return Err(GithubError::ServerError(status)),
            _ => return Err(GithubError::UnexpectedStatus(status)),
        }
        let body = resp.bytes().await?;
        parse_repo_response(&body)
    }

    async fn mint_token(
        &self,
        repo_id: u64,
        path: &str,
    ) -> Result<(String, SystemTime), GithubError> {
        let jwt = self.sign_jwt_now()?;
        let url = format!(
            "{}/app/installations/{}/access_tokens",
            self.api_base, self.installation_id
        );
        let body = build_mint_body(repo_id);
        let resp = self
            .client
            .post(&url)?
            .bearer_auth(&jwt)?
            .header("Accept", ACCEPT_HEADER)?
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)?
            .header("User-Agent", &self.user_agent)?
            .header("Content-Type", "application/json")?
            .body(body)
            .send()
            .await?;
        let status = resp.status().as_u16();
        match status {
            201 => {}
            401 => return Err(GithubError::Unauthorized),
            403 => return Err(GithubError::Forbidden),
            404 => {
                return Err(GithubError::RepoNotFound {
                    path: path.to_string(),
                });
            }
            429 => return Err(GithubError::RateLimited),
            500..=599 => return Err(GithubError::ServerError(status)),
            _ => return Err(GithubError::UnexpectedStatus(status)),
        }
        let bytes = resp.bytes().await?;
        parse_mint_response(&bytes)
    }

    fn sign_jwt_now(&self) -> Result<String, GithubError> {
        let claims = build_claims((self.clock)(), self.app_id);
        sign_jwt(&claims, &self.encoding_key)
    }
}

impl RepoIdCache {
    fn lookup(&self, key: &str, now: SystemTime) -> Option<u64> {
        self.0
            .borrow()
            .get(key)
            .copied()
            .filter(|e| e.expires_at > now)
            .map(|e| e.id)
    }

    fn insert(&self, key: &str, id: u64, expires_at: SystemTime) {
        self.0
            .borrow_mut()
            .insert(key.to_string(), CachedRepoId { id, expires_at });
    }

    fn invalidate(&self, key: &str) {
        self.0.borrow_mut().remove(key);
    }
}

#[derive(Serialize)]
struct JwtClaims {
    iss: String,
    iat: u64,
    exp: u64,
}

#[derive(Serialize)]
struct MintRequestBody {
    repository_ids: [u64; 1],
    permissions: MintPermissions,
}

#[derive(Serialize)]
struct MintPermissions {
    contents: &'static str,
    metadata: &'static str,
}

fn build_claims(now: SystemTime, app_id: u64) -> JwtClaims {
    let unix = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    JwtClaims {
        iss: app_id.to_string(),
        iat: unix.saturating_sub(JWT_LEEWAY_PAST),
        exp: unix.saturating_add(JWT_LIFETIME),
    }
}

fn sign_jwt(claims: &JwtClaims, key: &EncodingKey) -> Result<String, GithubError> {
    let header = Header::new(Algorithm::RS256);
    jsonwebtoken::encode(&header, claims, key).map_err(GithubError::JwtSign)
}

fn build_mint_body(repo_id: u64) -> Vec<u8> {
    let body = MintRequestBody {
        repository_ids: [repo_id],
        permissions: MintPermissions {
            contents: "write",
            metadata: "read",
        },
    };
    serde_json::to_vec(&body).expect("MintRequestBody fields are all serializable")
}

fn parse_mint_response(bytes: &[u8]) -> Result<(String, SystemTime), GithubError> {
    let v: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|source| GithubError::JsonParse {
            context: "mint",
            source,
        })?;
    let token = v
        .get("token")
        .and_then(|t| t.as_str())
        .ok_or(GithubError::MissingField {
            context: "mint",
            field: "token",
        })?
        .to_string();
    let expires_at_str =
        v.get("expires_at")
            .and_then(|t| t.as_str())
            .ok_or(GithubError::MissingField {
                context: "mint",
                field: "expires_at",
            })?;
    let expires_at = parse_rfc3339_z(expires_at_str)?;
    Ok((token, expires_at))
}

fn parse_repo_response(bytes: &[u8]) -> Result<u64, GithubError> {
    let v: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|source| GithubError::JsonParse {
            context: "repo",
            source,
        })?;
    v.get("id")
        .and_then(|i| i.as_u64())
        .ok_or(GithubError::MissingField {
            context: "repo",
            field: "id",
        })
}

fn split_owner_repo(path: &str) -> Result<(&str, &str), GithubError> {
    if !path.is_ascii() {
        return Err(GithubError::MalformedPath(path.to_string()));
    }
    let mut parts = path.splitn(2, '/');
    let owner = parts.next().unwrap_or("");
    let repo = parts.next().unwrap_or("");
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return Err(GithubError::MalformedPath(path.to_string()));
    }
    Ok((owner, repo))
}

fn parse_rfc3339_z(s: &str) -> Result<SystemTime, GithubError> {
    let bad = || GithubError::BadExpiresAt(s.to_string());
    let bytes = s.as_bytes();
    if bytes.len() != 20 {
        return Err(bad());
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return Err(bad());
    }
    let parse_int = |range: std::ops::Range<usize>| -> Result<u32, GithubError> {
        let slice = &bytes[range];
        if !slice.iter().all(u8::is_ascii_digit) {
            return Err(bad());
        }
        std::str::from_utf8(slice)
            .map_err(|_| bad())?
            .parse()
            .map_err(|_| bad())
    };
    let year = parse_int(0..4)?;
    let month = parse_int(5..7)?;
    let day = parse_int(8..10)?;
    let hour = parse_int(11..13)?;
    let minute = parse_int(14..16)?;
    let second = parse_int(17..19)?;

    if year < 1970 || !(1..=12).contains(&month) {
        return Err(bad());
    }
    if !(1..=days_in_month(year, month)).contains(&day) {
        return Err(bad());
    }
    if hour > 23 || minute > 59 || second > 59 {
        return Err(bad());
    }

    let days = days_from_civil(year as i64, month as i64, day as i64);
    let secs = days * 86_400 + (hour as i64) * 3600 + (minute as i64) * 60 + second as i64;
    if secs < 0 {
        return Err(bad());
    }
    Ok(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

// Howard Hinnant's days-from-civil: days between 1970-01-01 and y-m-d.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = y - era * 400;
    let doy = (153 * if m > 2 { m - 3 } else { m + 9 } + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_PEM: &str = include_str!("../../tests/fixtures/test_app_key.pem");

    fn t(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn build_claims_at_fixed_time() {
        let claims = build_claims(t(1_700_000_000), 42);
        assert_eq!(claims.iss, "42");
        assert_eq!(claims.iat, 1_700_000_000 - 60);
        assert_eq!(claims.exp, 1_700_000_000 + 540);
    }

    #[test]
    fn sign_jwt_produces_three_parts() {
        let key = EncodingKey::from_rsa_pem(FIXTURE_PEM.as_bytes()).unwrap();
        let claims = build_claims(t(1_700_000_000), 42);
        let token = sign_jwt(&claims, &key).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn build_mint_body_exact_bytes() {
        let bytes = build_mint_body(42);
        assert_eq!(
            bytes,
            br#"{"repository_ids":[42],"permissions":{"contents":"write","metadata":"read"}}"#
        );
    }

    #[test]
    fn parse_mint_response_ok() {
        let body = br#"{"token":"ghs_x","expires_at":"2026-05-31T13:00:00Z","extra":"ignored"}"#;
        let (tok, exp) = parse_mint_response(body).unwrap();
        assert_eq!(tok, "ghs_x");
        assert_eq!(exp, parse_rfc3339_z("2026-05-31T13:00:00Z").unwrap());
    }

    #[test]
    fn parse_mint_response_missing_token() {
        let body = br#"{"expires_at":"2026-05-31T13:00:00Z"}"#;
        let err = parse_mint_response(body).unwrap_err();
        assert!(matches!(
            err,
            GithubError::MissingField {
                context: "mint",
                field: "token"
            }
        ));
    }

    #[test]
    fn parse_mint_response_bad_json() {
        let body = b"not json at all";
        let err = parse_mint_response(body).unwrap_err();
        assert!(matches!(
            err,
            GithubError::JsonParse {
                context: "mint",
                ..
            }
        ));
    }

    #[test]
    fn parse_repo_response_ok() {
        let body = br#"{"id":12345,"name":"Hello-World"}"#;
        assert_eq!(parse_repo_response(body).unwrap(), 12345);
    }

    #[test]
    fn parse_repo_response_missing_id() {
        let body = br#"{"name":"Hello-World"}"#;
        let err = parse_repo_response(body).unwrap_err();
        assert!(matches!(
            err,
            GithubError::MissingField {
                context: "repo",
                field: "id"
            }
        ));
    }

    #[test]
    fn parse_rfc3339_known() {
        let exp = parse_rfc3339_z("2026-05-31T12:34:56Z").unwrap();
        let secs = exp.duration_since(UNIX_EPOCH).unwrap().as_secs();
        // 2026-05-31 12:34:56 UTC = 1780230896 (verified via `date -u`).
        assert_eq!(secs, 1_780_230_896);
    }

    #[test]
    fn parse_rfc3339_epoch() {
        assert_eq!(parse_rfc3339_z("1970-01-01T00:00:00Z").unwrap(), UNIX_EPOCH);
    }

    #[test]
    fn parse_rfc3339_rejects_offset() {
        assert!(parse_rfc3339_z("2026-05-31T12:34:56+01:00").is_err());
    }

    #[test]
    fn parse_rfc3339_rejects_subseconds() {
        assert!(parse_rfc3339_z("2026-05-31T12:34:56.123Z").is_err());
    }

    #[test]
    fn parse_rfc3339_rejects_invalid_month() {
        assert!(parse_rfc3339_z("2026-13-01T00:00:00Z").is_err());
    }

    #[test]
    fn parse_rfc3339_rejects_feb_30() {
        assert!(parse_rfc3339_z("2026-02-30T00:00:00Z").is_err());
    }

    #[test]
    fn parse_rfc3339_accepts_leap_day_in_leap_year() {
        assert!(parse_rfc3339_z("2024-02-29T00:00:00Z").is_ok());
    }

    #[test]
    fn parse_rfc3339_rejects_leap_day_in_non_leap_year() {
        assert!(parse_rfc3339_z("2023-02-29T00:00:00Z").is_err());
    }

    #[test]
    fn split_owner_repo_ok() {
        assert_eq!(
            split_owner_repo("octocat/Hello-World").unwrap(),
            ("octocat", "Hello-World")
        );
    }

    #[test]
    fn split_owner_repo_rejects_empty_half() {
        assert!(matches!(
            split_owner_repo("/foo").unwrap_err(),
            GithubError::MalformedPath(_)
        ));
        assert!(matches!(
            split_owner_repo("foo/").unwrap_err(),
            GithubError::MalformedPath(_)
        ));
    }

    #[test]
    fn split_owner_repo_rejects_extra_slash() {
        assert!(matches!(
            split_owner_repo("a/b/c").unwrap_err(),
            GithubError::MalformedPath(_)
        ));
    }

    #[test]
    fn split_owner_repo_rejects_non_ascii() {
        assert!(matches!(
            split_owner_repo("föö/bar").unwrap_err(),
            GithubError::MalformedPath(_)
        ));
    }

    #[test]
    fn api_base_trailing_slash_stripped() {
        let cfg = ProviderGithub {
            host: "github.com".to_string(),
            api_base: "https://api.github.com/".to_string(),
            app_id: 1,
            installation_id: 2,
            private_key_path: fixture_pem_path(),
        };
        let p = GitHubProvider::new(&cfg).unwrap();
        assert_eq!(p.api_base, "https://api.github.com");
    }

    fn fixture_pem_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test_app_key.pem")
    }

    #[test]
    fn cache_key_case_insensitive() {
        let cache = RepoIdCache::default();
        let now = t(1_000_000);
        cache.insert("foo/bar", 42, now + Duration::from_secs(600));
        assert_eq!(cache.lookup("foo/bar", now), Some(42));
    }

    #[test]
    fn cache_ttl_hit() {
        let cache = RepoIdCache::default();
        let now = t(1_000_000);
        cache.insert("foo/bar", 42, now + Duration::from_secs(600));
        assert_eq!(
            cache.lookup("foo/bar", now + Duration::from_secs(599)),
            Some(42)
        );
    }

    #[test]
    fn cache_ttl_miss() {
        let cache = RepoIdCache::default();
        let now = t(1_000_000);
        cache.insert("foo/bar", 42, now + Duration::from_secs(600));
        assert_eq!(
            cache.lookup("foo/bar", now + Duration::from_secs(601)),
            None
        );
    }

    #[test]
    fn cache_invalidate_removes_entry() {
        let cache = RepoIdCache::default();
        let now = t(1_000_000);
        cache.insert("foo/bar", 42, now + Duration::from_secs(600));
        cache.invalidate("foo/bar");
        assert_eq!(cache.lookup("foo/bar", now), None);
    }
}
