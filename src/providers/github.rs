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

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tracing::info;

use crate::providers::jwt_rs256::{self, JwtSigningKey};
use compio::runtime::CancelToken;
use cyper::redirect;
use futures_util::FutureExt;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;

// Encodes any byte outside GitHub's documented name character class
// ([A-Za-z0-9._-]). `split_owner_repo` already rejects such bytes;
// this encoding is defence-in-depth so a future char-class
// regression cannot become a URL-injection.
const REPO_PATH_SAFE: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_');

use crate::config::ProviderGithub;
use crate::cpu_worker::CpuWorker;
use crate::events::EventKind;
use crate::git_credential;

const GITHUB_API_VERSION: &str = "2022-11-28";
const ACCEPT_HEADER: &str = "application/vnd.github+json";
const CACHE_TTL: Duration = Duration::from_secs(600);
const JWT_LEEWAY_PAST: u64 = 60;
const JWT_LIFETIME: u64 = 540;

pub struct GitHubProvider {
    api_base: String,
    client_id: String,
    installation_id: u64,
    signer: JwtSigner,
    client: cyper::Client,
    user_agent: String,
    clock: fn() -> SystemTime,
    repo_ids: RepoIdCache,
    selfcheck_timeout: Duration,
    request_timeout: Duration,
    // Cloned from Service::shutdown so HTTPS calls observe shutdown
    // and return promptly with GithubError::Cancelled instead of
    // blocking the daemon drain.
    cancel: CancelToken,
}

#[derive(Default)]
struct RepoIdCache(RefCell<HashMap<String, CacheEntry>>);

enum CacheEntry {
    Done { id: u64, expires_at: SystemTime },
    // Single-flight: when one mint task is resolving a key, other
    // mint tasks for the same key store a clone of this Event and
    // await `listen()` instead of issuing a duplicate resolve. The
    // resolver `notify`s on completion (success or failure), and
    // waiters retry the lookup — Done(id) by then, or evicted on
    // failure. `event_listener::Event` (re-exported by synchrony)
    // is the multi-listener primitive needed here:
    // `synchrony::AsyncFlag::wait` consumes the flag and only
    // supports one waiter, which doesn't fit N concurrent mints
    // for the same uncached repo.
    InFlight(Rc<synchrony::sync::event::Event>),
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
        source: jwt_rs256::JwtError,
    },
    #[error("failed to sign JWT")]
    JwtSign(#[source] jwt_rs256::JwtError),
    #[error("failed to spawn JWT signer thread")]
    SignerSpawn(#[source] std::io::Error),
    #[error("JWT signer thread is no longer running")]
    JwtSignerDead,
    #[error("HTTP transport error")]
    Http(#[source] cyper::Error),
    // `source` deliberately omitted. serde_json::Error's Display can
    // include a fragment of the input ("expected … at line X column Y
    // near {bytes}"); for the mint response, that fragment can be
    // the access token. The context string is enough for triage; the
    // raw error never reaches a log line.
    #[error("malformed response from {context}")]
    JsonParse { context: &'static str },
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
    #[error("Client ID mismatch: configured {configured}, GitHub reports {reported}")]
    ClientIdMismatch {
        configured: String,
        reported: String,
    },
    #[error("provider request timed out after {0:?}")]
    Timeout(Duration),
    #[error("provider request cancelled (daemon shutting down)")]
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct SelfcheckOutcome {
    pub(crate) client_id: String,
    pub(crate) installation_id: u64,
    pub(crate) api_base: String,
    pub(crate) clock_skew_sec: i64,
    /// ULID of the outbound HTTPS call. Pairs with the
    /// `provider_call` / `provider_call_done` breadcrumbs.
    pub(crate) out_req_id: String,
    /// `X-GitHub-Request-Id` returned by the API, if any.
    pub(crate) gh_req_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MintOutcome {
    pub response: git_credential::Response,
    pub repo_id: u64,
    /// ULID of the outbound `mint_token` HTTPS call. Pairs with
    /// the `provider_call` / `provider_call_done` breadcrumbs.
    pub out_req_id: String,
    /// `X-GitHub-Request-Id` returned by the mint endpoint, if any.
    pub gh_req_id: Option<String>,
}

impl From<cyper::Error> for GithubError {
    fn from(e: cyper::Error) -> Self {
        GithubError::Http(e)
    }
}

impl GitHubProvider {
    /// Load the App private key from disk and parse it into a
    /// `JwtSigningKey`. Must run BEFORE the sandbox closes
    /// filesystem access; the resulting `Arc` is then handed to
    /// [`new`] post-sandbox along with the shared CpuWorker.
    pub async fn load_key(cfg: &ProviderGithub) -> Result<Arc<JwtSigningKey>, GithubError> {
        let pem_bytes = compio::fs::read(&cfg.private_key_path)
            .await
            .map_err(|source| GithubError::PemRead {
                path: cfg.private_key_path.clone(),
                source,
            })?;
        let key = JwtSigningKey::from_pem(&pem_bytes).map_err(|source| GithubError::PemParse {
            path: cfg.private_key_path.clone(),
            source,
        })?;
        Ok(Arc::new(key))
    }

    pub fn new(
        cfg: &ProviderGithub,
        key: Arc<JwtSigningKey>,
        cpu_worker: Rc<CpuWorker>,
        cancel: CancelToken,
    ) -> Result<Self, GithubError> {
        Self::with_overrides(cfg, key, cpu_worker, cancel, None, SystemTime::now)
    }

    #[doc(hidden)]
    pub fn with_overrides(
        cfg: &ProviderGithub,
        key: Arc<JwtSigningKey>,
        cpu_worker: Rc<CpuWorker>,
        cancel: CancelToken,
        api_base_override: Option<String>,
        clock: fn() -> SystemTime,
    ) -> Result<Self, GithubError> {
        let api_base = api_base_override
            .unwrap_or_else(|| cfg.api_base.clone())
            .trim_end_matches('/')
            .to_string();

        // Same-origin redirect policy: HTTPS to api.github.com may
        // redirect within api.github.com, never elsewhere. Off-host
        // redirects would carry the App JWT off-domain.
        let api_host = Url::parse(&api_base)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .ok_or_else(|| GithubError::MalformedPath(format!("api_base={api_base}")))?;
        let policy = redirect::Policy::custom(move |attempt| {
            if attempt.url().host_str() == Some(&api_host) {
                attempt.follow()
            } else {
                attempt.stop()
            }
        });
        let client = cyper::Client::builder().redirect(policy).build()?;

        let signer = JwtSigner {
            worker: cpu_worker,
            key,
        };
        Ok(Self {
            api_base,
            client_id: cfg.client_id.clone(),
            installation_id: cfg.installation_id,
            signer,
            client,
            user_agent: cfg.user_agent.clone(),
            clock,
            repo_ids: RepoIdCache::default(),
            selfcheck_timeout: cfg.selfcheck_timeout,
            request_timeout: cfg.request_timeout,
            cancel,
        })
    }

    /// Wrap one outbound HTTPS call: emits the `provider_call`
    /// breadcrumb before, races shutdown + timeout around the
    /// inner future, then emits `provider_call_done` with status +
    /// `gh_req_id` + elapsed_ms.
    ///
    /// Returns the inner `T` together with the outbound `out_req_id`
    /// (the ULID we minted for this call) and the response's
    /// `X-GitHub-Request-Id` if present. On timeout/cancel/
    /// transport-error a `provider_call_done` is still emitted
    /// with `status = 0`.
    async fn with_breadcrumbs<T, F, Fut>(
        &self,
        req_id: &str,
        endpoint: &'static str,
        timeout: Duration,
        mk_inner: F,
    ) -> Result<(T, String, Option<String>), GithubError>
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = ProviderCall<T>>,
    {
        let out_req_id = ulid::Ulid::new().to_string();
        info!(
            evt = %EventKind::ProviderCall,
            req_id = %req_id,
            out_req_id = %out_req_id,
            endpoint = endpoint,
            provider = %self.api_base,
            timeout_ms = timeout.as_millis() as u64,
        );
        let started = Instant::now();
        let raced: Result<ProviderCall<T>, GithubError> = futures_util::select_biased! {
            _ = self.cancel.clone().wait().fuse() => Err(GithubError::Cancelled),
            r = compio::time::timeout(timeout, mk_inner(out_req_id.clone())).fuse() => match r {
                Ok(pc) => Ok(pc),
                Err(_elapsed) => Err(GithubError::Timeout(timeout)),
            }
        };
        let elapsed_ms = started.elapsed().as_millis() as u64;
        match raced {
            Ok(pc) => {
                info!(
                    evt = %EventKind::ProviderCallDone,
                    req_id = %req_id,
                    out_req_id = %out_req_id,
                    status = pc.status,
                    gh_req_id = pc.gh_req_id.as_deref().unwrap_or(""),
                    elapsed_ms = elapsed_ms,
                );
                match pc.result {
                    Ok(v) => Ok((v, out_req_id, pc.gh_req_id)),
                    Err(e) => Err(e),
                }
            }
            Err(e) => {
                info!(
                    evt = %EventKind::ProviderCallDone,
                    req_id = %req_id,
                    out_req_id = %out_req_id,
                    status = 0,
                    gh_req_id = "",
                    elapsed_ms = elapsed_ms,
                    error = %e,
                );
                Err(e)
            }
        }
    }

    /// Verify the App private key signs a valid JWT and the App is
    /// reachable at `api_base`. The reported App ID must match the
    /// configured one — a mismatch indicates a wrong key/App pairing.
    pub async fn selfcheck(&self, req_id: &str) -> Result<SelfcheckOutcome, GithubError> {
        let (mut outcome, out_req_id, gh_req_id) = self
            .with_breadcrumbs(req_id, "selfcheck", self.selfcheck_timeout, |out| {
                self.selfcheck_inner(out)
            })
            .await?;
        outcome.out_req_id = out_req_id;
        outcome.gh_req_id = gh_req_id;
        Ok(outcome)
    }

    async fn selfcheck_inner(&self, out_req_id: String) -> ProviderCall<SelfcheckOutcome> {
        let jwt = match self.sign_jwt_now().await {
            Ok(j) => j,
            Err(e) => {
                return ProviderCall {
                    status: 0,
                    gh_req_id: None,
                    result: Err(e),
                };
            }
        };
        let url = format!("{}/app", self.api_base);
        let req = match self
            .client
            .get(&url)
            .and_then(|r| r.bearer_auth(&jwt))
            .and_then(|r| r.header("Accept", ACCEPT_HEADER))
            .and_then(|r| r.header("X-GitHub-Api-Version", GITHUB_API_VERSION))
            .and_then(|r| r.header("User-Agent", &self.user_agent))
            .and_then(|r| r.header(X_REQUEST_ID_HEADER, &out_req_id))
            .and_then(|r| {
                r.header(
                    REQUEST_TIMEOUT_HEADER,
                    &self.selfcheck_timeout.as_secs().to_string(),
                )
            }) {
            Ok(r) => r,
            Err(e) => {
                return ProviderCall {
                    status: 0,
                    gh_req_id: None,
                    result: Err(GithubError::from(e)),
                };
            }
        };
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                return ProviderCall {
                    status: 0,
                    gh_req_id: None,
                    result: Err(GithubError::from(e)),
                };
            }
        };
        let status = resp.status().as_u16();
        let gh_req_id = read_gh_req_id(&resp);
        match status {
            200 => {}
            401 => {
                return ProviderCall {
                    status,
                    gh_req_id,
                    result: Err(GithubError::Unauthorized),
                };
            }
            403 => {
                return ProviderCall {
                    status,
                    gh_req_id,
                    result: Err(GithubError::Forbidden),
                };
            }
            500..=599 => {
                return ProviderCall {
                    status,
                    gh_req_id,
                    result: Err(GithubError::ServerError(status)),
                };
            }
            other => {
                return ProviderCall {
                    status,
                    gh_req_id,
                    result: Err(GithubError::UnexpectedStatus(other)),
                };
            }
        }
        // HTTP `Date` header (IMF-fixdate per RFC 7231 § 7.1.1.1) is
        // accepted by `time`'s Rfc2822 parser (`GMT` → zero offset).
        // Silently 0 if the header is missing or unparseable; clock
        // skew is informational, not a hard failure.
        let clock_skew_sec = resp
            .headers()
            .get("date")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| {
                OffsetDateTime::parse(s, &time::format_description::well_known::Rfc2822).ok()
            })
            .map(|server_t| server_t.unix_timestamp() - OffsetDateTime::now_utc().unix_timestamp())
            .unwrap_or(0);
        let body = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                return ProviderCall {
                    status,
                    gh_req_id,
                    result: Err(GithubError::from(e)),
                };
            }
        };
        let parsed: Result<SelfcheckOutcome, GithubError> = (|| {
            let v: serde_json::Value =
                serde_json::from_slice(&body).map_err(|_| GithubError::JsonParse {
                    context: "selfcheck",
                })?;
            let reported =
                v.get("client_id")
                    .and_then(|i| i.as_str())
                    .ok_or(GithubError::MissingField {
                        context: "selfcheck",
                        field: "client_id",
                    })?;
            if reported != self.client_id {
                return Err(GithubError::ClientIdMismatch {
                    configured: self.client_id.clone(),
                    reported: reported.to_string(),
                });
            }
            Ok(SelfcheckOutcome {
                client_id: self.client_id.clone(),
                installation_id: self.installation_id,
                api_base: self.api_base.clone(),
                clock_skew_sec,
                out_req_id: String::new(),
                gh_req_id: None,
            })
        })();
        ProviderCall {
            status,
            gh_req_id,
            result: parsed,
        }
    }

    pub async fn mint(&self, req_id: &str, path: &str) -> Result<MintOutcome, GithubError> {
        let (owner, repo) = split_owner_repo(path)?;
        let key = format!(
            "{}/{}",
            owner.to_ascii_lowercase(),
            repo.to_ascii_lowercase()
        );
        let now = (self.clock)();

        let repo_id = self
            .resolve_with_singleflight(req_id, &key, owner, repo, now)
            .await?;

        match self.mint_token(req_id, repo_id, path).await {
            Ok((token, expires_at, out_req_id, gh_req_id)) => Ok(MintOutcome {
                response: git_credential::Response {
                    username: "x-access-token".to_string(),
                    password: token,
                    password_expiry_utc: expires_at,
                },
                repo_id,
                out_req_id,
                gh_req_id,
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

    /// Single-flight wrapper around `resolve_repo_id`. Concurrent
    /// mints for the same key share a single in-flight resolve; once
    /// it completes, all waiters retry the cache lookup.
    async fn resolve_with_singleflight(
        &self,
        req_id: &str,
        key: &str,
        owner: &str,
        repo: &str,
        now: SystemTime,
    ) -> Result<u64, GithubError> {
        loop {
            match self.repo_ids.get_or_claim(key, now) {
                CacheAction::Hit(id) => return Ok(id),
                CacheAction::Wait(ev) => {
                    ev.listen().await;
                    // Loop to re-check; the resolver may have
                    // landed a Done entry, evicted on failure, or
                    // raced ahead leaving Done expired.
                }
                CacheAction::Resolve(ev) => {
                    // RAII: if the resolve future is dropped (shutdown,
                    // caller cancel), the guard invalidates the
                    // InFlight entry and wakes any waiters so they
                    // retry rather than block forever on a notify
                    // that will never come.
                    let mut guard = InFlightGuard::new(&self.repo_ids, key, ev);
                    let result = self.resolve_repo_id(req_id, owner, repo).await;
                    match &result {
                        Ok(id) => self.repo_ids.put_done(key, *id, now + CACHE_TTL),
                        Err(_) => self.repo_ids.invalidate(key),
                    }
                    guard.disarm_and_notify();
                    return result;
                }
            }
        }
    }

    async fn resolve_repo_id(
        &self,
        req_id: &str,
        owner: &str,
        repo: &str,
    ) -> Result<u64, GithubError> {
        let (id, _out, _gh) = self
            .with_breadcrumbs(req_id, "resolve_repo_id", self.request_timeout, |out| {
                self.resolve_repo_id_inner(out, owner, repo)
            })
            .await?;
        Ok(id)
    }

    async fn resolve_repo_id_inner(
        &self,
        out_req_id: String,
        owner: &str,
        repo: &str,
    ) -> ProviderCall<u64> {
        let jwt = match self.sign_jwt_now().await {
            Ok(j) => j,
            Err(e) => {
                return ProviderCall {
                    status: 0,
                    gh_req_id: None,
                    result: Err(e),
                };
            }
        };
        let url = format!(
            "{}/repos/{}/{}",
            self.api_base,
            utf8_percent_encode(owner, REPO_PATH_SAFE),
            utf8_percent_encode(repo, REPO_PATH_SAFE),
        );
        let req = match self
            .client
            .get(&url)
            .and_then(|r| r.bearer_auth(&jwt))
            .and_then(|r| r.header("Accept", ACCEPT_HEADER))
            .and_then(|r| r.header("X-GitHub-Api-Version", GITHUB_API_VERSION))
            .and_then(|r| r.header("User-Agent", &self.user_agent))
            .and_then(|r| r.header(X_REQUEST_ID_HEADER, &out_req_id))
            .and_then(|r| {
                r.header(
                    REQUEST_TIMEOUT_HEADER,
                    &self.request_timeout.as_secs().to_string(),
                )
            }) {
            Ok(r) => r,
            Err(e) => {
                return ProviderCall {
                    status: 0,
                    gh_req_id: None,
                    result: Err(GithubError::from(e)),
                };
            }
        };
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                return ProviderCall {
                    status: 0,
                    gh_req_id: None,
                    result: Err(GithubError::from(e)),
                };
            }
        };
        let status = resp.status().as_u16();
        let gh_req_id = read_gh_req_id(&resp);
        let err: Option<GithubError> = match status {
            200 => None,
            401 => Some(GithubError::Unauthorized),
            403 => Some(GithubError::Forbidden),
            404 => Some(GithubError::RepoNotFound {
                path: format!("{owner}/{repo}"),
            }),
            429 => Some(GithubError::RateLimited),
            500..=599 => Some(GithubError::ServerError(status)),
            _ => Some(GithubError::UnexpectedStatus(status)),
        };
        if let Some(e) = err {
            return ProviderCall {
                status,
                gh_req_id,
                result: Err(e),
            };
        }
        let body = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                return ProviderCall {
                    status,
                    gh_req_id,
                    result: Err(GithubError::from(e)),
                };
            }
        };
        ProviderCall {
            status,
            gh_req_id,
            result: parse_repo_response(&body),
        }
    }

    async fn mint_token(
        &self,
        req_id: &str,
        repo_id: u64,
        path: &str,
    ) -> Result<(String, SystemTime, String, Option<String>), GithubError> {
        let ((token, expires_at), out_req_id, gh_req_id) = self
            .with_breadcrumbs(req_id, "mint_token", self.request_timeout, |out| {
                self.mint_token_inner(out, repo_id, path)
            })
            .await?;
        Ok((token, expires_at, out_req_id, gh_req_id))
    }

    async fn mint_token_inner(
        &self,
        out_req_id: String,
        repo_id: u64,
        path: &str,
    ) -> ProviderCall<(String, SystemTime)> {
        let jwt = match self.sign_jwt_now().await {
            Ok(j) => j,
            Err(e) => {
                return ProviderCall {
                    status: 0,
                    gh_req_id: None,
                    result: Err(e),
                };
            }
        };
        let url = format!(
            "{}/app/installations/{}/access_tokens",
            self.api_base, self.installation_id
        );
        let body = build_mint_body(repo_id);
        let req = match self
            .client
            .post(&url)
            .and_then(|r| r.bearer_auth(&jwt))
            .and_then(|r| r.header("Accept", ACCEPT_HEADER))
            .and_then(|r| r.header("X-GitHub-Api-Version", GITHUB_API_VERSION))
            .and_then(|r| r.header("User-Agent", &self.user_agent))
            .and_then(|r| r.header("Content-Type", "application/json"))
            .and_then(|r| r.header(X_REQUEST_ID_HEADER, &out_req_id))
            .and_then(|r| {
                r.header(
                    REQUEST_TIMEOUT_HEADER,
                    &self.request_timeout.as_secs().to_string(),
                )
            }) {
            Ok(r) => r.body(body),
            Err(e) => {
                return ProviderCall {
                    status: 0,
                    gh_req_id: None,
                    result: Err(GithubError::from(e)),
                };
            }
        };
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                return ProviderCall {
                    status: 0,
                    gh_req_id: None,
                    result: Err(GithubError::from(e)),
                };
            }
        };
        let status = resp.status().as_u16();
        let gh_req_id = read_gh_req_id(&resp);
        let err: Option<GithubError> = match status {
            201 => None,
            401 => Some(GithubError::Unauthorized),
            403 => Some(GithubError::Forbidden),
            404 => Some(GithubError::RepoNotFound {
                path: path.to_string(),
            }),
            429 => Some(GithubError::RateLimited),
            500..=599 => Some(GithubError::ServerError(status)),
            _ => Some(GithubError::UnexpectedStatus(status)),
        };
        if let Some(e) = err {
            return ProviderCall {
                status,
                gh_req_id,
                result: Err(e),
            };
        }
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                return ProviderCall {
                    status,
                    gh_req_id,
                    result: Err(GithubError::from(e)),
                };
            }
        };
        ProviderCall {
            status,
            gh_req_id,
            result: parse_mint_response(&bytes),
        }
    }

    async fn sign_jwt_now(&self) -> Result<String, GithubError> {
        let claims = build_claims((self.clock)(), &self.client_id);
        self.signer.sign(claims).await
    }
}

enum CacheAction {
    Hit(u64),
    Wait(Rc<synchrony::sync::event::Event>),
    Resolve(Rc<synchrony::sync::event::Event>),
}

/// One outbound HTTPS call's bookkeeping: the parsed result, the
/// response's HTTP status, and the `X-GitHub-Request-Id` header
/// (if any). Even on error we still want status + gh_req_id for
/// the `provider_call_done` log line, which is why this isn't a
/// plain `Result`.
struct ProviderCall<T> {
    status: u16,
    gh_req_id: Option<String>,
    result: Result<T, GithubError>,
}

const REQUEST_TIMEOUT_HEADER: &str = "Request-Timeout";
const X_REQUEST_ID_HEADER: &str = "X-Request-ID";
const GH_REQUEST_ID_HEADER: &str = "x-github-request-id";

fn read_gh_req_id(resp: &cyper::Response) -> Option<String> {
    resp.headers()
        .get(GH_REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

/// Holds the InFlight claim for the resolver task. On `Drop` (i.e.
/// the resolver future was cancelled mid-flight) the guard
/// invalidates the cache entry and notifies waiters so they retry
/// the lookup. The resolver disarms the guard via
/// `disarm_and_notify` once it has explicitly committed put_done or
/// invalidate.
struct InFlightGuard<'a> {
    cache: &'a RepoIdCache,
    key: String,
    event: Rc<synchrony::sync::event::Event>,
    armed: bool,
}

impl<'a> InFlightGuard<'a> {
    fn new(cache: &'a RepoIdCache, key: &str, event: Rc<synchrony::sync::event::Event>) -> Self {
        Self {
            cache,
            key: key.to_string(),
            event,
            armed: true,
        }
    }

    fn disarm_and_notify(&mut self) {
        self.armed = false;
        self.event.notify(usize::MAX);
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.cache.invalidate(&self.key);
            self.event.notify(usize::MAX);
        }
    }
}

impl RepoIdCache {
    /// Atomic test-and-set. Returns Hit on fresh Done entry, Wait
    /// when another task is already resolving (with that resolver's
    /// completion event), or Resolve when this caller should
    /// perform the resolve (with a fresh event the caller will
    /// notify on completion).
    fn get_or_claim(&self, key: &str, now: SystemTime) -> CacheAction {
        let mut cache = self.0.borrow_mut();
        match cache.get(key) {
            Some(CacheEntry::Done { id, expires_at }) if *expires_at > now => CacheAction::Hit(*id),
            Some(CacheEntry::InFlight(ev)) => CacheAction::Wait(ev.clone()),
            _ => {
                let ev = Rc::new(synchrony::sync::event::Event::new());
                cache.insert(key.to_string(), CacheEntry::InFlight(ev.clone()));
                CacheAction::Resolve(ev)
            }
        }
    }

    fn put_done(&self, key: &str, id: u64, expires_at: SystemTime) {
        self.0
            .borrow_mut()
            .insert(key.to_string(), CacheEntry::Done { id, expires_at });
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

fn build_claims(now: SystemTime, client_id: &str) -> JwtClaims {
    let unix = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    JwtClaims {
        iss: client_id.to_string(),
        iat: unix.saturating_sub(JWT_LEEWAY_PAST),
        exp: unix.saturating_add(JWT_LIFETIME),
    }
}

/// Synchronous JWT signing. RSA-2048 with the App's private key —
/// ~1-2 ms per call on commodity hardware. NEVER call from the
/// compio runtime thread directly; the `JwtSigner` worker thread
/// is the only caller (plus a unit test).
fn sign_jwt_blocking(claims: &JwtClaims, key: &JwtSigningKey) -> Result<String, GithubError> {
    key.sign_rs256(claims).map_err(GithubError::JwtSign)
}

/// Holds a shared [`CpuWorker`] handle and the App's
/// `JwtSigningKey`, dispatching `sign_jwt_blocking` jobs to the
/// worker thread. The worker is shared across all providers in
/// the daemon and spawned once at Service init, after the sandbox
/// is in place.
struct JwtSigner {
    worker: Rc<CpuWorker>,
    // Arc so each sign call clones a handle into the closure shipped
    // to the worker thread without copying the key bytes.
    key: Arc<JwtSigningKey>,
}

impl JwtSigner {
    async fn sign(&self, claims: JwtClaims) -> Result<String, GithubError> {
        let key = Arc::clone(&self.key);
        match self
            .worker
            .run(move || sign_jwt_blocking(&claims, &key))
            .await
        {
            Ok(res) => res,
            Err(crate::cpu_worker::WorkerDead) => Err(GithubError::JwtSignerDead),
        }
    }
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
        serde_json::from_slice(bytes).map_err(|_| GithubError::JsonParse { context: "mint" })?;
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
    let expires_at = parse_rfc3339_to_systemtime(expires_at_str)?;
    Ok((token, expires_at))
}

fn parse_repo_response(bytes: &[u8]) -> Result<u64, GithubError> {
    let v: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| GithubError::JsonParse { context: "repo" })?;
    v.get("id")
        .and_then(|i| i.as_u64())
        .ok_or(GithubError::MissingField {
            context: "repo",
            field: "id",
        })
}

// GitHub's documented character set for owner/repo names:
// alphanumerics, dash, underscore, dot. Any other byte (slash beyond
// the single separator, `?`, `#`, `%`, NUL, control bytes, non-ASCII)
// is rejected before the value reaches a URL `format!`.
fn is_valid_owner_or_repo_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
}

fn split_owner_repo(path: &str) -> Result<(&str, &str), GithubError> {
    let mut parts = path.splitn(2, '/');
    let owner = parts.next().unwrap_or("");
    let repo = parts.next().unwrap_or("");
    if owner.is_empty() || repo.is_empty() {
        return Err(GithubError::MalformedPath(path.to_string()));
    }
    if !owner.bytes().all(is_valid_owner_or_repo_byte)
        || !repo.bytes().all(is_valid_owner_or_repo_byte)
    {
        return Err(GithubError::MalformedPath(path.to_string()));
    }
    Ok((owner, repo))
}

fn parse_rfc3339_to_systemtime(s: &str) -> Result<SystemTime, GithubError> {
    let dt =
        OffsetDateTime::parse(s, &Rfc3339).map_err(|_| GithubError::BadExpiresAt(s.to_string()))?;
    let secs = dt.unix_timestamp();
    // SystemTime + Duration::from_secs takes u64; a negative
    // unix-timestamp (pre-1970) would underflow on the cast below.
    if secs < 0 {
        return Err(GithubError::BadExpiresAt(s.to_string()));
    }
    Ok(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_date_rfc2822_parses_imf_fixdate() {
        // RFC 7231 § 7.1.1.1 example.
        let dt = OffsetDateTime::parse(
            "Sun, 06 Nov 1994 08:49:37 GMT",
            &time::format_description::well_known::Rfc2822,
        )
        .unwrap();
        assert_eq!(dt.unix_timestamp(), 784_111_777);
    }

    const FIXTURE_PEM: &str = include_str!("../../tests/fixtures/test_app_key.pem");

    fn t(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn build_claims_at_fixed_time() {
        let claims = build_claims(t(1_700_000_000), "Iv1.test42");
        assert_eq!(claims.iss, "Iv1.test42");
        assert_eq!(claims.iat, 1_700_000_000 - 60);
        assert_eq!(claims.exp, 1_700_000_000 + 540);
    }

    #[test]
    fn sign_jwt_produces_three_parts() {
        let key = JwtSigningKey::from_pem(FIXTURE_PEM.as_bytes()).unwrap();
        let claims = build_claims(t(1_700_000_000), "Iv1.test42");
        let token = sign_jwt_blocking(&claims, &key).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    /// Pin byte-equivalence with jsonwebtoken's prior output for
    /// the same (claims, key). The post-swap implementation lives
    /// in `crate::providers::jwt_rs256` and has its own copy of
    /// this assertion; this one belongs to the github.rs path so
    /// `sign_jwt_blocking` itself is exercised.
    #[test]
    fn sign_jwt_blocking_matches_jsonwebtoken_baseline() {
        let key = JwtSigningKey::from_pem(FIXTURE_PEM.as_bytes()).unwrap();
        let claims = build_claims(t(1_700_000_000), "Iv1.test42");
        let token = sign_jwt_blocking(&claims, &key).unwrap();
        assert_eq!(
            token,
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJJdjEudGVzdDQyIiwiaWF0IjoxNjk5OTk5OTQwLCJleHAiOjE3MDAwMDA1NDB9.yPTDonwO4souVu_3nk7Aq8ZbiAq3PBVLHRJ5J6B67JHmUxVh-yvIoXdQ8O_EAqj-H57GKRAo_b0nu6hQT_keD9-wB_ah8DC_ZqtV42S3jHACWAdEG066W1XdKUftU82QkdSM5hrpdg9OvFN6i7m0ObCJi3uJMWXYb8lY1LYJew0SWajBzLKQjw47Qmbq-AYiTgkdBoRfK5TrD64u6wd0aQCathxELkaiEacilUtU6ZH8jOQ_W5hYjjwxjTF7wbNWdx-v7M3yUSUn_01Sn9w2bTLeimsP4e81ydchLhIeJED4iF-j-QG_uBlhp0auwTPYqPaG6Zh-qhbkE0DJaV-log",
        );
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
        // 2026-05-31T13:00:00Z = 1780232400.
        let secs = exp.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 1_780_232_400);
    }

    #[test]
    fn parse_mint_response_bad_expires_at() {
        let body = br#"{"token":"ghs_x","expires_at":"not-a-date"}"#;
        let err = parse_mint_response(body).unwrap_err();
        assert!(matches!(err, GithubError::BadExpiresAt(_)));
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

    // Defence against accidental log leaks. The mint response body
    // contains the access token; any error variant constructed from
    // it must NOT carry response bytes that could surface via
    // `tracing::warn!(error = %err)` or `error = ?err`. Drop tests
    // here for every JSON-parse / token-adjacent error path.
    #[test]
    fn json_parse_error_does_not_leak_response_bytes() {
        let token_like = "ghs_secretSECRETsecret1234567890";
        let body = format!(r#"{{"token":"{token_like}", broken json"#).into_bytes();
        let err = parse_mint_response(&body).unwrap_err();
        let display = format!("{err}");
        let debug = format!("{err:?}");
        assert!(
            !display.contains(token_like),
            "Display leaks token: {display}"
        );
        assert!(!debug.contains(token_like), "Debug leaks token: {debug}");
        // Walk the error chain too (some logging frameworks chase
        // source()).
        use std::error::Error;
        let mut cur: Option<&dyn Error> = Some(&err);
        while let Some(e) = cur {
            let s = format!("{e}");
            assert!(!s.contains(token_like), "chain leaks token: {s}");
            cur = e.source();
        }
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

    #[compio::test]
    async fn api_base_trailing_slash_stripped() {
        let cfg = ProviderGithub {
            host: "github.com".to_string(),
            api_base: "https://api.github.com/".to_string(),
            client_id: "Iv1.test1".to_string(),
            installation_id: 2,
            private_key_path: fixture_pem_path(),
            selfcheck_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            user_agent: "symbolon".to_string(),
        };
        let key = GitHubProvider::load_key(&cfg).await.unwrap();
        let worker = Rc::new(CpuWorker::new("symbolon-test-jwt").unwrap());
        let cancel = compio::runtime::CancelToken::new();
        let p = GitHubProvider::new(&cfg, key, worker, cancel).unwrap();
        assert_eq!(p.api_base, "https://api.github.com");
    }

    fn fixture_pem_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test_app_key.pem")
    }

    fn assert_hit(action: CacheAction, expected: u64) {
        match action {
            CacheAction::Hit(id) => assert_eq!(id, expected),
            CacheAction::Wait(_) => panic!("expected Hit, got Wait"),
            CacheAction::Resolve(_) => panic!("expected Hit, got Resolve"),
        }
    }

    fn assert_resolve(action: CacheAction) {
        match action {
            CacheAction::Resolve(_) => {}
            CacheAction::Hit(_) => panic!("expected Resolve, got Hit"),
            CacheAction::Wait(_) => panic!("expected Resolve, got Wait"),
        }
    }

    #[test]
    fn cache_done_hit_within_ttl() {
        let cache = RepoIdCache::default();
        let now = t(1_000_000);
        cache.put_done("foo/bar", 42, now + Duration::from_secs(600));
        assert_hit(cache.get_or_claim("foo/bar", now), 42);
        assert_hit(
            cache.get_or_claim("foo/bar", now + Duration::from_secs(599)),
            42,
        );
    }

    #[test]
    fn cache_done_miss_when_expired() {
        let cache = RepoIdCache::default();
        let now = t(1_000_000);
        cache.put_done("foo/bar", 42, now + Duration::from_secs(600));
        // Expired entry yields Resolve (the new caller takes
        // ownership of refreshing it).
        assert_resolve(cache.get_or_claim("foo/bar", now + Duration::from_secs(601)));
    }

    #[test]
    fn cache_invalidate_removes_entry() {
        let cache = RepoIdCache::default();
        let now = t(1_000_000);
        cache.put_done("foo/bar", 42, now + Duration::from_secs(600));
        cache.invalidate("foo/bar");
        assert_resolve(cache.get_or_claim("foo/bar", now));
    }

    #[test]
    fn cache_singleflight_second_caller_waits() {
        let cache = RepoIdCache::default();
        let now = t(1_000_000);
        // First caller claims an in-flight slot.
        assert_resolve(cache.get_or_claim("foo/bar", now));
        // Second caller for same key gets a Wait, sharing the
        // first caller's event. Don't call notify (the test only
        // verifies the state-machine transition).
        match cache.get_or_claim("foo/bar", now) {
            CacheAction::Wait(_) => {}
            CacheAction::Hit(_) => panic!("expected Wait, got Hit"),
            CacheAction::Resolve(_) => panic!("expected Wait, got Resolve"),
        }
    }

    #[test]
    fn inflight_guard_drop_invalidates_and_notifies() {
        let cache = RepoIdCache::default();
        let now = t(1_000_000);
        let ev = match cache.get_or_claim("foo/bar", now) {
            CacheAction::Resolve(ev) => ev,
            _ => panic!("expected initial Resolve"),
        };
        // Simulate the resolver future being dropped mid-flight: the
        // guard goes out of scope without being disarmed.
        {
            let _guard = InFlightGuard::new(&cache, "foo/bar", ev);
        }
        // Cache must be empty and a new caller must get Resolve.
        assert_resolve(cache.get_or_claim("foo/bar", now));
    }

    #[test]
    fn inflight_guard_disarm_does_not_invalidate() {
        let cache = RepoIdCache::default();
        let now = t(1_000_000);
        let ev = match cache.get_or_claim("foo/bar", now) {
            CacheAction::Resolve(ev) => ev,
            _ => panic!("expected initial Resolve"),
        };
        {
            let mut guard = InFlightGuard::new(&cache, "foo/bar", ev);
            // Resolver committed put_done; then disarm.
            cache.put_done("foo/bar", 42, now + Duration::from_secs(600));
            guard.disarm_and_notify();
        }
        // Cache must show the committed entry; subsequent callers Hit.
        assert_hit(cache.get_or_claim("foo/bar", now), 42);
    }
}
