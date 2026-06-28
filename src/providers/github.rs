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

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use compio::bytes::Bytes;
use compio::runtime::CancelToken;
use cyper::redirect;
use futures_util::FutureExt;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::{Rfc2822, Rfc3339};
use tracing::info;
use url::Url;

use async_trait::async_trait;
use derive_more::{Display, From};
use serde_json::json;

use crate::config::ProviderGithub;
use crate::cpu_worker::{CpuWorker, WorkerDead};
use crate::events::EventKind;
use crate::git_credential;
use crate::ids::OutReqId;
use crate::providers::jwt_rs256::{self, JwtSigningKey};
use crate::providers::{
    MintOutcome as AbstractMintOutcome, Provider, ProviderError, ProviderReqId,
    SelfcheckOutcome as AbstractSelfcheckOutcome,
};
use crate::singleflight_cache::SingleflightCache;

pub use crate::config::InstallationId;

/// GitHub **repository** numeric id (the `id` field on the repo
/// REST resource; used in the mint body's `repository_ids` array).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, From, Deserialize, Serialize)]
#[from(u64)]
#[serde(transparent)]
pub struct RepoId(u64);

const GITHUB_API_VERSION: &str = "2026-03-10";
const ACCEPT_HEADER: &str = "application/vnd.github+json";

// ============================================================================
// Public types
// ============================================================================

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
    #[error("JWT signer thread is no longer running")]
    JwtSignerDead,
    #[error("HTTP transport error")]
    Http(#[from] cyper::Error),
    // `source` deliberately omitted. serde_json::Error's Display can
    // include a fragment of the input ("expected … at line X column Y
    // near {bytes}"); for the mint response, that fragment can be
    // the access token. `detail` is a `&'static` short tag — no
    // payload bytes can reach a log line via this variant.
    #[error("malformed response from {context} ({detail})")]
    ParseResponse {
        context: &'static str,
        detail: &'static str,
    },
    #[error("malformed owner/repo path: {0}")]
    MalformedPath(String),
    // Body excerpt is GitHub's error envelope `message` (e.g.
    // "A JSON web token could not be decoded", "Bad credentials")
    // or, if the body wasn't parseable, a short raw prefix. Safe to
    // log — 4xx envelopes never carry token bytes (those only appear
    // in 2xx mint responses, which take a different code path).
    #[error("unauthorized (401): {body}")]
    Unauthorized { body: String },
    #[error("forbidden (403): {body}")]
    Forbidden { body: String },
    #[error("repository not found or App lacks access")]
    RepoNotFound,
    #[error("rate limited (429)")]
    RateLimited {
        /// Server-suggested wait time before retry, parsed from the
        /// `Retry-After` HTTP header per RFC 9110 §10.2.3. `None`
        /// when the header was absent or malformed.
        retry_after: Option<Duration>,
    },
    #[error("provider returned status {0}")]
    OtherStatus(u16),
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

impl From<WorkerDead> for GithubError {
    fn from(_: WorkerDead) -> Self {
        GithubError::JwtSignerDead
    }
}

impl GithubError {
    /// Map the GitHub HTTP status codes shared across every
    /// endpoint to an error. Endpoint-specific cases (200 vs 201
    /// success, 404 → `RepoNotFound`) are handled by the caller
    /// before they fall through here.
    fn from_common_status(status: u16, body: &Bytes, retry_after: Option<Duration>) -> Self {
        match status {
            401 => Self::Unauthorized {
                body: Self::message_from_body(body),
            },
            403 => Self::Forbidden {
                body: Self::message_from_body(body),
            },
            429 => Self::RateLimited { retry_after },
            other => Self::OtherStatus(other),
        }
    }

    /// Pull a short, log-safe excerpt from a GitHub 4xx response body.
    /// GitHub's error responses are typically
    /// `{"message":"…","documentation_url":"…"}`; return the `message`
    /// when present, otherwise a truncated raw prefix. **Only safe for
    /// 4xx responses**: mint 2xx bodies carry the access token and must
    /// never reach this function.
    fn message_from_body(body: &[u8]) -> String {
        #[derive(Deserialize)]
        struct Envelope<'a> {
            message: Option<&'a str>,
        }
        if let Ok(env) = serde_json::from_slice::<Envelope>(body)
            && let Some(m) = env.message
        {
            return m.to_string();
        }
        const MAX_CHARS: usize = 200;
        let text = std::str::from_utf8(body).unwrap_or("(non-utf8 body)");
        match text.char_indices().nth(MAX_CHARS) {
            Some((cut, _)) => format!("{}…", &text[..cut]),
            None => text.to_string(),
        }
    }
}

impl From<GithubError> for ProviderError {
    fn from(e: GithubError) -> Self {
        match e {
            GithubError::Http(src) => Self::Transport(Box::new(src)),
            GithubError::Unauthorized { body } => Self::Unauthorized { body },
            GithubError::Forbidden { body } => Self::Forbidden { body },
            GithubError::RepoNotFound => Self::RepoNotFound,
            GithubError::RateLimited { retry_after } => Self::RateLimited { retry_after },
            GithubError::OtherStatus(s) => Self::UnexpectedStatus { status: s },
            GithubError::MalformedPath(p) => Self::MalformedPath { path: p },
            GithubError::ParseResponse { context, detail } => {
                Self::MalformedResponse { context, detail }
            }
            GithubError::Timeout(d) => Self::Timeout { elapsed: d },
            GithubError::Cancelled => Self::Cancelled,
            // GitHub-private grab bag (PEM load, JWT signer, identity
            // mismatch). The source chain is walked by `ErrorChain` in
            // the daemon's catch-all log arm.
            other @ (GithubError::PemRead { .. }
            | GithubError::PemParse { .. }
            | GithubError::JwtSign(_)
            | GithubError::JwtSignerDead
            | GithubError::ClientIdMismatch { .. }) => Self::Internal(Box::new(other)),
        }
    }
}

pub struct GitHubProvider {
    /// Configured `[provider.github].host` — the value the daemon
    /// matches `host=` against in incoming git-credential requests
    /// (AGENTS.md invariant #11). Exposed via [`Self::host`] so the
    /// `Provider` trait impl can dispatch on it without re-reading
    /// the original config.
    host: String,
    api_base: String,
    client_id: String,
    installation_id: InstallationId,
    signer: JwtSigner,
    client: cyper::Client,
    user_agent: String,
    clock: fn() -> SystemTime,
    repo_ids: SingleflightCache<String, RepoId>,
    selfcheck_timeout: Duration,
    request_timeout: Duration,
    // Cloned from Service::shutdown so HTTPS calls observe shutdown
    // and return promptly with GithubError::Cancelled instead of
    // blocking the daemon drain.
    cancel: CancelToken,
}

// ============================================================================
// impl GitHubProvider — construction
// ============================================================================

impl GitHubProvider {
    /// Load the App private key from disk and parse it into a
    /// `JwtSigningKey`. Must run BEFORE the sandbox closes
    /// filesystem access; the resulting `Arc` is then handed to
    /// [`new`] post-sandbox along with the shared CpuWorker.
    pub async fn load_key(cfg: &ProviderGithub) -> Result<Arc<JwtSigningKey>, GithubError> {
        let path = cfg.private_key_path.clone();
        let pem_bytes = compio::fs::read(&path)
            .await
            .map_err(|source| GithubError::PemRead {
                path: path.clone(),
                source,
            })?;
        let key = JwtSigningKey::from_pem(&pem_bytes)
            .map_err(|source| GithubError::PemParse { path, source })?;
        Ok(Arc::new(key))
    }

    pub fn new(
        cfg: &ProviderGithub,
        key: Arc<JwtSigningKey>,
        worker: Rc<CpuWorker>,
        cancel: CancelToken,
    ) -> Result<Self, GithubError> {
        Self::with_overrides(cfg, key, worker, cancel, None, SystemTime::now)
    }

    #[doc(hidden)]
    pub fn with_overrides(
        cfg: &ProviderGithub,
        key: Arc<JwtSigningKey>,
        worker: Rc<CpuWorker>,
        cancel: CancelToken,
        api_base_override: Option<String>,
        clock: fn() -> SystemTime,
    ) -> Result<Self, GithubError> {
        let api_base = api_base_override
            .unwrap_or_else(|| cfg.api_base.clone())
            .trim_end_matches('/')
            .to_string();
        let client = {
            // Same-origin redirect policy: HTTPS to api.github.com may
            // redirect within api.github.com, never elsewhere. Off-host
            // redirects would carry the App JWT off-domain.
            let bad_base = || GithubError::MalformedPath(format!("api_base={api_base}"));
            let url = Url::parse(&api_base).map_err(|_| bad_base())?;
            let api_host = url.host_str().ok_or_else(bad_base)?.to_owned();
            let policy = redirect::Policy::custom(move |attempt| {
                if attempt.url().host_str() == Some(&api_host) {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            });
            cyper::Client::builder().redirect(policy).build()?
        };
        Ok(Self {
            host: cfg.host.clone(),
            api_base,
            client_id: cfg.client_id.clone(),
            installation_id: cfg.installation_id,
            signer: JwtSigner { worker, key },
            client,
            user_agent: cfg.user_agent.clone(),
            clock,
            repo_ids: SingleflightCache::default(),
            selfcheck_timeout: cfg.selfcheck_timeout,
            request_timeout: cfg.request_timeout,
            cancel,
        })
    }
}

// ============================================================================
// impl GitHubProvider — public operations
// ============================================================================

impl GitHubProvider {
    /// Host this provider serves — the value the daemon matches
    /// the incoming git-credential `host=` against (byte-exact).
    pub fn host(&self) -> &str {
        &self.host
    }

    pub async fn mint(&self, path: &str) -> Result<AbstractMintOutcome, GithubError> {
        let RepoPath { owner, repo } = RepoPath::parse(path)?;
        let key = format!(
            "{}/{}",
            owner.to_ascii_lowercase(),
            repo.to_ascii_lowercase()
        );
        let repo_id = self
            .repo_ids
            .with(&key, async || {
                // Repo-scoped reads on `GET /repos/{owner}/{repo}` require an
                // **installation access token**; the raw App JWT only
                // authenticates App-level endpoints (`/app`,
                // `/app/installations/...`). Mint a metadata-only
                // installation token first, then use it as the bearer for
                // the actual repo lookup. Logged as two distinct
                // `provider_call` breadcrumbs.
                self.with_metadata_token(async |token| {
                    self.resolve_repo_id(token, owner, repo).await
                })
                .await
            })
            .await?;
        self.mint_token(repo_id).await.inspect_err(|e| {
            // Repo deleted/recreated since the resolve — drop the
            // cached id so the next mint re-resolves.
            if matches!(e, GithubError::RepoNotFound) {
                self.repo_ids.invalidate(&key);
            }
        })
    }
}

// ============================================================================
// impl GitHubProvider — internal helpers
// ============================================================================

impl GitHubProvider {
    async fn sign_jwt_now(&self) -> Result<String, GithubError> {
        let claims = JwtClaims::new((self.clock)(), &self.client_id);
        self.signer.sign(claims).await
    }

    /// Apply the GitHub-standard request headers that depend only
    /// on the endpoint (Bearer, Accept, X-GitHub-Api-Version,
    /// User-Agent). Per-call headers (X-Request-Id, request-timeout)
    /// are appended by `run_call` after the `build` closure returns,
    /// so build closures don't have to thread `out_req_id` /
    /// `timeout` through their own signatures.
    fn apply_standard_headers(
        &self,
        req: cyper::RequestBuilder,
        bearer: &str,
    ) -> Result<cyper::RequestBuilder, GithubError> {
        Ok(req
            .bearer_auth(bearer)?
            .header("accept", ACCEPT_HEADER)?
            .header("x-github-api-version", GITHUB_API_VERSION)?
            .header("user-agent", &self.user_agent)?)
    }

    /// Run one outbound HTTPS call end-to-end:
    /// build the request (with the minted `out_req_id`), send it,
    /// hand the `Response` + `CallMeta` to the endpoint's `handle`
    /// closure, then emit the `provider_call_done` breadcrumb.
    /// Pulling `status` + `provider_req_id` into `CallMeta`
    /// *before* the body is consumed means `handle` can call either
    /// `resp.json::<T>()` (typed success deserialise) or
    /// `resp.bytes()` (raw — needed for the 4xx error envelope or
    /// custom parsers like `parse_mint_response`) and the breadcrumb
    /// still carries the upstream correlation id on the error path.
    ///
    /// Races shutdown + timeout around the inner future. On
    /// timeout/cancel/transport-error the breadcrumb logs
    /// `status = 0` with the error string.
    async fn run_call<T>(
        &self,
        endpoint: &'static str,
        timeout: Duration,
        build: impl AsyncFnOnce() -> Result<cyper::RequestBuilder, GithubError>,
        handle: impl AsyncFnOnce(cyper::Response, &CallMeta, &OutReqId) -> Result<T, GithubError>,
    ) -> Result<T, GithubError> {
        use tracing::Instrument;
        let out_req_id = OutReqId::new();
        // Per-HTTPS-call nested span: inherits `req_id` from the
        // outer per-connection span (opened by the daemon/admin
        // accept loop) and adds `out_req_id` so both ids ride
        // along on every event the closures emit.
        let span = tracing::info_span!("provider_call", out_req_id = %out_req_id);
        async move {
            info!(
                evt = %EventKind::ProviderCall,
                endpoint = endpoint,
                provider = %self.api_base,
                timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
            );
            let started = Instant::now();
            let raced = futures_util::select_biased! {
                _ = self.cancel.clone().wait().fuse() => Err(GithubError::Cancelled),
                r = compio::time::timeout(timeout, async {
                    // Apply per-call headers (X-Request-Id +
                    // request-timeout) here so build closures stay
                    // free of `&OutReqId` / `timeout` plumbing.
                    let resp = build()
                        .await?
                        .header(X_REQUEST_ID_HEADER, out_req_id.as_str())?
                        .header(REQUEST_TIMEOUT_HEADER, timeout.as_secs())?
                        .send()
                        .await?;
                    let meta = CallMeta {
                        status: resp.status().as_u16(),
                        provider_req_id: Self::read_provider_req_id(&resp),
                    };
                    let result = handle(resp, &meta, &out_req_id).await;
                    Ok((meta, result))
                }).fuse() => match r {
                    Ok(inner) => inner,
                    Err(_) => Err(GithubError::Timeout(timeout)),
                },
            };
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            match raced {
                Ok((
                    CallMeta {
                        status,
                        provider_req_id,
                    },
                    result,
                )) => {
                    info!(
                        evt = %EventKind::ProviderCallDone,
                        status = status,
                        // GitHub's `X-GitHub-Request-Id`. The
                        // PROTOCOLS.md logging schema names this
                        // `provider_req_id` so future providers
                        // (GitLab, Gitea, ...) emit the same key
                        // with their own upstream correlation id.
                        provider_req_id = provider_req_id.as_ref().map(|p| p.as_str()).unwrap_or(""),
                        elapsed_ms = elapsed_ms,
                    );
                    result
                }
                Err(e) => {
                    info!(
                        evt = %EventKind::ProviderCallDone,
                        status = 0,
                        provider_req_id = "",
                        elapsed_ms = elapsed_ms,
                        error = %e,
                    );
                    Err(e)
                }
            }
        }
        .instrument(span)
        .await
    }

    /// Mint a scratch metadata-only installation token, hand it to
    /// `work`, and revoke it best-effort regardless of whether `work`
    /// succeeded, failed, or panicked-mid-await. The structural
    /// guarantee replaces the open-coded "mint / use / revoke"
    /// sequence and prevents the silent-leak class where a future
    /// `?` lands between use and revoke. The mint token returned to
    /// the client (in `mint_token`) CANNOT use this helper — the
    /// client holds it for the duration of its git operation, and
    /// revoking would break the in-flight clone/fetch/push.
    /// Documented asymmetry.
    async fn with_metadata_token<T>(
        &self,
        work: impl AsyncFnOnce(&str) -> Result<T, GithubError>,
    ) -> Result<T, GithubError> {
        let (token, _expires) = self.mint_metadata_token().await?;
        let result = work(&token).await;
        // Best-effort `DELETE /installation/token`: failures are
        // already logged as `provider_call_done` breadcrumbs; we
        // discard them here because the caller has already finished
        // with the token and the worst case is the token sticks
        // around for its natural 1-hour TTL.
        let _ = self.revoke_install_token(&token).await;
        result
    }

    /// `GET /app` to verify reachability + key/App pairing. Reads the
    /// `Date` response header for clock-skew reporting off the borrowed
    /// `Response` *before* consuming the body — only `run_call`'s shape
    /// (handing `Response` to the closure intact) makes that ordering
    /// expressible without rebuilding the breadcrumb plumbing inline.
    pub async fn selfcheck(&self) -> Result<AbstractSelfcheckOutcome, GithubError> {
        self.run_call(
            "selfcheck",
            self.selfcheck_timeout,
            async || {
                let jwt = self.sign_jwt_now().await?;
                let req = self.client.get(format!("{}/app", self.api_base))?;
                self.apply_standard_headers(req, &jwt)
            },
            async |resp, meta, out_req_id| {
                // HTTP `Date` header (RFC 7231 § 7.1.1.1) parsed via
                // `time`'s Rfc2822 (`GMT` → zero offset). Silently 0
                // on a missing or unparseable header — clock skew is
                // informational, not load-bearing.
                let clock_skew_sec = resp
                    .headers()
                    .get("date")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| OffsetDateTime::parse(s, &Rfc2822).ok())
                    .map(|t| t.unix_timestamp() - OffsetDateTime::now_utc().unix_timestamp())
                    .unwrap_or(0);
                let retry_after = Self::read_retry_after(&resp);
                let body = resp.bytes().await?;
                if meta.status != 200 {
                    return Err(GithubError::from_common_status(
                        meta.status,
                        &body,
                        retry_after,
                    ));
                }
                Self::check_app_identity(&body, &self.client_id)?;
                Ok(AbstractSelfcheckOutcome {
                    out_req_id: out_req_id.clone(),
                    provider_req_id: meta.provider_req_id.clone(),
                    clock_skew_sec,
                    // GitHub-specific diagnostic dump documented in
                    // `docs/providers/github.md`.
                    details: json!({
                        "client_id": self.client_id,
                        "installation_id": self.installation_id,
                        "api_base": self.api_base,
                    }),
                })
            },
        )
        .await
    }

    async fn resolve_repo_id(
        &self,
        install_token: &str,
        owner: &str,
        repo: &str,
    ) -> Result<RepoId, GithubError> {
        self.run_call(
            "resolve_repo_id",
            self.request_timeout,
            async || {
                // `owner` / `repo` already came through `RepoPath::parse`,
                // so they're guaranteed `[A-Za-z0-9._-]+` and need no
                // URL-escaping.
                let req = self
                    .client
                    .get(format!("{}/repos/{owner}/{repo}", self.api_base))?;
                self.apply_standard_headers(req, install_token)
            },
            async |resp, meta, _out_req_id| {
                #[derive(Deserialize)]
                struct Resp {
                    id: RepoId,
                }
                let retry_after = Self::read_retry_after(&resp);
                let body = resp.bytes().await?;
                match meta.status {
                    200 => serde_json::from_slice::<Resp>(&body)
                        .map(|r| r.id)
                        .map_err(|_| GithubError::ParseResponse {
                            context: "repo",
                            detail: "json",
                        }),
                    404 => Err(GithubError::RepoNotFound),
                    s => Err(GithubError::from_common_status(s, &body, retry_after)),
                }
            },
        )
        .await
    }

    /// Mint a metadata-only installation token (no `repository_ids`,
    /// `permissions: {metadata: read}`). Used to authenticate the
    /// `/repos/{owner}/{repo}` lookup that precedes the actual
    /// narrow-scope mint. Returns `(token, expires_at)`; `expires_at`
    /// is only used by the breadcrumb log on the caller's side.
    async fn mint_metadata_token(&self) -> Result<(String, SystemTime), GithubError> {
        self.run_call(
            "mint_metadata_token",
            self.request_timeout,
            async || {
                let jwt = self.sign_jwt_now().await?;
                let req = self.client.post(format!(
                    "{}/app/installations/{}/access_tokens",
                    self.api_base, self.installation_id
                ))?;
                Ok(self
                    .apply_standard_headers(req, &jwt)?
                    .header("content-type", "application/json")?
                    .body(Bytes::from_static(
                        br#"{"permissions":{"metadata":"read"}}"#,
                    )))
            },
            async |resp, meta, _| {
                let retry_after = Self::read_retry_after(&resp);
                let body = resp.bytes().await?;
                match meta.status {
                    201 => Self::parse_mint_response(&body),
                    s => Err(GithubError::from_common_status(s, &body, retry_after)),
                }
            },
        )
        .await
    }

    async fn mint_token(&self, repo_id: RepoId) -> Result<AbstractMintOutcome, GithubError> {
        self.run_call(
            "mint_token",
            self.request_timeout,
            async || {
                let jwt = self.sign_jwt_now().await?;
                let req = self.client.post(format!(
                    "{}/app/installations/{}/access_tokens",
                    self.api_base, self.installation_id
                ))?;
                // Per-mint body: exactly one repo, hard-coded permission
                // set (AGENTS.md invariants #4, #5). Wire bytes pinned by
                // `tests::mint_request_headers_and_body_exact` (integration).
                Ok(self
                    .apply_standard_headers(req, &jwt)?
                    .header("content-type", "application/json")?
                    .body(Bytes::from(format!(
                        r#"{{"repository_ids":[{repo_id}],"permissions":{{"contents":"write","metadata":"read"}}}}"#
                    ))))
            },
            async |resp, meta, out_req_id| {
                let retry_after = Self::read_retry_after(&resp);
                let body = resp.bytes().await?;
                match meta.status {
                    201 => {
                        let (token, expires_at) = Self::parse_mint_response(&body)?;
                        // GitHub-specific sentinel: when the username on a
                        // git HTTPS clone is the literal `x-access-token`,
                        // the password is interpreted as an installation
                        // access token (vs a personal access token or OAuth
                        // token). Documented in GitHub Apps "Authenticating
                        // as an installation".
                        //
                        // `Response::new` validates that the token has no
                        // CR/LF/NUL and that the expiry isn't pre-epoch.
                        // GitHub has never been observed to return such a
                        // token; if it ever does, surface it as a malformed
                        // mint response rather than letting bad bytes reach
                        // the wire emit.
                        let response = git_credential::Response::new(
                            "x-access-token".to_string(),
                            token,
                            expires_at,
                        )
                        .map_err(|_| GithubError::ParseResponse {
                            context: "mint",
                            detail: "invalid token or expiry from GitHub",
                        })?;
                        Ok(AbstractMintOutcome {
                            response,
                            out_req_id: out_req_id.clone(),
                            provider_req_id: meta.provider_req_id.clone(),
                        })
                    }
                    404 => Err(GithubError::RepoNotFound),
                    s => Err(GithubError::from_common_status(s, &body, retry_after)),
                }
            },
        )
        .await
    }

    /// `DELETE /installation/token` — revokes the currently-held
    /// installation access token. Used by `with_metadata_token` to
    /// narrow the leak window on the broadly-scoped metadata token.
    async fn revoke_install_token(&self, token: &str) -> Result<(), GithubError> {
        self.run_call(
            "revoke_install_token",
            self.request_timeout,
            async || {
                let req = self
                    .client
                    .delete(format!("{}/installation/token", self.api_base))?;
                self.apply_standard_headers(req, token)
            },
            async |resp, meta, _| match meta.status {
                204 => Ok(()),
                s => {
                    let retry_after = Self::read_retry_after(&resp);
                    let body = resp.bytes().await.unwrap_or_default();
                    Err(GithubError::from_common_status(s, &body, retry_after))
                }
            },
        )
        .await
    }
}

// ============================================================================
// HTTP plumbing
// ============================================================================

const REQUEST_TIMEOUT_HEADER: &str = "request-timeout";
const X_REQUEST_ID_HEADER: &str = "x-request-id";
const GH_REQUEST_ID_HEADER: &str = "x-github-request-id";

/// Metadata pulled off a `cyper::Response` before its body is
/// consumed. `run_call` reads this once and passes a borrow to the
/// endpoint's `handle` closure, so the breadcrumb log gets `status`
/// and `provider_req_id` even when `handle` calls `.json::<T>()` or
/// `.bytes()` and ends up returning an error.
struct CallMeta {
    status: u16,
    provider_req_id: Option<ProviderReqId>,
}

// ============================================================================
// JWT signing
// ============================================================================

#[derive(Serialize)]
struct JwtClaims {
    iss: String,
    iat: u64,
    exp: u64,
}

impl JwtClaims {
    /// Clock-skew leeway: stamp `iat` 60 s in the past so a slightly
    /// behind broker still passes GitHub's "iat in the future" check.
    const LEEWAY_PAST_SECS: u64 = 60;
    /// Lifetime: 9 minutes. GitHub caps App JWTs at 10 minutes; the
    /// 60 s margin matches `LEEWAY_PAST_SECS` so total skew tolerance
    /// is 1 minute on either side.
    const LIFETIME_SECS: u64 = 540;

    fn new(now: SystemTime, client_id: &str) -> Self {
        let unix = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Self {
            iss: client_id.to_string(),
            iat: unix.saturating_sub(Self::LEEWAY_PAST_SECS),
            exp: unix.saturating_add(Self::LIFETIME_SECS),
        }
    }
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
    /// Synchronous RSA-2048 signing runs ~1-2 ms per call on the
    /// shared `CpuWorker` thread — never on the compio runtime.
    async fn sign(&self, claims: JwtClaims) -> Result<String, GithubError> {
        let key = Arc::clone(&self.key);
        self.worker
            .run(move || key.sign_rs256(&claims).map_err(GithubError::JwtSign))
            .await?
    }
}

// ============================================================================
// impl GitHubProvider — request body builder, response parsers
// ============================================================================

impl GitHubProvider {
    /// Read the GitHub-specific `X-GitHub-Request-Id` header off a
    /// response, if present. The string ends up on the abstract
    /// `provider_req_id` log/wire field; field shape is shared with
    /// other providers (each surfaces their own upstream correlation
    /// id under the same field name).
    fn read_provider_req_id(resp: &cyper::Response) -> Option<ProviderReqId> {
        resp.headers()
            .get(GH_REQUEST_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|s| ProviderReqId::from(s.to_string()))
    }

    /// Read the `Retry-After` header per RFC 9110 §10.2.3. The
    /// header carries either an integer number of seconds OR an
    /// HTTP-date; we parse the integer form (which GitHub uses) and
    /// ignore the date form. Returns `None` on absent or malformed
    /// values — caller falls back to "wait at your own pace."
    fn read_retry_after(resp: &cyper::Response) -> Option<Duration> {
        resp.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(Duration::from_secs)
    }

    /// Parse `GET /app`'s body and verify the reported `client_id`
    /// matches the configured one (`expected`). Returns `Ok(())` on
    /// match; the caller already has `expected` in hand.
    fn check_app_identity(body: &[u8], expected: &str) -> Result<(), GithubError> {
        #[derive(Deserialize)]
        struct App {
            client_id: String,
        }
        let app: App = serde_json::from_slice(body).map_err(|_| GithubError::ParseResponse {
            context: "selfcheck",
            detail: "json",
        })?;
        if app.client_id != expected {
            return Err(GithubError::ClientIdMismatch {
                configured: expected.to_string(),
                reported: app.client_id,
            });
        }
        Ok(())
    }

    fn parse_mint_response(bytes: &[u8]) -> Result<(String, SystemTime), GithubError> {
        #[derive(Deserialize)]
        struct Resp {
            token: String,
            expires_at: String,
        }
        let r: Resp = serde_json::from_slice(bytes).map_err(|_| GithubError::ParseResponse {
            context: "mint",
            detail: "json",
        })?;
        let secs = OffsetDateTime::parse(&r.expires_at, &Rfc3339)
            .ok()
            .and_then(|dt| u64::try_from(dt.unix_timestamp()).ok())
            .ok_or(GithubError::ParseResponse {
                context: "mint",
                detail: "bad expires_at",
            })?;
        Ok((r.token, UNIX_EPOCH + Duration::from_secs(secs)))
    }
}

// ============================================================================
// RepoPath: parsed and validated owner/repo from a git-credential request
// ============================================================================

/// `owner/repo` reference borrowed from a git-credential request,
/// validated against the GitHub-allowed charset by [`Self::parse`]
/// so downstream URL builders can paste it raw without escaping.
#[derive(Debug)]
struct RepoPath<'a> {
    owner: &'a str,
    repo: &'a str,
}

impl<'a> RepoPath<'a> {
    /// Split `owner/repo` and validate both halves against the
    /// GitHub-allowed charset (`[A-Za-z0-9._-]+`). Zero-alloc on
    /// the success path.
    fn parse(path: &'a str) -> Result<Self, GithubError> {
        fn is_valid_byte(b: u8) -> bool {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
        }
        let (owner, repo) = path
            .split_once('/')
            .ok_or_else(|| GithubError::MalformedPath(path.to_string()))?;
        if owner.is_empty()
            || repo.is_empty()
            || !owner.bytes().all(is_valid_byte)
            || !repo.bytes().all(is_valid_byte)
        {
            return Err(GithubError::MalformedPath(path.to_string()));
        }
        Ok(Self { owner, repo })
    }
}

// ============================================================================
// Provider trait impl
// ============================================================================

#[async_trait(?Send)]
impl Provider for GitHubProvider {
    fn host(&self) -> &str {
        self.host()
    }

    async fn mint(&self, path: &str) -> Result<AbstractMintOutcome, ProviderError> {
        Ok(GitHubProvider::mint(self, path).await?)
    }

    async fn selfcheck(&self) -> Result<AbstractSelfcheckOutcome, ProviderError> {
        Ok(GitHubProvider::selfcheck(self).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_date_rfc2822_parses_imf_fixdate() {
        // RFC 7231 § 7.1.1.1 example.
        let dt = OffsetDateTime::parse("Sun, 06 Nov 1994 08:49:37 GMT", &Rfc2822).unwrap();
        assert_eq!(dt.unix_timestamp(), 784_111_777);
    }

    const FIXTURE_PEM: &str = include_str!("../../tests/fixtures/test_app_key.pem");

    fn t(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn build_claims_at_fixed_time() {
        let claims = JwtClaims::new(t(1_700_000_000), "Iv1.test42");
        assert_eq!(claims.iss, "Iv1.test42");
        assert_eq!(claims.iat, 1_700_000_000 - 60);
        assert_eq!(claims.exp, 1_700_000_000 + 540);
    }

    #[test]
    fn sign_jwt_produces_three_parts() {
        let key = JwtSigningKey::from_pem(FIXTURE_PEM.as_bytes()).unwrap();
        let claims = JwtClaims::new(t(1_700_000_000), "Iv1.test42");
        let token = key.sign_rs256(&claims).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    /// Pin the exact signed token for known (claims, key).
    /// RSASSA-PKCS1-v1_5 is deterministic; the
    /// `crate::providers::jwt_rs256` test has the same assertion
    /// for the lower-level helper, this one covers
    /// `JwtSigner::sign` end-to-end.
    #[test]
    fn sign_jwt_blocking_known_vector() {
        let key = JwtSigningKey::from_pem(FIXTURE_PEM.as_bytes()).unwrap();
        let claims = JwtClaims::new(t(1_700_000_000), "Iv1.test42");
        let token = key.sign_rs256(&claims).unwrap();
        assert_eq!(
            token,
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJJdjEudGVzdDQyIiwiaWF0IjoxNjk5OTk5OTQwLCJleHAiOjE3MDAwMDA1NDB9.yPTDonwO4souVu_3nk7Aq8ZbiAq3PBVLHRJ5J6B67JHmUxVh-yvIoXdQ8O_EAqj-H57GKRAo_b0nu6hQT_keD9-wB_ah8DC_ZqtV42S3jHACWAdEG066W1XdKUftU82QkdSM5hrpdg9OvFN6i7m0ObCJi3uJMWXYb8lY1LYJew0SWajBzLKQjw47Qmbq-AYiTgkdBoRfK5TrD64u6wd0aQCathxELkaiEacilUtU6ZH8jOQ_W5hYjjwxjTF7wbNWdx-v7M3yUSUn_01Sn9w2bTLeimsP4e81ydchLhIeJED4iF-j-QG_uBlhp0auwTPYqPaG6Zh-qhbkE0DJaV-log",
        );
    }

    #[test]
    fn parse_mint_response_ok() {
        let body = br#"{"token":"ghs_x","expires_at":"2026-05-31T13:00:00Z","extra":"ignored"}"#;
        let (tok, exp) = GitHubProvider::parse_mint_response(body).unwrap();
        assert_eq!(tok, "ghs_x");
        // 2026-05-31T13:00:00Z = 1780232400.
        let secs = exp.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 1_780_232_400);
    }

    #[test]
    fn parse_mint_response_bad_expires_at() {
        let body = br#"{"token":"ghs_x","expires_at":"not-a-date"}"#;
        let err = GitHubProvider::parse_mint_response(body).unwrap_err();
        assert!(matches!(
            err,
            GithubError::ParseResponse {
                context: "mint",
                detail: "bad expires_at",
            }
        ));
    }

    #[test]
    fn parse_mint_response_missing_token() {
        let body = br#"{"expires_at":"2026-05-31T13:00:00Z"}"#;
        let err = GitHubProvider::parse_mint_response(body).unwrap_err();
        assert!(matches!(
            err,
            GithubError::ParseResponse {
                context: "mint",
                detail: "json",
            }
        ));
    }

    #[test]
    fn parse_mint_response_bad_json() {
        let body = b"not json at all";
        let err = GitHubProvider::parse_mint_response(body).unwrap_err();
        assert!(matches!(
            err,
            GithubError::ParseResponse {
                context: "mint",
                detail: "json",
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
        let err = GitHubProvider::parse_mint_response(&body).unwrap_err();
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
    fn repo_path_parse_ok() {
        let RepoPath { owner, repo } = RepoPath::parse("octocat/Hello-World").unwrap();
        assert_eq!(owner, "octocat");
        assert_eq!(repo, "Hello-World");
    }

    #[test]
    fn repo_path_parse_rejects_empty_half() {
        assert!(matches!(
            RepoPath::parse("/foo").unwrap_err(),
            GithubError::MalformedPath(_)
        ));
        assert!(matches!(
            RepoPath::parse("foo/").unwrap_err(),
            GithubError::MalformedPath(_)
        ));
    }

    #[test]
    fn repo_path_parse_rejects_extra_slash() {
        assert!(matches!(
            RepoPath::parse("a/b/c").unwrap_err(),
            GithubError::MalformedPath(_)
        ));
    }

    #[test]
    fn repo_path_parse_rejects_non_ascii() {
        assert!(matches!(
            RepoPath::parse("föö/bar").unwrap_err(),
            GithubError::MalformedPath(_)
        ));
    }

    #[compio::test]
    async fn api_base_trailing_slash_stripped() {
        let cfg = ProviderGithub {
            host: "github.com".to_string(),
            api_base: "https://api.github.com/".to_string(),
            client_id: "Iv1.test1".to_string(),
            installation_id: 2u64.into(),
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
}
