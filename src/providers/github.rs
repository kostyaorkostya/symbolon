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
use derive_more::{AsRef, Display, From, Into};
use serde_json::json;

use crate::config::ProviderGithub;
use crate::cpu_worker::{CpuWorker, WorkerDead};
use crate::events::EventKind;
use crate::git_credential;
use crate::ids::{OutReqId, ReqId};
use crate::providers::jwt_rs256::{self, JwtSigningKey};
use crate::providers::{
    MintOutcome as AbstractMintOutcome, Provider, ProviderError, ProviderKind, ProviderReqId,
    SelfcheckOutcome as AbstractSelfcheckOutcome,
};
use crate::singleflight_cache::SingleflightCache;

/// GitHub App **installation** numeric id (the `installation_id`
/// path parameter on `/app/installations/{id}/access_tokens` etc.).
/// Distinct from `RepoId` so a swap is a compile error.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    AsRef,
    Display,
    From,
    Into,
    serde::Deserialize,
    serde::Serialize,
)]
#[as_ref(u64)]
#[from(u64)]
#[serde(transparent)]
pub struct InstallationId(u64);

/// GitHub **repository** numeric id (the `id` field on the repo
/// REST resource; used in the mint body's `repository_ids` array).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    AsRef,
    Display,
    From,
    Into,
    serde::Deserialize,
    serde::Serialize,
)]
#[as_ref(u64)]
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
    #[error("repository '{path}' not found or App lacks access")]
    RepoNotFound { path: String },
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
            GithubError::RepoNotFound { path } => Self::RepoNotFound { path },
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

#[derive(Debug, Clone)]
pub struct SelfcheckData {
    pub(crate) client_id: String,
    pub(crate) installation_id: InstallationId,
    pub(crate) api_base: String,
    pub(crate) clock_skew_sec: i64,
    /// ULID of the outbound HTTPS call. Pairs with the
    /// `provider_call` / `provider_call_done` breadcrumbs.
    pub(crate) out_req_id: OutReqId,
    /// `X-GitHub-Request-Id` returned by the API, if any.
    pub(crate) provider_req_id: Option<ProviderReqId>,
}

#[derive(Debug, Clone)]
pub struct MintData {
    pub response: git_credential::Response,
    /// ULID of the outbound `mint_token` HTTPS call. Pairs with
    /// the `provider_call` / `provider_call_done` breadcrumbs.
    pub out_req_id: OutReqId,
    /// `X-GitHub-Request-Id` returned by the mint endpoint, if any.
    pub provider_req_id: Option<ProviderReqId>,
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
            host: cfg.host.clone(),
            api_base,
            client_id: cfg.client_id.clone(),
            installation_id: InstallationId::from(cfg.installation_id),
            signer,
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

    /// Verify the App private key signs a valid JWT and the App is
    /// reachable at `api_base`. The reported App ID must match the
    /// configured one — a mismatch indicates a wrong key/App pairing.
    pub async fn selfcheck(&self, req_id: &ReqId) -> Result<SelfcheckData, GithubError> {
        self.with_breadcrumbs(req_id, "selfcheck", self.selfcheck_timeout, async |out| {
            self.selfcheck_inner(out).await
        })
        .await
    }

    pub async fn mint(&self, req_id: &ReqId, path: &str) -> Result<MintData, GithubError> {
        let parsed = RepoPath::parse(path)?;
        let key = format!(
            "{}/{}",
            parsed.owner().to_ascii_lowercase(),
            parsed.repo().to_ascii_lowercase()
        );
        let repo_id = self
            .repo_ids
            .with(&key, async || {
                self.resolve_repo_id(req_id, parsed.owner(), parsed.repo())
                    .await
            })
            .await?;

        self.with_breadcrumbs(req_id, "mint_token", self.request_timeout, async |out| {
            self.mint_token_inner(out, repo_id, path).await
        })
        .await
        .inspect_err(|e| {
            // Repo deleted/recreated since the resolve — drop the
            // cached id so the next mint re-resolves.
            if matches!(e, GithubError::RepoNotFound { .. }) {
                self.repo_ids.invalidate(&key);
            }
        })
    }
}

// ============================================================================
// impl GitHubProvider — internal helpers
// ============================================================================

impl GitHubProvider {
    /// Wrap one outbound HTTPS call: emits the `provider_call`
    /// breadcrumb before, races shutdown + timeout around the
    /// inner future, then emits `provider_call_done` with status +
    /// `provider_req_id` + elapsed_ms.
    ///
    /// On timeout/cancel/transport-error a `provider_call_done` is
    /// still emitted with `status = 0`. The inner closure receives the
    /// minted `OutReqId` and is expected to embed it (plus any
    /// upstream correlation id from the response) into the success
    /// type `T` it returns — see `MintToken`, `SelfcheckData`,
    /// `MintData` for the in-tree shapes. This lets the breadcrumb
    /// wrapper stay payload-agnostic and return a flat
    /// `Result<T, GithubError>` rather than the
    /// `(T, OutReqId, Option<ProviderReqId>)` tuple every caller used
    /// to immediately destructure.
    async fn with_breadcrumbs<T>(
        &self,
        req_id: &ReqId,
        endpoint: &'static str,
        timeout: Duration,
        mk_inner: impl AsyncFnOnce(OutReqId) -> ProviderCall<T>,
    ) -> Result<T, GithubError> {
        let out_req_id = OutReqId::new();
        info!(
            evt = %EventKind::ProviderCall,
            req_id = %req_id,
            out_req_id = %out_req_id,
            endpoint = endpoint,
            provider = %self.api_base,
            timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
        );
        let started = Instant::now();
        let raced = futures_util::select_biased! {
            _ = self.cancel.clone().wait().fuse() => Err(GithubError::Cancelled),
            r = compio::time::timeout(timeout, mk_inner(out_req_id.clone())).fuse() =>
                r.map_err(|_| GithubError::Timeout(timeout)),
        };
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match raced {
            Ok(pc) => {
                info!(
                    evt = %EventKind::ProviderCallDone,
                    req_id = %req_id,
                    out_req_id = %out_req_id,
                    status = pc.status,
                    // GitHub's `X-GitHub-Request-Id`. The PROTOCOLS.md
                    // logging schema names this `provider_req_id` so
                    // future providers (GitLab, Gitea, ...) emit the
                    // same key with their own upstream correlation id.
                    provider_req_id = pc.provider_req_id.as_ref().map(|p| p.as_str()).unwrap_or(""),
                    elapsed_ms = elapsed_ms,
                );
                pc.result
            }
            Err(e) => {
                info!(
                    evt = %EventKind::ProviderCallDone,
                    req_id = %req_id,
                    out_req_id = %out_req_id,
                    status = 0,
                    provider_req_id = "",
                    elapsed_ms = elapsed_ms,
                    error = %e,
                );
                Err(e)
            }
        }
    }

    async fn sign_jwt_now(&self) -> Result<String, GithubError> {
        let claims = JwtClaims::new((self.clock)(), &self.client_id);
        self.signer.sign(claims).await
    }

    /// Build a `RequestBuilder` with the shared GitHub headers
    /// (Accept, API-Version, User-Agent, X-Request-ID,
    /// Request-Timeout) and bearer auth applied. If `json_body`
    /// is `Some` (applies to either method), the builder also
    /// sets `Content-Type: application/json` and attaches the body.
    fn build_request(
        &self,
        method: Method,
        url: &str,
        bearer: &str,
        json_body: Option<Vec<u8>>,
        out_req_id: &OutReqId,
        timeout: Duration,
    ) -> Result<cyper::RequestBuilder, cyper::Error> {
        let mut req = match method {
            Method::Get => self.client.get(url),
            Method::Post => self.client.post(url),
            Method::Delete => self.client.delete(url),
        }?
        .bearer_auth(bearer)?
        .header("accept", ACCEPT_HEADER)?
        .header("x-github-api-version", GITHUB_API_VERSION)?
        .header("user-agent", &self.user_agent)?
        .header(X_REQUEST_ID_HEADER, out_req_id.as_str())?
        .header(REQUEST_TIMEOUT_HEADER, timeout.as_secs())?;
        if let Some(body) = json_body {
            req = req.header("content-type", "application/json")?.body(body);
        }
        Ok(req)
    }

    /// Build and dispatch a request, returning the raw `Response`.
    /// Pre-body-read errors surface here.
    async fn send_authenticated(
        &self,
        method: Method,
        url: &str,
        bearer: &str,
        json_body: Option<Vec<u8>>,
        out_req_id: &OutReqId,
        timeout: Duration,
    ) -> Result<cyper::Response, GithubError> {
        let req = self
            .build_request(method, url, bearer, json_body, out_req_id, timeout)
            .map_err(GithubError::from)?;
        req.send().await.map_err(GithubError::from)
    }

    /// Send a request and read the response body. Returns the raw
    /// body alongside `status` + `provider_req_id`. Callers inspect
    /// `status` and either parse `result` as a success body or
    /// coerce it into an endpoint-specific error.
    async fn http_call(
        &self,
        method: Method,
        url: &str,
        bearer: &str,
        json_body: Option<Vec<u8>>,
        out_req_id: &OutReqId,
        timeout: Duration,
    ) -> ProviderCall<Bytes> {
        let resp = match self
            .send_authenticated(method, url, bearer, json_body, out_req_id, timeout)
            .await
        {
            Ok(r) => r,
            Err(e) => return ProviderCall::pre_send(e),
        };
        ProviderCall {
            status: resp.status().as_u16(),
            provider_req_id: Self::read_provider_req_id(&resp),
            retry_after: Self::read_retry_after(&resp),
            result: resp.bytes().await.map_err(GithubError::from),
        }
    }

    async fn resolve_repo_id(
        &self,
        req_id: &ReqId,
        owner: &str,
        repo: &str,
    ) -> Result<RepoId, GithubError> {
        // Repo-scoped reads on `GET /repos/{owner}/{repo}` require an
        // **installation access token**; the raw App JWT only
        // authenticates App-level endpoints (`/app`,
        // `/app/installations/...`). Mint a metadata-only
        // installation token first, then use it as the bearer for
        // the actual repo lookup. Logged as two distinct
        // `provider_call` breadcrumbs.
        self.with_metadata_token(req_id, async |token| {
            self.with_breadcrumbs(
                req_id,
                "resolve_repo_id",
                self.request_timeout,
                async |out| self.resolve_repo_id_inner(out, token, owner, repo).await,
            )
            .await
        })
        .await
    }

    /// Mint a scratch metadata-only installation token, hand it to
    /// `work`, and revoke it best-effort regardless of whether `work`
    /// succeeded, failed, or panicked-mid-await. The structural
    /// guarantee replaces the open-coded "mint / use / revoke"
    /// sequence and prevents the silent-leak class where a future
    /// `?` lands between use and revoke. The mint token returned to
    /// the client (in `mint_token_inner`) CANNOT use this helper —
    /// the client holds it for the duration of its git operation,
    /// and revoking would break the in-flight clone/fetch/push.
    /// Documented asymmetry.
    async fn with_metadata_token<T>(
        &self,
        req_id: &ReqId,
        work: impl AsyncFnOnce(&str) -> Result<T, GithubError>,
    ) -> Result<T, GithubError> {
        let token = self
            .with_breadcrumbs(
                req_id,
                "mint_metadata_token",
                self.request_timeout,
                async |out| self.mint_metadata_token_inner(out).await,
            )
            .await?;
        let result = work(&token).await;
        // Best-effort `DELETE /installation/token`: failures are
        // already logged as `provider_call_done` breadcrumbs by
        // with_breadcrumbs; we discard them here because the caller
        // has already finished with the token and the worst case is
        // the token sticks around for its natural 1-hour TTL.
        let _ = self
            .with_breadcrumbs(
                req_id,
                "revoke_install_token",
                self.request_timeout,
                async |out| self.revoke_token_inner(out, &token).await,
            )
            .await;
        result
    }

    async fn revoke_token_inner(
        &self,
        out_req_id: OutReqId,
        install_token: &str,
    ) -> ProviderCall<()> {
        let url = format!("{}/installation/token", self.api_base);
        self.http_call(
            Method::Delete,
            &url,
            install_token,
            None,
            &out_req_id,
            self.request_timeout,
        )
        .await
        .map_with_meta(|_, m| match m.status {
            // 204 No Content = revoked.
            204 => Ok(()),
            s => Err(GithubError::from_common_status(
                s,
                &Bytes::new(),
                m.retry_after,
            )),
        })
    }

    /// `GET /app` to verify reachability + key/App pairing.
    /// Unlike the other endpoints, this one reads the `Date`
    /// response header for clock-skew reporting BEFORE consuming
    /// the body, so it can't use the body-eating `http_call`
    /// helper. The async block lets `?` propagate inside the
    /// future while the surrounding scope captures status +
    /// provider_req_id for the partial-failure `ProviderCall`.
    async fn selfcheck_inner(&self, out_req_id: OutReqId) -> ProviderCall<SelfcheckData> {
        let mut status: u16 = 0;
        let mut provider_req_id: Option<ProviderReqId> = None;
        let result: Result<SelfcheckData, GithubError> = async {
            let jwt = self.sign_jwt_now().await?;
            let url = format!("{}/app", self.api_base);
            let resp = self
                .send_authenticated(
                    Method::Get,
                    &url,
                    &jwt,
                    None,
                    &out_req_id,
                    self.selfcheck_timeout,
                )
                .await?;
            status = resp.status().as_u16();
            provider_req_id = Self::read_provider_req_id(&resp);
            let retry_after = Self::read_retry_after(&resp);
            // HTTP `Date` header (RFC 7231 § 7.1.1.1) parsed via
            // `time`'s Rfc2822 (`GMT` → zero offset). Silently 0 on
            // a missing or unparseable header — clock skew is
            // informational, not load-bearing.
            let clock_skew_sec = resp
                .headers()
                .get("date")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| OffsetDateTime::parse(s, &Rfc2822).ok())
                .map(|t| t.unix_timestamp() - OffsetDateTime::now_utc().unix_timestamp())
                .unwrap_or(0);
            let body = resp.bytes().await?;
            if status != 200 {
                return Err(GithubError::from_common_status(status, &body, retry_after));
            }
            let client_id = Self::check_app_identity(&body, &self.client_id)?;
            Ok(SelfcheckData {
                client_id,
                installation_id: self.installation_id,
                api_base: self.api_base.clone(),
                clock_skew_sec,
                out_req_id: out_req_id.clone(),
                provider_req_id: provider_req_id.clone(),
            })
        }
        .await;
        ProviderCall {
            status,
            provider_req_id,
            // selfcheck has already folded any 429 retry_after into
            // the error variant; the breadcrumb log doesn't surface
            // it, so the outer struct field can stay None here.
            retry_after: None,
            result,
        }
    }

    async fn resolve_repo_id_inner(
        &self,
        out_req_id: OutReqId,
        install_token: &str,
        owner: &str,
        repo: &str,
    ) -> ProviderCall<RepoId> {
        // `owner` / `repo` already came through `RepoPath::parse`, so
        // they're guaranteed `[A-Za-z0-9._-]+` and need no URL-escaping.
        let url = format!("{}/repos/{owner}/{repo}", self.api_base);
        let call = self
            .http_call(
                Method::Get,
                &url,
                install_token,
                None,
                &out_req_id,
                self.request_timeout,
            )
            .await;
        call.map_with_meta(|body, m| match m.status {
            200 => {
                #[derive(Deserialize)]
                struct Resp {
                    id: RepoId,
                }
                serde_json::from_slice::<Resp>(&body)
                    .map(|r| r.id)
                    .map_err(|_| GithubError::ParseResponse {
                        context: "repo",
                        detail: "json",
                    })
            }
            404 => Err(GithubError::RepoNotFound {
                path: format!("{owner}/{repo}"),
            }),
            s => Err(GithubError::from_common_status(s, &body, m.retry_after)),
        })
    }

    /// Mint a metadata-only installation token (no
    /// `repository_ids`, `permissions: {metadata: read}`). Used to
    /// authenticate the `/repos/{owner}/{repo}` lookup that
    /// precedes the actual narrow-scope mint. 404 here means
    /// "installation not found" — surfaced as `OtherStatus` rather
    /// than `RepoNotFound` since this mint isn't repo-scoped.
    async fn mint_metadata_token_inner(&self, out_req_id: OutReqId) -> ProviderCall<String> {
        let jwt = match self.sign_jwt_now().await {
            Ok(j) => j,
            Err(e) => return ProviderCall::pre_send(e),
        };
        let url = format!(
            "{}/app/installations/{}/access_tokens",
            self.api_base, self.installation_id
        );
        // Inline body: metadata-only installation token, no `repository_ids`
        // — `GET /repos/{owner}/{repo}` accepts installation tokens but not
        // the App JWT, so we mint a broad one for the lookup. We discard the
        // `expires_at` half of the parsed response because the token is used
        // for one call in milliseconds and revoked before the hour-long TTL
        // could matter.
        self.http_call(
            Method::Post,
            &url,
            &jwt,
            Some(br#"{"permissions":{"metadata":"read"}}"#.to_vec()),
            &out_req_id,
            self.request_timeout,
        )
        .await
        .map_with_meta(|bytes, m| match m.status {
            201 => Self::parse_mint_response(&bytes).map(|(token, _expires)| token),
            s => Err(GithubError::from_common_status(s, &bytes, m.retry_after)),
        })
    }

    async fn mint_token_inner(
        &self,
        out_req_id: OutReqId,
        repo_id: RepoId,
        path: &str,
    ) -> ProviderCall<MintData> {
        let jwt = match self.sign_jwt_now().await {
            Ok(j) => j,
            Err(e) => return ProviderCall::pre_send(e),
        };
        let url = format!(
            "{}/app/installations/{}/access_tokens",
            self.api_base, self.installation_id
        );
        // Per-mint body: exactly one repo, hard-coded permission set
        // (AGENTS.md invariants #4, #5). Wire bytes pinned by
        // `tests::mint_request_headers_and_body_exact` (integration).
        let body = format!(
            r#"{{"repository_ids":[{repo_id}],"permissions":{{"contents":"write","metadata":"read"}}}}"#
        )
        .into_bytes();
        self.http_call(
            Method::Post,
            &url,
            &jwt,
            Some(body),
            &out_req_id,
            self.request_timeout,
        )
        .await
        .map_with_meta(move |bytes, m| match m.status {
            201 => {
                let (token, expires_at) = Self::parse_mint_response(&bytes)?;
                Ok(MintData {
                    response: git_credential::Response {
                        username: "x-access-token".to_string(),
                        password: token,
                        password_expiry_utc: expires_at,
                    },
                    out_req_id,
                    provider_req_id: m.provider_req_id.cloned(),
                })
            }
            404 => Err(GithubError::RepoNotFound {
                path: path.to_string(),
            }),
            s => Err(GithubError::from_common_status(s, &bytes, m.retry_after)),
        })
    }
}

// ============================================================================
// HTTP plumbing
// ============================================================================

const REQUEST_TIMEOUT_HEADER: &str = "request-timeout";
const X_REQUEST_ID_HEADER: &str = "x-request-id";
const GH_REQUEST_ID_HEADER: &str = "x-github-request-id";

#[derive(Clone, Copy)]
enum Method {
    Get,
    Post,
    Delete,
}

/// One outbound HTTPS call's bookkeeping. `status` + `provider_req_id` +
/// `retry_after` are carried separately so the
/// `provider_call_done` breadcrumb can log them even when `result`
/// is an error, and so the 429-specific `RateLimited` error can
/// carry the server-suggested wait time.
struct ProviderCall<T> {
    status: u16,
    provider_req_id: Option<ProviderReqId>,
    retry_after: Option<Duration>,
    result: Result<T, GithubError>,
}

/// Borrowed view of a `ProviderCall`'s metadata passed into the
/// `map_with_meta` closure. Exists so `map_with_meta` callers can
/// build endpoint-specific errors (which need `status` + `retry_after`)
/// or success values that embed the upstream correlation id
/// (`provider_req_id`) without pre-destructuring the `ProviderCall` into
/// local variables — the smell `let status = call.status; let
/// retry_after = call.retry_after;` repeated at every previous use of
/// `map`.
struct CallMeta<'a> {
    status: u16,
    retry_after: Option<Duration>,
    provider_req_id: Option<&'a ProviderReqId>,
}

impl<T> ProviderCall<T> {
    /// Failure with no HTTP exchange (signing failed, builder
    /// rejected a header, etc.). The breadcrumb logs `status=0`
    /// and `provider_req_id=""`.
    fn pre_send(err: GithubError) -> Self {
        Self {
            status: 0,
            provider_req_id: None,
            retry_after: None,
            result: Err(err),
        }
    }

    /// Carry `status` + `provider_req_id` + `retry_after` forward while
    /// transforming the success payload. The closure receives a
    /// [`CallMeta`] borrow of the metadata so it can both branch on
    /// `status` and embed `provider_req_id` into a richer success type,
    /// without the caller having to pre-destructure the
    /// `ProviderCall`.
    fn map_with_meta<U>(
        self,
        f: impl FnOnce(T, CallMeta<'_>) -> Result<U, GithubError>,
    ) -> ProviderCall<U> {
        let ProviderCall {
            status,
            provider_req_id,
            retry_after,
            result,
        } = self;
        // Inner scope so the borrow of `provider_req_id` ends before we move
        // it into the output struct.
        let result = {
            let meta = CallMeta {
                status,
                retry_after,
                provider_req_id: provider_req_id.as_ref(),
            };
            result.and_then(|t| f(t, meta))
        };
        ProviderCall {
            status,
            provider_req_id,
            retry_after,
            result,
        }
    }
}

// ============================================================================
// JWT signing
// ============================================================================

const JWT_LEEWAY_PAST: u64 = 60;
const JWT_LIFETIME: u64 = 540;

#[derive(Serialize)]
struct JwtClaims {
    iss: String,
    iat: u64,
    exp: u64,
}

impl JwtClaims {
    fn new(now: SystemTime, client_id: &str) -> Self {
        let unix = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Self {
            iss: client_id.to_string(),
            iat: unix.saturating_sub(JWT_LEEWAY_PAST),
            exp: unix.saturating_add(JWT_LIFETIME),
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
    /// matches the configured one (`expected`). Returns the
    /// confirmed `client_id` on success so the caller can fold it
    /// into `SelfcheckData` without re-parsing.
    fn check_app_identity(body: &[u8], expected: &str) -> Result<String, GithubError> {
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
        Ok(app.client_id)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    fn owner(&self) -> &'a str {
        self.owner
    }

    fn repo(&self) -> &'a str {
        self.repo
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

    fn kind(&self) -> ProviderKind {
        ProviderKind::Github
    }

    async fn mint(&self, req_id: &ReqId, path: &str) -> Result<AbstractMintOutcome, ProviderError> {
        let data = GitHubProvider::mint(self, req_id, path).await?;
        Ok(AbstractMintOutcome {
            response: data.response,
            out_req_id: data.out_req_id,
            provider_req_id: data.provider_req_id,
        })
    }

    async fn selfcheck(&self, req_id: &ReqId) -> Result<AbstractSelfcheckOutcome, ProviderError> {
        let data = GitHubProvider::selfcheck(self, req_id).await?;
        Ok(AbstractSelfcheckOutcome {
            out_req_id: data.out_req_id,
            provider_req_id: data.provider_req_id,
            clock_skew_sec: data.clock_skew_sec,
            details: json!({
                "client_id": data.client_id,
                "installation_id": data.installation_id,
                "api_base": data.api_base,
            }),
        })
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
        let p = RepoPath::parse("octocat/Hello-World").unwrap();
        assert_eq!(p.owner(), "octocat");
        assert_eq!(p.repo(), "Hello-World");
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
}
