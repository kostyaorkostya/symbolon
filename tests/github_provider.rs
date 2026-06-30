//! GitHub provider tests: `GitHubProvider` against a `wiremock` server.
//!
//! wiremock runs a tokio runtime in a sidecar thread; the cyper
//! request loops in compio on the test thread; they meet over a
//! localhost TCP port.

mod common;

use std::time::UNIX_EPOCH;

use serde_json::json;
use symbolon::GithubError;
use wiremock::matchers::{body_bytes, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{
    EXPIRES_AT, METADATA_TOKEN, OWNER, REPO, REPO_ID, TOKEN, build_provider,
    build_provider_with_clock, canonical_metadata_token_body, canonical_mint_body, mint_path,
    mount_metadata_token_ok, mount_mint_ok, mount_repo_ok, past_clock, repo_path,
};

#[compio::test]
async fn mint_happy_path() {
    let server = MockServer::start().await;
    mount_repo_ok(&server).await;
    mount_mint_ok(&server).await;

    let provider = build_provider(server.uri()).await;
    let outcome = provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();

    assert_eq!(outcome.response.username, "x-access-token");
    assert_eq!(outcome.response.password, TOKEN);
    // The wiremock matcher on `body_bytes(canonical_mint_body())`
    // already proves the narrow mint POST carried REPO_ID; no need
    // to re-assert it on the outcome.
    let secs = outcome
        .response
        .password_expiry_utc
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // 2026-05-31T13:00:00Z = 1780232400
    assert_eq!(secs, 1_780_232_400);
}

#[compio::test]
async fn mint_uses_cached_repo_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(repo_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": REPO_ID})))
        .expect(1) // GET fires once: cache miss on the first mint, hit on the second.
        .mount(&server)
        .await;
    // Metadata-only token POST is part of the resolve flow only, so
    // it fires once (only on the cache-miss mint).
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .and(body_bytes(canonical_metadata_token_body()))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"token": "meta", "expires_at": EXPIRES_AT})),
        )
        .expect(1)
        .mount(&server)
        .await;
    // Narrow mint POST fires once per `mint()` call.
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .and(body_bytes(canonical_mint_body()))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"token": TOKEN, "expires_at": EXPIRES_AT})),
        )
        .expect(2)
        .mount(&server)
        .await;

    let provider = build_provider(server.uri()).await;
    provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();
    provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();
    // MockServer's drop verifies `.expect(N)` counts.
}

#[compio::test]
async fn mint_uses_cached_token() {
    let server = MockServer::start().await;
    // Repo resolve fires once (first mint only; second hits token cache).
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .and(body_bytes(canonical_metadata_token_body()))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"token": METADATA_TOKEN, "expires_at": EXPIRES_AT})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(repo_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": REPO_ID})))
        .expect(1)
        .mount(&server)
        .await;
    // Narrow mint fires once; the second `mint()` call hits the token cache.
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .and(body_bytes(canonical_mint_body()))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"token": TOKEN, "expires_at": EXPIRES_AT})),
        )
        .expect(1)
        .mount(&server)
        .await;

    // `past_clock` returns Unix 1_000_000_000 (year 2001), making
    // EXPIRES_AT ("2026-05-31T13:00:00Z", Unix 1_780_232_400) appear
    // to be in the future so the token cache holds the entry.
    let provider = build_provider_with_clock(server.uri(), past_clock).await;
    let o1 = provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();
    let o2 = provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();
    assert_eq!(o1.response.password, TOKEN);
    assert_eq!(o2.response.password, TOKEN);
    // MockServer drop verifies all three `.expect(1)` counts.
}

#[compio::test]
async fn mint_request_headers_and_body_exact() {
    use wiremock::matchers::header_exists;
    let server = MockServer::start().await;
    mount_metadata_token_ok(&server).await;
    mount_repo_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .and(header("accept", "application/vnd.github+json"))
        .and(header("x-github-api-version", "2026-03-10"))
        .and(header("user-agent", "symbolon"))
        .and(header("content-type", "application/json"))
        // x-request-id is a per-call ULID; just assert presence
        // (per-call value is non-deterministic).
        .and(header_exists("x-request-id"))
        // request-timeout is derived from the per-call timeout (10s
        // for mint per test fixture).
        .and(header("request-timeout", "10"))
        .and(body_bytes(canonical_mint_body()))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"token": TOKEN, "expires_at": EXPIRES_AT})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(server.uri()).await;
    provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();
}

#[compio::test]
async fn mint_surfaces_github_request_id() {
    let server = MockServer::start().await;
    mount_repo_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("x-github-request-id", "ABC:DEF:1234")
                .set_body_json(json!({"token": TOKEN, "expires_at": EXPIRES_AT})),
        )
        .mount(&server)
        .await;

    let provider = build_provider(server.uri()).await;
    let outcome = provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();
    assert_eq!(
        outcome.provider_req_id.as_ref().map(|p| p.as_str()),
        Some("ABC:DEF:1234")
    );
    assert!(
        !outcome.out_req_id.as_str().is_empty(),
        "out_req_id should be a ULID"
    );
}

#[compio::test]
async fn resolve_returns_404() {
    let server = MockServer::start().await;
    // Metadata-only token mint must succeed so the resolve flow
    // reaches the `GET /repos/...` call we want to test.
    mount_metadata_token_ok(&server).await;
    Mock::given(method("GET"))
        .and(path(repo_path()))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let provider = build_provider(server.uri()).await;
    let err = provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap_err();
    assert!(matches!(err, GithubError::RepoNotFound));
}

#[compio::test]
async fn mint_returns_401() {
    let server = MockServer::start().await;
    mount_repo_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let provider = build_provider(server.uri()).await;
    assert!(matches!(
        provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap_err(),
        GithubError::Unauthorized { .. }
    ));
}

#[compio::test]
async fn mint_returns_403() {
    let server = MockServer::start().await;
    mount_repo_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let provider = build_provider(server.uri()).await;
    assert!(matches!(
        provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap_err(),
        GithubError::Forbidden { .. }
    ));
}

#[compio::test]
async fn mint_returns_429() {
    let server = MockServer::start().await;
    mount_repo_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;

    let provider = build_provider(server.uri()).await;
    assert!(matches!(
        provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap_err(),
        GithubError::RateLimited { retry_after: None }
    ));
}

#[compio::test]
async fn mint_returns_429_with_retry_after() {
    let server = MockServer::start().await;
    mount_metadata_token_ok(&server).await;
    mount_repo_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "42"))
        .mount(&server)
        .await;

    let provider = build_provider(server.uri()).await;
    let err = provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap_err();
    assert!(matches!(
        err,
        GithubError::RateLimited {
            retry_after: Some(d),
        } if d == std::time::Duration::from_secs(42),
    ));
}

#[compio::test]
async fn mint_calls_revoke_after_resolve() {
    // After resolve_repo_id finishes (success path), the metadata
    // installation token is revoked via DELETE /installation/token.
    // wiremock's `.expect(1)` panics on drop if the count doesn't
    // match, so this asserts the call happened exactly once.
    let server = MockServer::start().await;
    mount_metadata_token_ok(&server).await;
    mount_repo_ok(&server).await;
    mount_mint_ok(&server).await;
    Mock::given(method("DELETE"))
        .and(path("/installation/token"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let provider = build_provider(server.uri()).await;
    let _ = provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();
    // Verifications happen on MockServer drop.
}

#[compio::test]
async fn mint_returns_500() {
    let server = MockServer::start().await;
    mount_repo_ok(&server).await;
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let provider = build_provider(server.uri()).await;
    assert!(matches!(
        provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap_err(),
        GithubError::OtherStatus(500)
    ));
}

#[compio::test]
async fn mint_invalidates_on_404() {
    let server = MockServer::start().await;

    // GET fires twice across phases 1 and 3 (cache miss → fill,
    // narrow-mint 404 invalidates → re-resolve). Phase 2 hits the
    // cache and skips the GET.
    Mock::given(method("GET"))
        .and(path(repo_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": REPO_ID})))
        .expect(2)
        .mount(&server)
        .await;

    // Metadata-only token POST fires whenever a GET fires (same
    // pre-condition: the resolve path runs). So 2 calls.
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .and(body_bytes(canonical_metadata_token_body()))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"token": "meta", "expires_at": EXPIRES_AT})),
        )
        .expect(2)
        .mount(&server)
        .await;

    // Phase 1: narrow mint succeeds.
    let first_narrow = Mock::given(method("POST"))
        .and(path(mint_path()))
        .and(body_bytes(canonical_mint_body()))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"token": TOKEN, "expires_at": EXPIRES_AT})),
        )
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    let provider = build_provider(server.uri()).await;
    provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();

    drop(first_narrow);

    // Phase 2: narrow mint 404s (repo deleted/recreated). Cache is
    // hit, so no GET / no metadata POST this round.
    let second_narrow = Mock::given(method("POST"))
        .and(path(mint_path()))
        .and(body_bytes(canonical_mint_body()))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    let err = provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap_err();
    assert!(matches!(err, GithubError::RepoNotFound));

    drop(second_narrow);

    // Phase 3: narrow mint succeeds. The phase-2 404 invalidated the
    // cache, so this triggers a fresh resolve (metadata POST + GET +
    // narrow POST).
    Mock::given(method("POST"))
        .and(path(mint_path()))
        .and(body_bytes(canonical_mint_body()))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"token": TOKEN, "expires_at": EXPIRES_AT})),
        )
        .expect(1)
        .mount(&server)
        .await;

    provider.mint(&format!("{OWNER}/{REPO}")).await.unwrap();
    // Drop of `server` at end of test verifies all `.expect(N)` counts.
}
