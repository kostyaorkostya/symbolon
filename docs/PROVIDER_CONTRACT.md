# Provider contract

The contract any `symbolon` provider implementation satisfies.
Read this before adding a provider. RFC-2119 normative language.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for how the broker uses
providers, and the existing GitHub provider in
[`providers/github.md`](providers/github.md) plus
`src/providers/github.rs` for a worked example.

## Status

The abstraction is **implicit** in the codebase today
(`src/providers/mod.rs` is a one-line module that re-exports the
single `github` provider). This document defines the contract a
provider satisfies; landing a second provider is what will
crystallise it into a Rust trait. The rules here apply now
(GitHub satisfies them by construction); they bind any future
provider too.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**,
and **MAY** in this document are to be interpreted as described
in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Scope

A "provider" is the broker's adapter to one external system that
issues short-lived git credentials (a GitHub App, a GitLab token
issuer, etc.). One provider type per `[provider.<name>]` section
of `config.toml`; one provider identity per (broker, provider)
per AGENTS.md invariant #1.

The provider is responsible for:

- Loading the provider-specific private key at startup.
- Authenticating against the provider's API.
- Resolving a repository identifier from a git-credential request
  if the provider requires it.
- Minting a short-lived, single-repository token.
- A selfcheck that proves "the configured identity can reach the
  provider's API right now."

Everything else (transport, identity, sandboxing, state storage,
logging, observability) is the broker's responsibility and the
provider MUST NOT replicate or override it.

## MUST

### M1. Per-mint scope is a single repository

Every token-issuing call to the provider MUST be scoped to
exactly one repository: the one the git-credential request
named. No "all repos" tokens, no "multiple repos at once"
tokens. The on-the-wire encoding is provider-specific (e.g.
GitHub's `repository_ids: [<one>]`) but the cardinality MUST be
one.

### M2. Permission set is hard-coded

The permission set the provider requests at mint time MUST be
hard-coded in `src/providers/<name>.rs`. It MUST be the minimum
the provider accepts for `git push` + `git clone` against a
single repo. Operators MUST NOT be able to configure it through
`config.toml` or any other surface. Widening the set requires a
code change and an explicit AGENTS.md instruction.

### M3. Provider key is immutable post-startup

The provider private key (PEM file or equivalent) MUST be loaded
once at daemon startup, before the sandbox is applied. The
provider MUST NOT re-read the key from disk at runtime; the
sandbox makes that path unreachable on purpose. To rotate, the
operator restarts the daemon.

### M4. Selfcheck

The provider MUST expose a `selfcheck(req_id)` operation that
makes a real HTTPS call to the provider's API and verifies:

- The provider key parses and signs whatever auth artefact the
  provider needs.
- The provider's API is reachable on `api_base`.
- (Where the API surfaces it) clock skew is within a reasonable
  bound.

Selfcheck MUST exit non-zero / return `Err` on any failed check.
It runs once at startup and on demand via the CLI.

### M5. Outbound HTTPS only on port 443

The provider MUST make all outbound calls to its API over HTTPS
on port 443. Other ports are blocked by the Landlock ruleset
(see [`ARCHITECTURE.md` § Sandbox model](ARCHITECTURE.md#sandbox-model)).
Use of any other port requires changing the broker's sandbox
allowlist and is a design change, not a provider concern.

### M6. Error envelope safety

Any 4xx response body the provider surfaces in error messages
MUST be parsed for the provider's safe error envelope (e.g.
`{"message": "..."}`) or truncated, and MUST NOT include
response bodies that could carry tokens (typically only 2xx mint
responses; provider implementations route those through a
separate code path that drops the body before any logging). See
the `JsonParse` variant of `GithubError` for the pattern: the
serde error source is dropped to avoid leaking a fragment of a
2xx mint response.

### M7. Observable per-call

Every outbound HTTPS call MUST emit a `provider_call` breadcrumb
before the call and a `provider_call_done` breadcrumb after, with
`req_id`, `out_req_id` (a ULID), `endpoint` (a short string label),
and `elapsed_ms`. See
[`PROTOCOLS.md` § Logging schema](PROTOCOLS.md#logging-schema).
The provider MAY add a per-provider correlation ID (e.g. GitHub's
`X-GitHub-Request-Id` becomes the `gh_req_id` field), but the
core breadcrumb pair is mandatory.

## SHOULD

### S1. Singleflight repo-ID cache (when applicable)

If the provider requires a separate API call to resolve a
human-readable repo name to a stable internal ID before minting,
the provider SHOULD cache the result keyed by
`(provider_name, owner/repo)` with a bounded TTL (10 minutes is
fine), AND singleflight concurrent resolves for the same key.
This avoids duplicating an idempotent lookup under burst traffic.
The GitHub provider uses `synchrony::sync::event::Event` for the
single-flight wake; future providers SHOULD reuse that primitive
unless there is a specific reason not to.

### S2. 404 → cache invalidation

If a cache (per S1) is in use, a 404 on a later mint that
referenced a cached entry SHOULD invalidate the entry so the
next mint re-resolves. Handles delete-then-recreate-with-same-name
on the provider side where the internal ID changes.

### S3. Cancel-token propagation

Every long-await in the provider's HTTPS path SHOULD race the
shared `CancelToken` (see `Service::shutdown` in
`src/daemon.rs`). On token fire, the call SHOULD return promptly
with `GithubError::Cancelled` / equivalent rather than blocking
the daemon drain.

## MAY

### A1. Provider-specific config sub-keys

The provider MAY define `[provider.<name>]` sub-keys beyond the
common ones (`host`, `api_base`, `private_key_path`,
`selfcheck_timeout`, `request_timeout`). Document any additional
keys in the provider's doc under [`providers/`](providers/).

### A2. Provider-specific error variants

The provider's error enum MAY have arbitrarily many variants
beyond the common HTTP-status-derived ones (Unauthorized,
Forbidden, RateLimited, ServerError, UnexpectedStatus,
RepoNotFound, Timeout, Cancelled). Provider-specific variants
SHOULD be documented in `providers/<name>.md`.

### A3. Provider-specific correlation IDs

The provider MAY add provider-specific fields to the
`provider_call_done` breadcrumb (e.g. `gh_req_id` from GitHub's
`X-GitHub-Request-Id` header). Such fields are non-standard
across providers; consumers of the logs (jq queries, dashboards)
should treat them as optional.

## FORBIDDEN

### F1. Broker-side allowlists

A provider MUST NOT consult a broker-side per-repo allowlist
before minting. Per AGENTS.md invariant #3: the broker mints for
any repo the configured provider identity can reach. The
"accessible-repo set" is managed externally on the provider's
web UI.

### F2. In-repo policy files

A provider MUST NOT read or honour any in-repo policy file (no
`.github/symbolon.yaml`, no Octo-STS-style trust files, no
`SYMBOLON-trusted-pushers.txt`). Per AGENTS.md "Hard NOTs": no
in-repo policy.

### F3. Webhook consumption

A provider MUST NOT register or consume provider-side webhooks.
The broker has no inbound HTTP surface for webhooks; provider
identity / permission changes are detected on-demand by
`selfcheck` only.

### F4. Permission widening

A provider's mint call MUST NOT request permissions broader than
the hard-coded set (M2). A provider MUST NOT request "all repos"
tokens (M1). A provider MUST NOT issue tokens with no `exp` or
with `exp` beyond the provider's documented maximum.

### F5. Persistent token storage

A provider MUST NOT persist minted tokens anywhere. Every mint is
fresh; the daemon writes the token straight back through the
Noise transport and forgets it.

### F6. SSH transport

A provider MUST NOT issue or interact with SSH keys for the
client. The broker's transport to the client is Noise NNpsk0
over TCP; SSH is a hard NOT per AGENTS.md.

## How GitHub satisfies the contract

See [`providers/github.md` § Per-mint guarantees](providers/github.md#per-mint-guarantees)
for the GitHub-specific bindings. In summary:

- M1: `repository_ids: [<one>]` in the access-tokens POST body.
- M2: `permissions: {contents: write, metadata: read}`, hard-coded
  in `src/providers/github.rs::build_mint_body`. Operators
  cannot configure it. `Workflows` is intentionally not granted.
- M3: PEM key loaded by `GitHubProvider::load_key` before the
  sandbox closes; no re-read.
- M4: `symbolon github selfcheck` calls `GET /app` and asserts
  the App ID matches the configured Client ID.
- M5: All outbound to `api.github.com:443`; the Landlock ruleset
  allows TCP-connect to 443 only.
- M6: `parse_github_error_body` extracts the `message` from
  GitHub's 4xx envelope (or truncates raw text); `JsonParse`
  deliberately drops its serde source so mint 2xx fragments
  cannot leak.
- M7: `with_breadcrumbs` wraps every HTTPS call with
  `provider_call` / `provider_call_done`. `gh_req_id` (A3) is
  the GitHub-specific correlation field.
- S1: `RepoIdCache` in `src/providers/github.rs`, 600 s TTL,
  `synchrony::sync::event::Event` for singleflight.
- S2: `RepoIdCache::invalidate` on a 404 from `mint_token`.
- S3: `with_breadcrumbs` races `self.cancel.wait().fuse()` for
  every call.
