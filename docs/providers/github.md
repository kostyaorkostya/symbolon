# GitHub provider

Everything specific to the GitHub provider. Cross-provider
core lives in [`../ARCHITECTURE.md`](../ARCHITECTURE.md),
[`../PROTOCOLS.md`](../PROTOCOLS.md), and
[`../PROVIDER_CONTRACT.md`](../PROVIDER_CONTRACT.md) (see its
"How GitHub satisfies the contract" section for the per-clause
mapping). Deploy: [`../INSTALL.md`](../INSTALL.md). Operate:
[`../OPERATIONS.md`](../OPERATIONS.md).

Tested against `github.com`. GitHub Enterprise Server should work
on the same code path (same API surface) but CI doesn't exercise it.

## Per-mint guarantees

These are the bounds a compromised client can hit when this provider
is in use. They follow from how the broker uses GitHub's APIs, not
from operator policy.

- **Token TTL ≤ 1 hour.** The lifetime of a GitHub installation
  access token. Outstanding tokens are not revocable by the broker;
  `symbolon github revoke` only stops future mints.
- **Single repository per token.** Every mint passes
  `repository_ids: [<one>]`. The token can act on that one repo,
  not the others the App installation reaches.
- **`contents: write` + `metadata: read`, nothing else.** Fixed at
  mint time. `Workflows`, `Issues`, `Pull requests`, `Actions`,
  secrets: all unrequested and therefore unavailable to the
  minted token even if the App was granted them
  installation-side.

The `Workflows`-not-granted property is the load-bearing reason a
compromised client cannot push changes to
`.github/workflows/*.yml`: GitHub rejects those pushes server-side
when the token lacks `Workflows: write`.

## Create the GitHub App

On github.com:

1. Settings → Developer settings → GitHub Apps → **New GitHub App**.
2. Permissions:
   - **Contents: Read & Write**
   - **Metadata: Read** (mandatory floor for any App)
   - **Nothing else.** Do NOT add `Workflows`, `Actions`,
     `Pull requests`, `Issues`, or anything else. The absence of
     `Workflows` is the property that prevents a compromised
     client from pushing CI changes.
3. Webhook: disable. The broker does not consume webhooks.
4. Where can this App be installed? **Only on this account.**
5. Generate a private key; download the `.pem` file.
6. Install the App on your account. Note the **Client ID** (a
   string like `Iv23liABCDEFGHIJklmn`, listed alongside the App ID
   on the settings page) and the **installation ID** (visible in
   the URL after installation, e.g. `/installations/789012`). The
   broker uses the Client ID as the JWT `iss` claim, which is
   GitHub's currently-recommended form per
   [Generating a JWT for a GitHub App][gh-jwt].
7. Choose **Only select repositories** and pick the ones you want
   the broker to mint for. This is the working set; keep it small.

For GitHub Enterprise Server: the same steps apply on your GHES
instance. The Client ID and installation ID will differ from any
public github.com Apps.

## Config block

In `/etc/symbolon/config.toml`:

```toml
[provider.github]
# For github.com, keep these defaults.
# For GitHub Enterprise Server, set:
#   host     = "github.example.com"
#   api_base = "https://github.example.com/api/v3"
host = "github.com"
api_base = "https://api.github.com"
client_id = "Iv23liABCDEFGHIJklmn"   # App settings page
installation_id = 789012             # /installations/<id> URL
private_key_path = "/etc/symbolon/github-app.pem"
selfcheck_timeout = "5s"             # required; tune to your p99 to api.github.com
# request_timeout = "10s"            # optional; default 10s
# user_agent = "symbolon"            # optional; default "symbolon"
```

`host` is matched **byte-exact** against the `host=` field a git
credential helper sends. No suffix matching, no case-folding, no
default. See [`../PROTOCOLS.md`](../PROTOCOLS.md) § "Host dispatch".

## Commands

```
symbolon github enroll <client> [--note <text>]
    Generate a per-client 32-byte PSK, append to the symbolon-owned
    `psks` file and `clients.json` (both atomic), and print a
    paste-ready provisioning snippet to stdout.

symbolon github revoke <client>
    Remove the client's GitHub enrollment. If the client has no
    remaining provider enrollments, also remove it from
    `clients.json` and `psks`.

    Outstanding tokens minted in the previous hour are NOT
    revoked. They live their full TTL; see § "Hard cutoff" below.

symbolon github mint <client> <owner/repo>
    Test path: run the full mint flow as if <client> requested a
    token for <owner/repo>. Prints token + expiry to stdout.

symbolon github selfcheck
    Verify the App private key parses, the App ID matches the
    JWT, api.github.com (or your GHES api_base) is reachable, and
    clock skew is bounded. Exits non-zero on any failed check.
```

## Outbound API contract

References: [REST API for App installations][gh-installs],
[Installation access tokens][gh-iat], [App permissions][gh-perms],
[JWT (RFC 7519)](https://www.rfc-editor.org/rfc/rfc7519).

[gh-installs]: https://docs.github.com/en/rest/apps/installations
[gh-iat]: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app
[gh-perms]: https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app
[gh-jwt]: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app#about-json-web-tokens-jwts

### App JWT signing (RS256)

- `iss`: App Client ID (e.g. `Iv23liABCDEFGHIJklmn`). GitHub
  accepts either the numeric App ID or the Client ID; we use the
  Client ID because it is stable across App ownership transfers.
- `iat`: now − 60 s (clock-skew tolerance).
- `exp`: now + 540 s (9 minutes; GitHub max is 10).
- Signing key: PEM at `provider.github.private_key_path`, loaded
  once at daemon startup, held in memory. To rotate: restart the
  daemon.
- Implementation: in-tree RS256 signer at
  `src/providers/jwt_rs256.rs` (RSASSA-PKCS1-v1_5 with SHA-256),
  built on the `rsa` and `sha2` crates.

### Repository-ID resolution + cache

The App JWT only authenticates App-level endpoints (`/app`,
`/app/installations/...`); it cannot authenticate
`GET /repos/{owner}/{repo}`. Resolution is a two-step flow per
cache miss:

1. `POST /app/installations/{installation_id}/access_tokens` with
   body `{"permissions":{"metadata":"read"}}` (no
   `repository_ids`) using the App JWT. Yields a metadata-only
   installation token. Logged as
   `provider_call endpoint=mint_metadata_token`.
2. `GET {api_base}/repos/{owner}/{repo}` with that installation
   token as bearer. Returns `{id, ...}`. Logged as
   `provider_call endpoint=resolve_repo_id`.

In-memory cache keyed by `(provider_name, owner/repo)`
(case-insensitive for `owner/repo`). Cache hits skip both steps
and go straight to `mint_token`.

**TTL: 600 seconds per entry.** On any 404 from a subsequent
`mint_token` call referring to a cached entry, invalidate it; the
next mint re-resolves. This handles the delete-then-recreate-
with-same-name case where the numeric ID changes.

### Token mint

- `POST {api_base}/app/installations/{installation_id}/access_tokens`
- Headers:
  - `Authorization: Bearer <jwt>`
  - `Accept: application/vnd.github+json`
  - `X-GitHub-Api-Version: <current>`
  - `User-Agent: <provider.github.user_agent>`. Defaults to
    `symbolon` if unset; configurable. Required by GitHub
    (missing UA returns 403). Carries no version number so an
    attacker can't narrow the applicable CVE list.
  - `X-Request-ID: <out_req_id>`. Fresh ULID per outbound call.
    Same value flows into the `provider_call` /
    `provider_call_done` breadcrumbs and into the abstract
    `MintOutcome` / `SelfcheckOutcome` for operator-side
    correlation.
  - `Request-Timeout: <seconds>`. Best-effort hint per the
    expired IETF draft (`draft-thomson-hybi-http-timeout`).
    Integer seconds derived from the per-call timeout. GitHub
    does not document honouring it; any intermediate proxy that
    follows the draft (e.g. envoy) might. Cost is one header.
- Body:
  ```json
  {
    "repository_ids": [<numeric_repo_id>],
    "permissions": { "contents": "write", "metadata": "read" }
  }
  ```
- Response: `201 Created` with `{token, expires_at}`. Surface 4xx
  as `evt=mint_denied provider_status=<code>`; surface 5xx as
  `evt=provider_error`.

Response headers (read on every call): `X-GitHub-Request-Id` is
captured into the abstract `provider_req_id` field on the
outcome and on the `provider_call_done` breadcrumb so an
operator can join the broker's log to GitHub's side when filing
a ticket. The field name is shared with other providers so
cross-provider log queries stay simple; the value here is
GitHub-specific.

## Admin response shape: selfcheck `details`

`SelfcheckOutcome.details` for this provider is:

```json
{
  "client_id": "Iv23liXXXXXXXXXXXXXX",
  "installation_id": 789012,
  "api_base": "https://api.github.com"
}
```

The CLI's `symbolon github selfcheck` reads these from
`response["details"]` (per the provider-shape convention in
[`PROVIDER_CONTRACT.md` § A3](../PROVIDER_CONTRACT.md#a3-provider-specific-selfcheck-details)).

## Hardening recommendations

The per-mint scoping above is the narrowest GitHub will issue for
a push-capable token. Within that scope, a compromised token can
still manage releases (create, edit, delete release records,
replace release assets, move release tags). These can be mitigated
on the GitHub side without changing the broker.

### Enable Immutable Releases (per repository)

Settings → General → Releases → **Enable release immutability**.

Once enabled, every release published from that point forward is
immutable: assets cannot be added, modified, or deleted, and the
release's tag is locked to its publication commit. Existing
releases remain mutable unless re-published. Release attestations
(Sigstore-signed) are generated automatically; consumers can
verify with `gh release verify <tag>` or
`gh release verify-asset <tag> <file>`.

Available on all GitHub plans including Free. See the
[official documentation](https://docs.github.com/en/enterprise-cloud@latest/code-security/concepts/supply-chain-security/immutable-releases).

### Restrict creation of release tags (per repository)

Settings → Rules → New ruleset → **New tag ruleset**.

- **Target tags**: pattern matching your release tags (e.g. `v*`).
- **Bypass list**: keep `Repository admin` only. Do NOT add the
  broker's GitHub App.
- **Tag rules**: enable **Restrict creations**, **Restrict
  updates**, **Restrict deletions**, and **Block force pushes**.

The broker's tokens act as the App identity, not as the repository
admin, so they cannot create, update, or delete tags matching the
release pattern. Legitimate release tagging continues to work from
contexts that authenticate as the admin (your local clone, a
GitHub Actions workflow, etc.).

Combined with Immutable Releases above, this closes both the
release-asset-tampering vector (existing releases) and the
rogue-release-creation vector (new releases) on the GitHub side.

#### Plan-tier caveat

Repository rulesets are enforced on:
- Any **public** repository (all plans, including Free).
- **Private** repositories on GitHub Pro, Team, or Enterprise
  Cloud.

On Free accounts, rulesets created on **private** repositories
save successfully and appear in the UI, but are not enforced;
GitHub shows a banner indicating this.

## Hard cutoff

`symbolon github revoke <client>` removes the client's PSK so the
client can't request more tokens, but it does not revoke the
≤1-hour tokens already minted. For a hard cutoff:

- **Remove the repository from the App's access set on
  github.com.** Prevents new mints for that repo from anywhere,
  but does not revoke outstanding tokens.
- **Regenerate the App private key on github.com.** Revokes the
  App's ability to issue new tokens entirely; existing minted
  tokens still live their TTL. Then update
  `/etc/symbolon/github-app.pem` on the broker and **restart the
  daemon**. The App key is loaded at startup and is not
  hot-reloadable.

## References

- [REST API for App installations](https://docs.github.com/en/rest/apps/installations)
- [Generating an installation access token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)
- [Choosing permissions for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app)
- [Generating a JWT for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app#about-json-web-tokens-jwts)
- [Immutable Releases (Enterprise Cloud)](https://docs.github.com/en/enterprise-cloud@latest/code-security/concepts/supply-chain-security/immutable-releases)
