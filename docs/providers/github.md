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
selfcheck_timeout = "5s"             # required; tune to your p99 to api.github.com
# request_timeout = "10s"            # optional; default 10s
# user_agent = "symbolon"            # optional; default "symbolon"

# Signing backend — required, no default. See "App key custody" below.
app_key_backend = "file"
private_key_path = "/etc/symbolon/github-app.pem"
```

`host` is matched **byte-exact** against the `host=` field a git
credential helper sends. No suffix matching, no case-folding, no
default. See [`../PROTOCOLS.md`](../PROTOCOLS.md) § "Host dispatch".

## App key custody: `file` vs `tpm`

The App private key signs a short-lived JWT on every
metadata-token and mint call. **The daemon never holds it** —
`app_key_backend` selects where the RSA private key lives, and the
daemon signs through an opaque seam either way. Pick one; there is
no default and no runtime fallback.

### `file` — sandboxed signing subprocess

```toml
app_key_backend = "file"
private_key_path = "/etc/symbolon/github-app.pem"
```

At startup the daemon forks a tiny signing agent (a hidden
subcommand of the same binary) over a `SOCK_SEQPACKET` socketpair,
*before* it sandboxes itself. The agent reads the PEM, then locks
itself down: `mlockall` (key off swap), `PR_SET_DUMPABLE=0` (no core
dump can leak it), `PR_SET_PDEATHSIG` (dies with the daemon),
Landlock (the key path read-only, **no network**), and a seccomp
syscall allowlist (no `socket`/`connect`/`execve`/io_uring). It then
serves one signature per request and logs every sign to stderr →
journald — an **audit trail** the daemon can't forge. A compromised
daemon is reduced from *key theft* to a *logged, time-bounded
signing oracle*: it can request signatures while it is resident, but
it cannot exfiltrate the key or sign after it is killed, and every
request it made is in the agent's log. The agent reads the PEM once,
before it sandboxes itself, and holds no filesystem access afterward;
to rotate the key, restart the daemon.

This backend needs no special hardware and is the recommended
default for most deployments.

### `tpm` — sign in a vTPM

```toml
app_key_backend = "tpm"

[provider.github.tpm]
device = "/dev/tpmrm0"           # default; kernel resource-manager node
persistent_handle = 0x81010001   # pre-provisioned RSA-2048 signing key
```

The RSA private key is generated in / imported into a TPM and never
leaves it. The daemon computes SHA-256 of the JWS signing input in
Rust and sends only the 32-byte digest to the TPM via `TPM2_Sign`
(scheme RSASSA+SHA-256); the signature comes back and the daemon
assembles the JWT. A dedicated thread owns the device fd (opened
once, pre-sandbox — the sandbox never grants the device path).

Provision the key with `tpm2-tools` (owner hierarchy, unrestricted
RSA-2048 signing key, empty auth, evicted to a persistent handle):

```sh
# TCTI points at your TPM (e.g. a per-instance swtpm — see INSTALL.md)
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"

tpm2_createprimary -C o -G rsa2048 -c primary.ctx
# Import the GitHub App PEM as a child of the primary...
tpm2_import -C primary.ctx -G rsa -i github-app.pem -u key.pub -r key.priv
#   ...OR generate a fresh in-TPM key instead of importing:
# tpm2_create -C primary.ctx -G rsa2048 -u key.pub -r key.priv \
#     -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign"
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_evictcontrol -C o -c key.ctx 0x81010001
```

The key must be **unrestricted** (no `restricted` attribute) with
`sign` set and scheme `null` or `rsassa`, so `TPM2_Sign` accepts a
digest computed outside the TPM with a null hashcheck ticket. Empty
auth is deliberate — see "App-key threat model" below. After
importing, destroy or offline the PEM.

### App-key threat model

- **`tpm` mode**: a compromised daemon is a direct, *symbolon-
  unlogged* signing oracle for as long as it is resident (the vTPM
  signs whatever digest it's handed; io_uring further dilutes the
  daemon's own seccomp — an accepted trade). The key itself cannot be
  extracted. Compensating controls are GitHub-side: the JWT is valid
  ≤10 minutes, minted tokens are single-repo and short-TTL, and the
  App key can be revoked on github.com.
- **`file` mode**: the agent reduces daemon compromise from key theft
  to a *logged, time-bounded* oracle — strictly better observability
  than `tpm` (every sign is audited), at the cost of the key living
  in a (hardened) process rather than hardware.
- **vTPM is per-instance**: each container gets its own swtpm with a
  dedicated kernel `vtpm_proxy` device pair; there is no
  cross-container path. Empty TPM auth is deliberate — an authValue
  would only police *intra*-container access, which the device-node
  uid/mode already does, and host root can read any authValue
  regardless.
- **Host root is the root of trust** in both modes: the swtpm state
  directory (holding the wrapped key) and the PEM/agent both live
  under the instance's host-side storage. symbolon protects against a
  compromised *client* and a compromised *daemon*, not a compromised
  *host*.

## Commands

All commands accept the global `--config <path>` flag. Output is
JSON on stdout; errors are JSON on stderr; exit code is `0` on
success, `1` on any error.

```
symbolon github enroll <client> [--note <text>] [--psk <64-hex>]
    Generate (or accept via --psk) a 32-byte PSK, append it to
    the symbolon-owned `psks` file and `clients.json` (both
    atomic), and print:
      {"ok":true,"psk_hex":"<64 hex chars>"}
    The PSK is generated client-side by the CLI, then handed to
    the daemon — the daemon never sees raw entropy. The client's
    key file wants `broker_pub_hex:psk_hex` on one line, so
    combine with `symbolon pubkey` when provisioning, e.g.:
      PUB=$(symbolon pubkey | jq -r .broker_public_key)
      PSK=$(symbolon github enroll dev-vm-1 --note "lab box" | jq -r .psk_hex)
      echo "${PUB}:${PSK}" \
        | ssh dev-vm-1 'tee /etc/symbolon/key >/dev/null && chmod 0400 /etc/symbolon/key'
    Use --psk to bring your own pre-generated hex (key rotation,
    backup restore, deterministic test setups).

symbolon github revoke <client>
    Remove <client>'s entry from both the in-memory PSK store /
    clients table AND the on-disk `psks` / `clients.json` files
    (atomic). Subsequent connections from that identity log
    `evt=identity_unknown` and fail exactly like a wrong-PSK
    attempt (anti-enumeration; see PROTOCOLS.md).

    Outstanding tokens minted in the previous hour are NOT
    revoked. They live their full TTL; see § "Hard cutoff" below.

symbolon github mint <client> <owner/repo>
    Test path: run the full mint flow as if <client> requested a
    token for <owner/repo>. Prints:
      {"ok":true,
       "username":"x-access-token",
       "password":"<token>",
       "expires_at_unix":<u64>,
       "out_req_id":"<ULID>",
       "provider_req_id":"<X-GitHub-Request-Id or null>"}

symbolon github selfcheck
    Verify the signing backend is live (the agent responds / the
    TPM key reads back as RSA-2048), the App ID matches the JWT,
    api.github.com (or your GHES api_base) is reachable, and clock
    skew is bounded. Exit code `0` on success, `1` on any failed
    check. (The daemon also runs the backend's own self-check at
    startup and refuses to start if it fails.) Prints:
      {"ok":true,
       "clock_skew_sec":<i64>,
       "out_req_id":"<ULID>",
       "provider_req_id":"<X-GitHub-Request-Id or null>",
       "details":{<provider-specific diagnostic blob —
                   see § "Admin response shape: selfcheck details">}}
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
- Signing key: never in the daemon — held by the configured
  backend (a vTPM or a sandboxed subprocess). See "App key custody"
  above. To rotate: `file` mode requires a daemon restart (the agent
  reads the PEM once at startup); `tpm` mode re-provisions the
  persistent handle.
- Implementation: the RS256 JWS framing (`{"typ":"JWT","alg":
  "RS256"}` header, base64url segments) lives in
  `src/providers/jwt_rs256.rs`. The RSASSA-PKCS1-v1_5 signature
  itself is produced by the backend — the `file` agent via the `rsa`
  crate, the `tpm` backend via `TPM2_Sign` over a Rust-computed
  SHA-256 digest.

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

**No TTL — entries live for the process lifetime.** On any 404
from a subsequent `mint_token` call referring to a cached entry,
invalidate it; the next mint re-resolves. This handles the
delete-then-recreate-with-same-name case where the numeric ID
changes, and is the only invalidation path.

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

## Operator notes

### Branch protection interaction

Installation tokens are **not exempt from branch protection rules.**
A `git push` to a protected branch with "Require pull request before
merging" / "Require status checks" / signed-commits / etc. will be
rejected at the receive layer even though our token holds
`contents: write`. The error is server-side (HTTP 200 with a
git-protocol packet line containing `! [remote rejected] ...`) and
will surface to the operator as a normal git push failure — not as
a broker error.

Fix at the **App-installation level** (not in the broker): either
add the App to the branch protection rule's bypass list, or use a
deploy strategy that doesn't push directly to a protected branch
(open a PR via the API instead). The broker mints tokens; it does
not configure GitHub-side authorisation.

### Token revocation

The metadata-only installation token used during
`resolve_repo_id` is revoked via `DELETE /installation/token`
immediately after the repo-ID lookup completes. This shortens its
useful life from the natural 1-hour TTL to the duration of one
HTTP round-trip. The revoke call is best-effort: failures are
logged as `evt=provider_call_done` breadcrumbs but do not
propagate, because the caller has already consumed the token's
single use.

The **mint token** returned to the client is NOT revoked from the
broker side. The client holds it for the duration of its git
operation (clone, fetch, push); revoking it would break that
operation in flight. Its 1-hour TTL is the only bound. A client
that has finished can revoke its own token by calling
`DELETE /installation/token` itself — see the
[GitHub docs](https://docs.github.com/en/rest/apps/installations#revoke-an-installation-access-token).

## Manual smoke test before public release

The modern git-credential response shape (`authtype=Bearer` +
`credential=<token>` + `ephemeral=true`) relies on git constructing
`Authorization: Bearer <ghs_…>` for git-HTTP and GitHub's git-HTTP
frontend accepting that header form. GitHub's docs explicitly
document the `https://x-access-token:TOKEN@github.com/…` form;
Bearer-for-git-HTTP is undocumented but, given the underlying
auth backend, very likely works (the same token works for the
REST API as Bearer). Verify empirically before tagging a public
release:

```sh
# Prereqs:
# - A test GitHub App with installation on a private test repo,
#   `Contents: write` permission, your test-VM PSK enrolled.
# - git ≥ 2.46 on the test VM.
# - symbolon daemon running on broker host with the App
#   configured under `[provider.github]`.

# 1. Confirm git is new enough that it sends capability[]=authtype.
git --version    # must be ≥ 2.46

# 2. Drop the helper config on the client VM.
git config --global \
  credential.https://github.com.helper \
  "/usr/local/bin/git-credential-symbolon \
   --endpoint broker.lan:9418 \
   --identity test-vm \
   --key-file /etc/symbolon/key"
# Required so git sends `path=owner/repo` on credential queries —
# the broker mints per-repo and rejects the request as
# `malformed_request` without it.
git config --global credential.https://github.com.useHttpPath true

# 3. Clone — exercises the modern auth flow.
git clone https://github.com/<owner>/<repo>.git /tmp/sb-test
cd /tmp/sb-test

# 4. Make a trivial commit and push — exercises write auth.
echo "x" >> README.md
git -c user.name=test -c user.email=test@example test commit -am test
git push

# 5. Tail the broker logs and confirm:
journalctl -u symbolon -f
# Expected event sequence per mint:
#   evt=provider_call endpoint=mint_metadata_token
#   evt=provider_call_done status=201 ...
#   evt=provider_call endpoint=resolve_repo_id
#   evt=provider_call_done status=200 ...
#   evt=provider_call endpoint=revoke_install_token
#   evt=provider_call_done status=204 ...
#   evt=provider_call endpoint=mint_token
#   evt=provider_call_done status=201 ...
#   evt=mint provider=github.com repo=... ttl_sec=3599 ...

# 6. If clone/push fails with a 4xx from GitHub at the git-HTTP
#    layer, revert the modern shape:
#    - In src/git_credential.rs::write_response, force
#      `client_supports_authtype = false`.
#    - Add a regression note in this doc.
```

If push succeeds and the broker emits the expected event sequence,
the modern shape is good to ship.

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
