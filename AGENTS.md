# AGENTS.md — `gcb`, the git credentials broker

Single source of truth for design decisions and conventions. Read it top
to bottom before writing or modifying code. If anything here conflicts
with an ad-hoc instruction in chat, ask before deviating.

Detail lives in sibling documents:
- Wire formats, file schemas, logging schema, daemon lifecycle:
  [`docs/PROTOCOLS.md`](docs/PROTOCOLS.md)
- Operator commands, logging recipes, troubleshooting:
  [`docs/OPERATIONS.md`](docs/OPERATIONS.md)
- Deployment: [`docs/INSTALL.md`](docs/INSTALL.md)
- Authoritative URLs: [`docs/REFERENCES.md`](docs/REFERENCES.md)

## Purpose

`gcb` is a Rust daemon that mints short-lived, single-repository git
credentials on demand. Currently implements **GitHub** via GitHub App
installation tokens. Structured to add other providers (e.g. GitLab) by
dropping a new module under `src/providers/` and a new `[provider.X]`
config section. Optimized for trusted-network homelab deployment;
assumes source-IP attestation comes from the surrounding environment
(e.g. [libvirt `clean-traffic`](https://libvirt.org/firewall.html)).

## Commands

```
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo zigbuild --release --locked --target x86_64-unknown-linux-musl
cargo zigbuild --release --locked --target aarch64-unknown-linux-musl
```

Release: `git tag v0.1.0 && git push --tags` triggers
`.github/workflows/release.yml`, which builds both musl targets and
publishes binaries with sha256 attestations.

## Threat model

Primary threat: a client is compromised (malicious supply-chain
dependency pulled at build time; agentic coding tool induced to read or
execute; untrusted code on disk). The broker is the trust boundary; it
holds provider private keys. Client compromise must not enable: pivot
to other repos on the account, modification of CI workflow files,
secret reads, or anything outside the App's configured permissions.
Acceptable residual: up to 1 hour of token use against repos already
accessible to the App.

## Architectural invariants (do not relitigate)

1. **One provider identity per (broker, provider).** No per-project
   Apps. No org-only features.
2. **Accessible-repo set is managed externally** (provider's web UI).
   The broker does not call any add-repo-to-installation endpoint.
3. **No broker-side allowlist.** The broker mints for any repo the
   configured provider identity can reach. Per-mint scoping (next
   item) keeps blast radius narrow.
4. **Per-mint scoping is mandatory.** Every mint passes
   `repository_ids: [single_repo_id]` and
   `permissions: {contents: write, metadata: read}`. Never broader.
5. **App permissions are immutable.** Contents R/W + Metadata R only.
   `Workflows` MUST NOT be granted; its absence prevents a compromised
   client from pushing CI changes.
6. **Transport: TLS-PSK via [stunnel](https://www.stunnel.org/).**
   stunnel terminates the client connection and forwards plain TCP
   over a Unix-domain socket with a
   [PROXY protocol v2](https://www.haproxy.org/download/2.4/doc/proxy-protocol.txt)
   header. The daemon never speaks TLS itself.
7. **Identity: source IP, attested upstream.** The daemon trusts the
   source IP in the PROXY v2 header and resolves it via
   `clients.json`. stunnel does not forward the PSK identity in a
   PROXY TLV, so the daemon cannot cross-check stunnel's PSK auth
   against the IP-resolved name. The upstream IP attestation is
   load-bearing — if it fails, attribution can be wrong (PSK auth
   still gates access).
8. **State is files.** `clients.json` + `gcb.psk` only, written
   atomically (tempfile + fsync + rename + fsync parent).
9. **Admin surface = Unix-domain socket.** No HTTP admin endpoints.
10. **Daemon is the sole writer** of state files. CLI commands talk
    to the daemon via the admin socket; the daemon serializes them.
    Therefore no file locks are required.
11. **Host dispatch is byte-exact.** `host=` in a git-credential
    request must match a configured `[provider.X].host` exactly.
    No suffix matching, no case-folding, no default.
12. **The git-credential parser rejects CR/LF inside values.**
    Defends against the Clone2Leak class (CVE-2024-52006,
    CVE-2024-50338, CVE-2025-23040). See PROTOCOLS.md for the
    exact rule.
13. **Logging: structured JSON to stdout** (warn/error to stderr).
    The operator routes from there.

## Hard NOTs

- No `tokio`, `async-std`, `smol`. `compio` only.
- No HTTP server framework (`axum`, `cyper-axum`). Plain TCP via
  `compio-net`.
- No direct use of TLS crates. `rustls` enters our binary
  transitively via `cyper` for HTTPS to provider APIs; we never
  `use rustls::...`.
- No database. State is files.
- No in-repo policy files (no Octo-STS, no `.github/*.yaml` trust).
- No SSH transport for clients.
- No additional provider permissions beyond invariant #5. Expanding
  requires an explicit operator instruction.

## Dependencies

Pinned in `Cargo.toml`:

- `compio` (runtime + net)
- `cyper` (HTTPS client for provider APIs)
- `jsonwebtoken` (App JWT)
- `serde`, `serde_json`, `toml` (config + provider responses)
- `tracing`, `tracing-subscriber` (JSON logging)
- `ulid` (request IDs)
- `thiserror` (errors)

Do not add, remove, or swap crates without asking. Versions are locked
via `Cargo.lock`. `rust-toolchain.toml` pins the compiler.

Release profile: `opt-level = "z"`, `lto = "fat"`,
`codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`.

## Style guide

[Rust Style Guide](https://doc.rust-lang.org/style-guide/) (`rustfmt`
default). [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
for API design.

Addenda:
- No `unwrap()` outside `#[cfg(test)]`. Use `?`, explicit `match`, or
  `expect("<reason>")` where panic is provably unreachable.
- No `panic!` in library code. Binaries may panic at startup for
  unrecoverable config errors only.
- `thiserror` for library error types (one enum per module,
  `<Module>Error`). `anyhow` only at the binary's `main` boundary.
- No `#[allow(...)]` without an explanatory comment.
- Default visibility is `pub(crate)`. Only `lib.rs` re-exports `pub`.
- Doc comments on every public item.
- Inline comments explain non-obvious choices.

## Diagnostic discipline (mandatory)

- **Diagnose before fixing.** State the cause: "Symptom X is caused
  by Y. Fix is Z." A reviewer should be able to verify the chain.
  "Symptom seems to be Y; let's try Z" is not acceptable beyond a
  one-line typo.
- **Symptom is truth.** A clean build, a clean `strace`, and a "fix
  that looks reasonable" are not evidence. The only evidence is the
  original symptom not recurring under the original workload.
- **Search before improvising.** Re-read AGENTS.md, PROTOCOLS.md,
  REFERENCES.md, the relevant crate docs, then reason.
- **Don't extrapolate from one observation.** State the
  preconditions when generalizing.
- **Run before speculating.** `cargo doc --open`, `cargo expand`,
  `journalctl`, small test programs beat reasoning about what
  should be.
- **Read crate docs before inventing signatures.**

## Module layout

```
src/
  main.rs              # entry; dispatches daemon vs CLI vs subcommands
  lib.rs               # crate-level docs, pub re-exports
  config.rs            # config.toml + clients.json parsing
  git_credential.rs    # protocol parse/emit; CR/LF rejection mandatory
  proxy_protocol.rs    # PROXY v2 parsing
  daemon.rs            # accept loop, per-connection handler, signal handling
  admin.rs             # Unix socket + CLI dispatch
  errors.rs            # crate-wide error composition
  providers/
    mod.rs             # Provider abstraction (lightweight)
    github.rs          # GitHub: JWT, repo-ID resolve, mint
tests/
  integration.rs       # wiremock-rs against provider APIs
```

## Out of scope (deferred)

Known omissions, not oversights:

- **Mint coalescing.** Concurrent mints for the same repo each call
  the provider API. Acceptable at homelab traffic; revisit if it
  changes.
- **Metrics endpoint** (Prometheus / OpenMetrics). Logs are the
  observability surface today. Add when there's a consumer.
- **Webhook handling.** No live notification when the App's
  permissions change provider-side; `gcb github selfcheck` is the
  on-demand check.
- **CLI without daemon.** Operator commands require a running
  daemon. No emergency offline state mutation.
- **App-key hot reload.** Restart the daemon to pick up a new key.
- **Multiple instances of the same provider** (e.g. github.com +
  github.example.com on one broker). Section name `[provider.X]` is
  also the dispatch key; introduce a `kind` field if/when needed.