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

- `argh` (derive-based argv parser used by `src/main.rs`. Picked over
  `clap` for code-size and over hand-rolled parsing for maintainability.
  Daemon mode is preserved on bare `gcb` by synthesising a hidden
  `daemon` subcommand in `main`; everything else is regular argh.)
- `compio` with features `runtime,macros,net,fs,signal,time,io-uring`
  (async runtime; `macros` for `#[compio::main]`; `net`+`fs`+`signal`+
  `time` for the daemon surface; `io-uring` listed explicitly so a
  future change to compio's default features can't silently disable it)
- `cyper` (HTTPS client for provider APIs)
- `jsonwebtoken` with feature `rust_crypto` (App JWT; `rust_crypto`
  is mandatory in 10.x — without a crypto-provider feature the
  crate panics at sign-time. `rust_crypto` over `aws_lc_rs` keeps
  the musl build pure-Rust with no C FFI.)
- `landlock` (Linux LSM sandboxing for FS + TCP-connect + abstract-UDS
  scope at ABI 6. Applied in `src/sandbox.rs` after both Unix-domain
  sockets are bound and before the accept loop; gated by `[security]
  sandbox` in `config.toml` with default `best_effort`. Pure Rust +
  `libc` only; works on musl. Used together with `seccompiler` —
  landlock cannot enable `Scope::Signal` because the daemon must keep
  SIGHUP-ing stunnel, which lives in a separate process tree.)
- `libc` (raw syscall numbers and signal constants for the
  `seccompiler` BPF filter; transitively required by landlock and
  seccompiler anyway, so the explicit dep adds no surface.)
- `sd-notify` (pure-Rust `sd_notify(READY=1)` so `Type=notify`
  systemd units mark the service active when `src/ready.rs::notify`
  fires. No-op outside systemd. Daemon code never imports this —
  only `src/ready.rs` does, and `src/ready.rs` is called from
  `src/main.rs`.)
- `seccompiler` (Firecracker's pure-Rust seccomp-BPF compiler. The
  filter built in `src/sandbox.rs` returns `EPERM` for every
  `kill`/`tkill`/`tgkill`/`pidfd_send_signal`/`rt_sigqueueinfo`/
  `rt_tgsigqueueinfo` whose signum argument isn't `SIGHUP`.
  Substitutes for landlock's `Scope::Signal` while preserving
  the legitimate SIGHUP-to-stunnel path.)
- `serde`, `serde_json`, `toml` (config + provider responses)
- `time` with `default-features = false, features = ["parsing",
  "formatting"]` (RFC3339 → `SystemTime` for GitHub's `expires_at`,
  RFC2822 for the HTTP `Date` header in selfcheck, and RFC3339
  rendering of `enrolled_at` on enroll plus the `ts` field in JSON
  log lines). Defaults disabled to strip the surface we don't use.
- `tracing`, `tracing-subscriber` (JSON logging; custom
  `FormatEvent` in `src/main.rs` renames `timestamp`/`level` to
  `ts`/`lvl` per PROTOCOLS.md).
- `futures-util` (`select!` and `FutureExt::fuse()` for the
  accept-vs-signal race in `daemon::run`; compio's own examples
  pull it in the same way — see compio-0.18 `examples/tick.rs`).
- `ulid` (request IDs)
- `thiserror` (errors)
- `rustix` with feature `process` (signal delivery to stunnel via
  `kill(2)` after enroll/revoke rewrites `gcb.psk`; also used for
  the `Signal::HUP`/`Signal::INT`/`Signal::TERM` raw values handed
  to `compio_signal::unix::signal`)

Do not add, remove, or swap crates without asking. Versions are locked
via `Cargo.lock`. `rust-toolchain.toml` pins the compiler.

### Resolving dependency versions

Use `cargo` to look up and add crate versions; **do not use WebFetch
for crates.io or any crate metadata**. `cargo` resolves the latest
compatible version against the existing lock file, writes correct
semver, and works in environments where outbound HTTPS is restricted
to the registry path. WebFetch is neither necessary nor reliable for
this and may fail in sandboxed environments.

- `cargo add <crate>` — adds the latest compatible version to
  `Cargo.toml` and updates `Cargo.lock`. Use `cargo add <crate>@<req>`
  to pin to a specific version.
- `cargo search <crate>` — inspect available versions if needed.

Never hand-edit version strings in `Cargo.toml` from guessed values.
Let `cargo add` write them, then commit `Cargo.lock`.

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
- Default to no comments. Add a doc comment only when the *why* or the
  contract isn't obvious from the name and signature — hidden
  invariants, surprising edge cases, security-load-bearing rules (e.g.
  the CR/LF rejection in `git_credential`). Don't restate what
  well-named code already says.

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
  errors.rs            # crate-wide error composition (stub; deferred)
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
- **Emergency offline state mutation.** Operator commands talk to
  the admin socket of a running daemon. No CLI path that mutates
  `clients.json` or `gcb.psk` directly.
- **App-key hot reload.** Restart the daemon to pick up a new key.
- **`provider_error` `endpoint` / `body_snippet` fields.**
  PROTOCOLS.md lists them in the logging schema; the daemon does
  not emit them yet. Adding `body_snippet` requires a redaction
  layer (provider responses can carry tokens on 5xx); doing this
  safely is its own task.
- **TTL-driven `evt=cache_invalidated`.** Only 404-driven
  invalidation fires the event today. TTL expiry is silently
  re-resolved; the provider doesn't currently surface "I just
  dropped an expired entry" to the daemon.
- **Multiple instances of the same provider** (e.g. github.com +
  github.example.com on one broker). Section name `[provider.X]` is
  also the dispatch key; introduce a `kind` field if/when needed.
- **Async DNS via `hickory-resolver`.** Tokio-coupled
  ([hickory-dns issue #2142](https://github.com/hickory-dns/hickory-dns/issues/2142)
  + multiple users-forum threads confirm no compio/async-std
  backend exists). AGENTS.md hard-NOTs tokio. The sandbox allowlist
  therefore continues to include the six nameservice files
  (`/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`,
  `/etc/host.conf`, `/etc/gai.conf`, `/etc/services`) for libc
  `getaddrinfo`. Reopen when either (a) hickory ships a runtime-
  agnostic mode, (b) a compio-native DNS crate appears on crates.io,
  or (c) operator need is concrete enough to justify hand-rolling a
  tiny UDP stub resolver on `compio-net` (~150–250 LOC, A/AAAA
  only). DoT/DoH are out of scope for our threat model regardless —
  see PROTOCOLS.md for the rationale.
- **Socket activation via `listen-fds` / `listenfd`.** systemd can
  hand pre-bound sockets to the daemon; would eliminate our own
  `UnixListener::bind` step under systemd. Real lifecycle redesign,
  deferred.
- **DNS re-resolution under IP rotation.** cyper's connection pool
  caches established TLS connections; when GitHub's IPs rotate, a
  pooled connection eventually fails, we surface `evt=provider_error`,
  and the next mint opens a fresh connection with a fresh DNS
  lookup. At our traffic (<<1 mint/s) the natural failure/retry
  cycle covers IP rotation — no proactive resolver work needed.
  High-mint-rate deployments would want a connection-lifetime cap.