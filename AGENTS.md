# AGENTS.md: `symbolon`, the git credentials broker

*Symbolon* (σύμβολον): in Ancient Greek, an object broken in two
halves; each party kept one, and matching them proved identity.
Fits a daemon that authenticates clients by PSK and hands them
short-lived, single-repository git credentials.

Single source of truth for design decisions and conventions. Read it top
to bottom before writing or modifying code. If anything here conflicts
with an ad-hoc instruction in chat, ask before deviating.

Detail lives in sibling documents:
- How the system works: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Wire formats, file schemas, logging schema, daemon lifecycle:
  [`docs/PROTOCOLS.md`](docs/PROTOCOLS.md)
- RFC-2119 contract for providers:
  [`docs/PROVIDER_CONTRACT.md`](docs/PROVIDER_CONTRACT.md)
- Operator commands, logging recipes, troubleshooting:
  [`docs/OPERATIONS.md`](docs/OPERATIONS.md)
- Deployment: [`docs/INSTALL.md`](docs/INSTALL.md)
- Per-provider setup, guarantees, outbound API contracts,
  hardening: [`docs/providers/`](docs/providers/)
- Authoritative URLs: [`docs/REFERENCES.md`](docs/REFERENCES.md)

### Where does a statement go?

Single decision rule for all doc edits: **if a statement would
still be true when a second provider lands (GitLab, Gitea,
Forgejo), it belongs in the generic docs (README, ARCHITECTURE,
PROTOCOLS, PROVIDER_CONTRACT, OPERATIONS, INSTALL). If swapping
providers would falsify it, it belongs in
`docs/providers/<name>.md`.** Apply this rule to every paragraph
you add or move.

## Purpose

`symbolon` is a Rust daemon that mints short-lived, single-repository git
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
publishes binaries with sha256 attestations. The workflow:

1. Sets `CARGO_BUILD_RUSTFLAGS` with `--remap-path-scope=all` +
   `--remap-path-prefix` entries derived from `$HOME` and
   `$GITHUB_WORKSPACE`, so released binaries carry no runner
   filesystem paths in their tracing callsite metadata.
2. Builds via `cargo zigbuild` (zig provides the cross C
   toolchain for musl).
3. Post-strips `.eh_frame` / `.eh_frame_hdr` /
   `.gcc_except_table` (safe with `panic = "abort"`; saves
   ~390 KB).
4. Hands each target's binaries+sha256s to a single downstream
   `release` job via `actions/upload-artifact`. The release job
   downloads everything and makes ONE `softprops/action-gh-release`
   call. The matrix legs never touch the release surface. That's
   what avoids the "Cannot upload assets to an immutable release"
   race when two parallel runners both try to create + publish the
   same tag on an Immutable Releases-enabled repo.

To reproduce a shipping-shaped local artefact (with the same
path-trim and post-strip applied), use the in-tree helper:

```
./scripts/release-build.sh                            # x86_64-musl
./scripts/release-build.sh aarch64-unknown-linux-musl
```

The script uses `$HOME` + `git rev-parse --show-toplevel`, so it
works for any user with no hardcoded paths in the repo.

Bare `cargo zigbuild --release --locked --target <triple>` (no
script) also works and is what AGENTS expects you to be able to
invoke; the resulting binary just won't have the path-trim
applied. Dev binaries aren't shipped, so this is fine.

## Threat model

Primary threat: a client is compromised (malicious supply-chain
dependency pulled at build time; agentic coding tool induced to read
or execute; untrusted code on disk). The broker is the trust
boundary; it holds the provider private key. Client compromise must
not enable: pivot to other repos on the account, modification of CI
workflow files, secret reads, or anything outside the configured
provider's permission set. Acceptable residual: up to the
provider-specific token TTL of token use against repos already
accessible to the configured provider identity. The concrete TTL
and permission set per provider live in `docs/providers/<name>.md`.

## Architectural invariants (do not relitigate)

1. **One provider identity per (broker, provider).** No per-project
   Apps. No org-only features.
2. **Accessible-repo set is managed externally** (provider's web UI).
   The broker does not call any add-repo-to-installation endpoint.
3. **No broker-side allowlist.** The broker mints for any repo the
   configured provider identity can reach. Per-mint scoping (next
   item) keeps blast radius narrow.
4. **Per-mint scoping is mandatory.** Every mint requests exactly
   one repository plus the minimum permission set the provider
   accepts for `git push` / `git clone`. Never broader. The exact
   on-the-wire encoding is provider-specific and lives in
   `docs/providers/<name>.md`. Normative form:
   [`docs/PROVIDER_CONTRACT.md` § M1, M2](docs/PROVIDER_CONTRACT.md#must).
5. **Provider permissions are immutable per provider.** The
   broker requests one fixed permission set per provider, hard-
   coded in `src/providers/<name>.rs`. Operators do not configure
   it. The required-vs-forbidden-vs-rejected set per provider
   lives in `docs/providers/<name>.md`. Normative form:
   [`docs/PROVIDER_CONTRACT.md` § M2, F4](docs/PROVIDER_CONTRACT.md).
6. **Transport: Noise NNpsk0 over TCP, terminated in-process** via
   the [`snow`](https://github.com/mcginty/snow) crate. The daemon
   listens directly on TCP (default `:9418`) and runs the responder
   side of `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` against the PSK
   selected by the client's identity prelude. Clients use the
   bundled `git-credential-symbolon` helper to run the matching
   initiator. No TLS at any layer (preserves the no-TLS hard NOT).
7. **Identity: PSK identity from the Noise handshake.** The client
   emits a small unencrypted identity prelude (`magic | version |
   identity_len | identity`) before the handshake; the broker looks
   up the PSK for that identity in its in-memory store and runs
   Noise. Handshake completion is the identity proof. The source IP
   is not used for identity at any point (DHCP-friendly); it is
   logged as audit metadata only.
8. **State is files.** `clients.json` + `psks` only, both owned and
   atomically rewritten by the daemon (tempfile + fsync + rename +
   fsync parent).
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
14. **Secrets stay off disk.** In-process defence:
    `mlockall(MCL_CURRENT|MCL_FUTURE)` at startup
    (`src/mlock.rs`) prevents pages reaching swap; controlled
    by `[security] mlock = required | best_effort (default) |
    off`. `MCL_ONFAULT` is deliberately NOT used. Deferred
    locks under finite `RLIMIT_MEMLOCK` create a footgun where
    `status=applied` is logged and the process then aborts at
    the first allocation that exceeds the limit. Pre-faulting
    surfaces rlimit failures at the mlockall call (current
    pages) or at the offending allocation (future pages),
    never at an unpredictable later page fault. Operator-side
    complements (per docs/INSTALL.md): disable swap on the
    broker host, and set `LimitCORE=0` in the systemd unit so
    coredumps can't leak page contents via dump files.

## Hard NOTs

- No `tokio`, `async-std`, `smol`. `compio` only.
- No HTTP server framework (`axum`, `cyper-axum`). Plain TCP via
  `compio-net`.
- No direct use of TLS crates. `rustls` enters our binary via
  `cyper`'s `rustls` feature (which we explicitly enable; see
  Dependencies) and the crypto provider (`ring`) via `compio`'s
  `ring` feature. We never `use rustls::...` or `use ring::...`
  in our own code.
- No database. State is files.
- No in-repo policy files (no Octo-STS, no `.github/*.yaml` trust).
- No SSH transport for clients.
- No additional provider permissions beyond invariant #5. Expanding
  requires an explicit operator instruction.

## Dependencies

Pinned in `Cargo.toml`:

- `argh` (derive-based argv parser used by `src/main.rs`. Picked over
  `clap` for code-size and over hand-rolled parsing for maintainability.
  All subcommands (`daemon`, `status`, `list`, `github …`) are regular
  argh subcommands; bare `symbolon` prints help and exits non-zero.)
- `compio` with features `runtime,macros,net,fs,time,io-uring,ring`
  (async runtime; `macros` for `#[compio::main]`; `net`+`fs`+`time`
  for the daemon surface; `io-uring` listed explicitly so a future
  change to compio's default features can't silently disable it.
  `ring` selects the rustls crypto provider via `compio-tls/ring`.
  Without it `cyper`'s `rustls` feature alone leaves rustls
  unable to pick a provider at runtime and the first HTTPS call
  panics. The `signal` feature is intentionally NOT enabled; we
  use signal-hook-registry directly for permanent signal handlers;
  see `src/signals.rs`.)
- `cyper` with `default-features = false, features = ["rustls",
  "http2"]` (HTTPS client for provider APIs. We turn off cyper's
  `native-tls` default to keep the binary OpenSSL-free under musl,
  and explicitly opt in to rustls. Pure Rust, ALPN-driven h2 over
  TLS so a keep-alive connection from a preceding resolve call is
  reused for the follow-up mint without a fresh handshake. The
  crypto provider (`ring`) is enabled via the `compio` dep above.)
- `rsa` with `default-features = false, features = ["pem", "std",
  "u64_digit"]` + `sha2` (with `oid` feature) + `base64`. The
  trio underneath `src/providers/jwt_rs256.rs`, our minimal RS256
  signer. The explicit rsa feature list matches its current
  defaults but is spelled out so future contributors see the
  audit: `pem` for PKCS#8 / PKCS#1 parsing, `std` for the
  digest/signature trait `std` glue, `u64_digit` for the 64-bit
  num-bigint backend (~2× faster RSA-2048 sign on x86_64/aarch64).
  Replaces `jsonwebtoken`, whose monolithic `Algorithm` enum kept
  ed25519-dalek / curve25519-dalek / p256 / p384 / hmac in the
  binary even though we only call RS256; the linker can't prove
  the unused enum arms unreachable. Byte-equivalence with the
  prior jsonwebtoken output is pinned by
  `tests::known_vector_matches_jsonwebtoken_baseline`. RSASSA-
  PKCS1-v1_5 with SHA-256 is one of the most thoroughly specified
  JOSE algorithms; the actual signing is a single `rsa::SigningKey`
  call.
- `hex` (encode/decode for the per-line PSK file format in
  `src/psk_store.rs`, the enroll output's `psk_hex` field in
  `src/admin.rs`, and the client binary's PSK file load in
  `src/bin/git_credential_symbolon.rs`. Pure-Rust, zero runtime
  deps, dual MIT/Apache. Replaces three hand-rolled hex codecs.)
- `landlock` (Linux LSM sandboxing at ABI 6: FS allowlist +
  outbound TCP-connect to port 443 + abstract-UDS scope +
  `Scope::Signal` (Linux 6.12+) denying cross-domain
  signal-sending. Applied in
  `src/sandbox.rs` after the TCP listen socket + admin Unix
  socket are bound and before the accept loops; gated by
  `[security] sandbox` in `config.toml` with default
  `best_effort`. Pure Rust + `libc` only; works on musl.
  Intra-process signals (panic handlers, libc `abort()`,
  thread-local plumbing) remain permitted; that is correct,
  since the threat surface worth blocking is *cross-process*
  signal attacks from a compromised broker.)
- `libc` (the `mlockall(MCL_CURRENT | MCL_FUTURE)` call in
  `src/mlock.rs`. Transitively required by landlock anyway,
  so the explicit dep adds no surface.)
- `sd-notify` (pure-Rust `sd_notify(READY=1)` so `Type=notify`
  systemd units mark the service active when `src/ready.rs::notify`
  fires. No-op outside systemd. Daemon code never imports this;
  only `src/ready.rs` does, and `src/ready.rs` is called from
  `src/main.rs`.)
- `snow` with `default-features = false, features =
  ["default-resolver", "use-chacha20poly1305", "use-blake2",
  "use-curve25519", "use-getrandom", "std"]` (pure-Rust Noise
  Protocol Framework implementation; tracks Noise spec rev 34,
  forbids `unsafe_code` internally. Drives `Noise_NNpsk0_25519_
  ChaChaPoly_BLAKE2s` in `src/transport.rs` (responder side in
  the daemon, initiator side in the `git-credential-symbolon`
  client binary). Feature trim drops aes-gcm / sha2 /
  blake3 / p256 / pqcrypto since our pattern uses only
  ChaCha20-Poly1305 + BLAKE2s + X25519.)
- `serde`, `serde_json`, `toml` (config + provider responses)
- `time` with `default-features = false, features = ["parsing",
  "formatting"]` (RFC3339 → `SystemTime` for GitHub's `expires_at`,
  RFC2822 for the HTTP `Date` header in selfcheck, and RFC3339
  rendering of `enrolled_at` on enroll). Defaults disabled to
  strip the surface we don't use.
- `tracing` with `default-features = false, features = ["std",
  "release_max_level_info"]`. `release_max_level_info` compiles
  out every `debug!` / `trace!` callsite in our code and our
  deps from release builds; in particular, h2 and rustls are
  heavily instrumented at those levels and gating them saves
  measurable `.rodata` + `.text` weight at no functional cost
  since we never log below info in production. `attributes` is
  dropped because we don't use `#[instrument]` anywhere.
- `tracing-subscriber` with `default-features = false, features =
  ["fmt", "json", "registry", "std"]` (structured JSON logging
  via the built-in `fmt::Json` formatter; configured in
  `src/logging.rs` with `flatten_event(true)` so user-added fields
  like `evt` and `req_id` appear as top-level JSON keys. The
  defaults `ansi` (terminal colours we don't use) + `tracing-log`
  (log→tracing bridge. No dep emits `log::` events for us
  because rustls's `logging` feature is off) + `smallvec` are
  trimmed.)
- `futures-util` (`select!` and `FutureExt::fuse()` for the
  accept-vs-signal race in `daemon::run`; compio's own examples
  pull it in the same way. See compio-0.18 `examples/tick.rs`).
- `futures-channel` (`oneshot` for the result hand-back in
  `src/cpu_worker.rs`; the dedicated OS thread sends the
  computed value back to the awaiting compio task.)
- `base64` (URL-safe-no-pad encoding in `src/providers/jwt_rs256.rs`
  for the JWT header / payload / signature segments. Listed as a
  top-level dep so the audit surface is explicit.)
- `ulid` (request IDs)
- `thiserror` (errors)
- `rustix` with features `net,process`. `process` for `geteuid` on
  the admin path (used by the SO_PEERCRED gate in `admin.rs`).
  `net` for `socket_peercred` on the admin UDS, the SO_PEERCRED
  check that rejects connections from UIDs other than root or
  the daemon's own (defense in depth against a loose
  `/run/symbolon/` ACL).
- `signal-hook-registry` (long-lived OS-level signal handler
  installed once at startup. Replaces `compio::signal::unix::signal`
  which is one-shot and reverts the kernel disposition to `SigDfl`
  on listener drop. A SIGHUP delivered in that gap would kill the
  daemon. We register synchronous handlers per signal that set an
  AtomicBool + call `AtomicWaker::wake` on a `SignalNotifier` struct;
  the compio task loop awaits a re-armable `Notified` future. Both
  the AtomicBool store and the AtomicWaker wake are lock-free,
  alloc-free, reentrant, and async-signal-safe; the handler matches
  compio-signal's internal handler at
  `compio/compio-signal/src/unix/mod.rs:15-26` but with a permanent
  rather than per-call registration.)
- `synchrony` with features `async_flag,event` (sync primitives for
  `compio`. `sync::event::Event` is the re-armable wakeup used by
  `ConnectionTracker`'s "drain empty" notification and by the
  singleflight cache in `providers::github`. The signal-handler
  notifier uses raw `AtomicBool` + `futures_util::task::AtomicWaker`
  directly rather than `AsyncFlag` because `AsyncFlag::wait` is
  consume-on-wait, which doesn't fit the permanent handler loop.
  `async_flag` feature stays enabled because synchrony co-builds
  the two primitives.)
- `percent-encoding` (URL component encoding for the owner/repo
  segments of GitHub API paths. The path parser already rejects
  any byte outside `[A-Za-z0-9._-]`; the encoding is defense in
  depth so a future char-class regression cannot become a URL
  injection.)
- `url` (parse `api_base` to extract its host string once at
  provider construction. The same-origin redirect policy on
  `cyper::ClientBuilder` compares `attempt.url().host_str()`
  against the cached api host so a redirect can never carry the
  App JWT off-domain.)
- `humantime-serde` (TOML-string parsing for `Duration` fields like
  `selfcheck_timeout = "5s"` / `request_timeout = "10s"`. Tiny,
  pulls only `humantime`. Avoids the `_secs: u64` code smell where
  the unit had to leak into the field name.)
- `thin-cell` (one-word `Rc<RefCell<T>>` replacement from the
  compio-rs ecosystem, used for `ConnectionTracker.active`. A
  shared counter across tracker and per-handler closures. Same
  API shape as `Rc<RefCell<T>>`; one pointer instead of two.)

Do not add, remove, or swap crates without asking. Versions are locked
via `Cargo.lock`. `rust-toolchain.toml` pins the compiler.

### Resolving dependency versions

Use `cargo` to look up and add crate versions; **do not use WebFetch
for crates.io or any crate metadata**. `cargo` resolves the latest
compatible version against the existing lock file, writes correct
semver, and works in environments where outbound HTTPS is restricted
to the registry path. WebFetch is neither necessary nor reliable for
this and may fail in sandboxed environments.

- `cargo add <crate>`: adds the latest compatible version to
  `Cargo.toml` and updates `Cargo.lock`. Use `cargo add <crate>@<req>`
  to pin to a specific version.
- `cargo search <crate>`: inspect available versions if needed.

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
- Default to no comments. Add a doc comment only when the *why* or
  the contract isn't obvious from the name and signature: hidden
  invariants, surprising edge cases, security-load-bearing rules
  (e.g. the CR/LF rejection in `git_credential`). Don't restate what
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
  main.rs              # daemon entry; dispatches daemon vs CLI subcommands
  bin/
    git_credential_symbolon.rs  # client-side git-credential helper
  lib.rs               # crate-level docs, pub re-exports
  config.rs            # config.toml + clients.json parsing
  connection_tracker.rs# spawn / drain abstraction for accept loops
  cpu_worker.rs        # Dedicated OS thread for CPU-bound work
  git_credential.rs    # protocol parse/emit; CR/LF rejection mandatory
  transport.rs         # Noise NNpsk0 wrapper + identity prelude + framing
  psk_store.rs         # in-memory identity → PSK store, file-backed
  daemon.rs            # TCP accept loop, per-connection Noise handler, Service shape
  admin.rs             # admin Unix socket + CLI dispatch (enroll/revoke/etc.)
  signals.rs           # signal-hook-registry handlers → CancelToken
  ready.rs             # sd_notify + pidfile (atomic) at startup
  loader.rs            # async config/clients.json file reads
  logging.rs           # tracing-subscriber JSON setup (stdout/stderr split)
  sandbox.rs           # landlock (FS + TCP + UDS scope + signal scope)
  providers/
    mod.rs             # Provider abstraction (lightweight)
    github.rs          # GitHub: JWT, repo-ID singleflight cache, mint
tests/
  integration.rs       # wiremock-rs against provider APIs
fuzz/                  # cargo-fuzz subproject (nightly-pinned)
  fuzz_targets/        # parser harnesses (security tooling)
```

## Concurrency notes

Compio uses **cooperative scheduling**: tasks only yield at `.await`
points. A long CPU-bound section without an `.await` blocks the
single-threaded compio runtime and starves every other task. This
is the same model Tokio uses (Tokio mitigates with per-task
operation budgets. Compio doesn't ship that yet).

Goroutines differ: Go's runtime preempts via compile-time yield-
point injection. Rust async can't, because the language doesn't
expose that hook to executors. See
[Tokio: Reducing tail latencies with automatic cooperative task yielding](https://tokio.rs/blog/2020-04-preemption)
and [Async Rust: Cooperative vs Preemptive scheduling](https://kerkour.com/cooperative-vs-preemptive-scheduling).

For CPU work, two options:

- **Dedicated always-on thread** via the project-wide primitive
  `crate::cpu_worker::CpuWorker`. Use when the work is recurring
  and small (microseconds of communication overhead per call, no
  thread-spawn churn). Construct as
  `let worker = CpuWorker::new("descriptive-thread-name")?;` then
  `worker.run(move || do_cpu_work()).await?`. The in-tree example
  is `src/providers/github.rs::JwtSigner`, which holds an
  `Arc<EncodingKey>` and dispatches each `sign_jwt_blocking` call
  to a `symbolon-jwt-signer`-named worker thread.
- **`compio::runtime::spawn_blocking(f)`** for one-off CPU bursts.
  Compio's pool lazily spawns up to 256 threads, 60 s idle reap.
  Good fit when work is occasional; bad fit for high-frequency
  recurring work (re-spawn cost dominates after each idle reap).

For long-but-async work, sprinkle explicit yield points via
`compio_runtime`'s yield helpers (tokio's analogue is
`tokio::task::yield_now().await`).

## Security tooling

**Miri** is not used. The codebase has exactly one `unsafe` block
(in a `src/sandbox.rs` test calling `libc::kill`); production code
is entirely safe Rust where Miri has nothing to find. Compio's
io_uring backend additionally cannot run under Miri (no shim for
the submission/completion queue model), so the codebase's
`#[compio::test]` tests would be unrunnable regardless. Skipping miri.

**Fuzzing** is set up for the two parsers that consume attacker-
controlled bytes:

- `symbolon::parse_identity_prelude`: the unencrypted prelude
  bytes the client sends before the Noise handshake. Identity
  selection depends on it (AGENTS.md invariant #7).
- `symbolon::git_credential::parse`: git-credential request block
  (decrypted out of the Noise transport before parsing); carries
  the CR/LF Clone2Leak defence (AGENTS.md invariant #12).

Fuzz targets live under `fuzz/fuzz_targets/`. The `fuzz/` subproject
pins nightly via its own `rust-toolchain.toml`; the main project
stays on stable. Run ad-hoc:

```sh
cargo install cargo-fuzz   # one-shot, no project change
cd fuzz
cargo fuzz run git_credential_parse -- -max_total_time=600
cargo fuzz run identity_prelude_parse -- -max_total_time=600
```

(The `+nightly` switch isn't needed because `fuzz/rust-toolchain.toml`
pins it.) The 10-minute budget is a baseline; longer runs find
more. libFuzzer writes any crashing input to
`fuzz/artifacts/<target>/` and exits non-zero. To reproduce:

```sh
cd fuzz
cargo fuzz run git_credential_parse \
  artifacts/git_credential_parse/<artifact-name>
```

No CI integration today. Operator runs fuzz on demand.

## Out of scope (deferred)

Known omissions, not oversights:

- **Mint coalescing.** Concurrent mints for the same repo each call
  the provider API. Acceptable at homelab traffic; revisit if it
  changes.
- **Metrics endpoint** (Prometheus / OpenMetrics). Logs are the
  observability surface today. Add when there's a consumer.
- **Webhook handling.** No live notification when the provider's
  permission grants change provider-side; per-provider selfcheck
  commands (e.g. `symbolon github selfcheck`) are the on-demand
  check.
- **Emergency offline state mutation.** Operator commands talk to
  the admin socket of a running daemon. No CLI path that mutates
  `clients.json` or `/var/lib/symbolon/psks` directly.
- **Provider-key hot reload.** Restart the daemon to pick up a
  new key.
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
  therefore continues to include the nameservice files libc's
  `getaddrinfo` actually reads, selected at compile time via
  `cfg(target_env = "musl")` in `src/daemon.rs::nameservice_files`.
  musl reads `/etc/resolv.conf` and `/etc/hosts` only; glibc also
  reads `/etc/nsswitch.conf` and `/etc/gai.conf`. The musl release
  binary's ruleset therefore omits the two glibc-only files.
  Reopen when either (a) hickory ships a runtime-agnostic mode,
  (b) a compio-native DNS crate appears on crates.io, or (c)
  operator need is concrete enough to justify hand-rolling a tiny
  UDP stub resolver on `compio-net` (~150–250 LOC, A/AAAA only).
  DoT/DoH are out of scope for our threat model regardless. See
  PROTOCOLS.md for the rationale.
- **Socket activation via `listen-fds` / `listenfd`.** systemd can
  hand pre-bound sockets to the daemon; would eliminate our own
  `UnixListener::bind` step under systemd. Real lifecycle redesign,
  deferred.
- **DNS re-resolution under IP rotation.** cyper's connection pool
  caches established TLS connections; when GitHub's IPs rotate, a
  pooled connection eventually fails, we surface `evt=provider_error`,
  and the next mint opens a fresh connection with a fresh DNS
  lookup. At our traffic (<<1 mint/s) the natural failure/retry
  cycle covers IP rotation. No proactive resolver work needed.
  High-mint-rate deployments would want a connection-lifetime cap.
- **Per-read buffer reuse.** Both `src/daemon.rs::read_exact_n` and
  `src/admin.rs::read_line` allocate a fresh `Vec` per read
  iteration. Apache iggy reuses a `BytesMut::with_capacity` via
  `.clear()` across iterations (see
  `iggy/core/server/src/tcp/connection_handler.rs`). Compio also
  offers `AsyncReadManaged` + `BufferPool` via io-uring's managed-
  buffer support. At our traffic (<<1 mint/s) per-read allocation
  cost is invisible relative to network RTT; revisit only if
  profiling shows allocation in the critical path.