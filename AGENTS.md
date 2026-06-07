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
  rendering of `enrolled_at` on enroll). Defaults disabled to
  strip the surface we don't use.
- `tracing`, `tracing-subscriber` with `features = ["json"]`
  (structured JSON logging via the built-in `fmt::Json`
  formatter; configured in `src/logging.rs` with
  `flatten_event(true)` so user-added fields like `evt` and
  `req_id` appear as top-level JSON keys).
- `futures-util` (`select!` and `FutureExt::fuse()` for the
  accept-vs-signal race in `daemon::run`; compio's own examples
  pull it in the same way — see compio-0.18 `examples/tick.rs`).
- `ulid` (request IDs)
- `thiserror` (errors)
- `rustix` with features `net,process`. `process` for signal
  delivery to stunnel via `kill(2)` after enroll/revoke rewrites
  `gcb.psk`. `net` for `socket_peercred` on the admin UDS — the
  SO_PEERCRED check that rejects connections from UIDs other than
  root or the daemon's own (defense in depth against a loose
  `/run/gcb/` ACL).
- `signal-hook-registry` (long-lived OS-level signal handler
  installed once at startup. Replaces `compio::signal::unix::signal`
  which is one-shot and reverts the kernel disposition to `SigDfl`
  on listener drop — a SIGHUP delivered in that gap would kill the
  daemon. We register synchronous handlers per signal that set an
  AtomicBool + notify an `event_listener::Event`; the compio task
  loop awaits the Event re-armably. Same pattern compio-signal uses
  internally, just with a permanent handler.)
- `synchrony` with features `async_flag,event` (sync primitives for
  `compio`. `unsync::async_flag::AsyncFlag` backs
  `ConnectionTracker`'s "drain empty" notification;
  `sync::event::Event` is the re-armable wakeup for signal handlers
  and for the singleflight cache in `providers::github`. Already a
  transitive dep via `compio-signal`; promoted to direct so the
  version is pinned independently.)
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
  compio-rs ecosystem, used for `ConnectionTracker.active` —
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
  connection_tracker.rs# spawn / drain abstraction for accept loops
  cpu_worker.rs        # Dedicated OS thread for CPU-bound work
  git_credential.rs    # protocol parse/emit; CR/LF rejection mandatory
  proxy_protocol.rs    # PROXY v2 parsing
  daemon.rs            # accept loop, per-connection handler, Service shape
  admin.rs             # Unix socket + CLI dispatch
  signals.rs           # signal-hook-registry handlers → CancelToken
  ready.rs             # sd_notify + pidfile (atomic) at startup
  loader.rs            # async config/clients.json file reads
  logging.rs           # tracing-subscriber JSON setup (stdout/stderr split)
  sandbox.rs           # landlock + seccomp
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
operation budgets — compio doesn't ship that yet).

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
  to a `gcb-jwt-signer`-named worker thread.
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
the submission/completion queue model), so the ~28 `#[compio::test]`
tests would be unrunnable regardless. Skipping miri.

**Fuzzing** is set up for the two parsers that consume attacker-
controlled bytes:

- `gcb::proxy_protocol::parse` — PROXY v2 from stunnel. Identity
  attestation depends on it (AGENTS.md invariant #7).
- `gcb::git_credential::parse` — git-credential request block;
  carries the CR/LF Clone2Leak defence (AGENTS.md invariant #12).

Fuzz targets live under `fuzz/fuzz_targets/`. The `fuzz/` subproject
pins nightly via its own `rust-toolchain.toml`; the main project
stays on stable. Run ad-hoc:

```sh
cargo install cargo-fuzz   # one-shot, no project change
cd fuzz
cargo fuzz run git_credential_parse -- -max_total_time=600
cargo fuzz run proxy_protocol_parse -- -max_total_time=600
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

No CI integration today — operator runs fuzz on demand.

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
  therefore continues to include the nameservice files libc's
  `getaddrinfo` actually reads — selected at compile time via
  `cfg(target_env = "musl")` in `src/daemon.rs::nameservice_files`.
  musl reads `/etc/resolv.conf` and `/etc/hosts` only; glibc also
  reads `/etc/nsswitch.conf` and `/etc/gai.conf`. The musl release
  binary's ruleset therefore omits the two glibc-only files.
  Reopen when either (a) hickory ships a runtime-agnostic mode,
  (b) a compio-native DNS crate appears on crates.io, or (c)
  operator need is concrete enough to justify hand-rolling a tiny
  UDP stub resolver on `compio-net` (~150–250 LOC, A/AAAA only).
  DoT/DoH are out of scope for our threat model regardless — see
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
  cycle covers IP rotation — no proactive resolver work needed.
  High-mint-rate deployments would want a connection-lifetime cap.
- **Per-read buffer reuse.** Both `src/daemon.rs::read_more` and
  `src/admin.rs::read_line` allocate a fresh `Vec` per read
  iteration. Apache iggy reuses a `BytesMut::with_capacity` via
  `.clear()` across iterations (see
  `iggy/core/server/src/tcp/connection_handler.rs`). Compio also
  offers `AsyncReadManaged` + `BufferPool` via io-uring's managed-
  buffer support. At our traffic (<<1 mint/s) per-read allocation
  cost is invisible relative to network RTT; revisit only if
  profiling shows allocation in the critical path.