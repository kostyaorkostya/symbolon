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
6. **Transport: Noise NKpsk2 over TCP, terminated in-process** via
   the [`snow`](https://github.com/mcginty/snow) crate. The daemon
   listens directly on TCP (default `:9418`) and runs the responder
   side of `Noise_NKpsk2_25519_ChaChaPoly_BLAKE2s` with a static
   X25519 key (`[listen] static_key_file`, 32 random bytes hex —
   no keygen tool, no rotation machinery, exactly one key). Clients
   pin the broker's static public key (from `symbolon pubkey`) and
   run the matching initiator via the bundled
   `git-credential-symbolon` helper. No TLS at any layer (preserves
   the no-TLS hard NOT).
7. **Identity: encrypted TLV inside handshake msg1.** The client
   carries the SBLN TLV (`magic | version | identity_len |
   identity`) as the encrypted payload of Noise message 1,
   TLS-ECH-style; the broker decrypts it with its static key,
   looks up the PSK for that identity in its in-memory store, and
   injects it via `set_psk` before message 2 (`psk2`). Handshake
   completion is the identity proof. **Anti-enumeration is
   mandatory:** an unknown identity gets a freshly random
   substitute PSK and the session dies at the first
   transport-frame decrypt — never an early drop, so enrollment
   status is unobservable from the wire (logged as rate-limited
   `evt=identity_unknown`). The source IP is not used for identity
   at any point (DHCP-friendly); it is logged as audit metadata
   only.
8. **State is files.** `clients.json` + `psks` only, both owned and
   atomically rewritten by the daemon (tempfile + fsync + rename +
   fsync parent).
9. **Admin surface = Unix-domain socket.** No HTTP admin endpoints.
10. **Daemon is the sole writer** of state files. CLI commands talk
    to the daemon via the admin socket; the daemon serialises
    concurrent enroll/revoke through `SharedState.mutation_lock`
    (single-permit async mutex) so on-disk writes can't race across
    `atomic_write` `.await`s. Both `psks` and `clients` in-memory
    tables are updated *before* the disk write so a concurrent mint
    on the wire path never sees a half-enrolled client. In-memory is
    the truth — no read-merge dance.
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
15. **Socket activation is mandatory.** The daemon does NOT bind
    its listeners. Both the TCP wire (`:9418` by convention) and
    the admin UDS (`/run/symbolon/admin.sock`) are obtained via the
    `LISTEN_FDS` env protocol — from a systemd `.socket` unit (with
    `Sockets=symbolon.socket` on the `.service`), or from the
    [`systemfd`](https://github.com/mitsuhiko/systemfd) wrapper
    under non-systemd inits (`systemfd --no-pid -s tcp::… -s unix::… --
    symbolon daemon`). Slot 0 = TCP wire, slot 1 = admin UDS. Plain
    `symbolon daemon` exits with `evt=run_failed` +
    `DaemonError::EnvFdTake` when no supervisor is present. The
    supervisor owns the socket inode lifecycle, perms, and unlink.
    See `docs/INSTALL.md` §3.9–3.11. Consumed via the `listenfd`
    crate.
16. **The App private key never lives in the daemon.** Signing goes
    through the `JwtBackend` trait (`src/providers/jwt_backend.rs`),
    the ONLY seam where the signing path branches on backend. Past
    construction the provider holds a `Box<dyn JwtBackend>` and
    cannot distinguish a vTPM from a key subprocess — no
    backend-conditional logic anywhere else. Two impls:
    `tpm_backend` (RSA in a vTPM; the daemon SHA-256s the JWS
    signing input in Rust and only the 32-byte digest crosses to the
    TPM) and `agent_backend` (RSA in a sandboxed subprocess that
    owns the PEM; the daemon ships claims and gets a whole JWT back).
    The operator picks via `[provider.github] app_key_backend =
    "tpm" | "file"` — required, no default, no auto-probe, no
    runtime fallback.
17. **Security-critical ordering is enforced by types, not comments.**
    Two silent-if-wrong orderings exist in the codebase (a mistake is
    a vulnerability, not a loud failure); both are made
    *unrepresentable*:
    - **Daemon — the `Sandboxed` witness.** `sandbox::apply` returns a
      `Sandboxed` (`!Send` ZST, private constructor). `sandbox::spawn`
      is the ONLY OS-thread API in the daemon and requires
      `&Sandboxed`, so a thread can't be spawned before Landlock (which
      would leave it outside the per-thread domain — a silent escape
      hole). `prepare_inner` reads as three phases: `Acquired::acquire`
      (all pre-gate reads + the TPM device open / agent `execve`, which
      need access the sandbox revokes) → `apply_sandbox` (returns the
      witness; also denies `execve` via `AccessFs::Execute` granted
      nowhere, never grants the TPM/key paths) → `build_providers`
      (starts the actor thread through the witness, then `self_check` —
      a dead agent / unreachable TPM is fatal at startup). The
      `SpawnedBackend::into_backend(&Sandboxed)` signature makes the
      two-phase split self-documenting.
    - **Agent — the `Locked` witness.** The `__sign-agent` process
      (`src/providers/agent.rs`) locks itself down in
      `Locked::lock_down` — read the PEM once, then `mlockall` /
      `PR_SET_DUMPABLE=0` / `PR_SET_PDEATHSIG`, then Landlock (deny all
      FS — the key is already read — and all network), then the seccomp
      allowlist — and returns a `Locked` witness. `serve` exists only
      on `Locked`, so the serve loop cannot run under-restricted. The
      intra-lockdown orderings (PEM before Landlock; Landlock before
      seccomp) stay a linear sequence in `lock_down`, NOT a per-rung
      typestate — they fail loudly at runtime if reordered (see below),
      so only the one silent risk (serve-before-lockdown) is
      type-encoded. The key is read exactly once, up front; there is no
      hot reload (rotate by restarting — see "Out of scope"), so the
      agent holds no filesystem reach and no `openat`/`read` in its
      seccomp allowlist after lockdown.

    Orderings that fail *loudly* at runtime (a key read after Landlock
    → EACCES; `execve` after the gate → denied; a syscall after seccomp
    → killed) are deliberately NOT type-encoded — the runtime already
    catches them on the first run, so a witness there would be
    ceremony.

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
- `async-trait` (proc macro that rewrites `async fn` trait methods
  to return `Pin<Box<dyn Future + 'async_trait>>`. Required because
  AFIT + `dyn Trait` is not yet dyn-compatible on stable Rust as
  of 1.96 — the only way to get a heterogeneous
  `Vec<Box<dyn Provider>>` for the `Provider` trait in
  `src/providers/mod.rs`. We invoke it as `#[async_trait(?Send)]`
  because compio is single-threaded; the `?Send` drops the default
  `Send + 'static` bound on the returned future. Cost: one
  `Box::pin` per `mint` / `selfcheck` call — invisible next to
  the outbound HTTPS round-trip these methods perform. Build cost:
  `syn`/`quote`/`proc-macro2` are already in our graph via
  `serde_derive` / `thiserror_impl`. Picked over hand-rolled
  `Pin<Box<dyn Future>>` returns (identical alloc cost, but every
  method signature becomes noise) and over the enum-with-match
  alternative (would have foreclosed the trait shape PROVIDER_CONTRACT.md
  promised, and forced provider variants to live in a single
  central enum rather than as sibling modules).)
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
- `derive_more` with `default-features = false, features = ["as_ref",
  "display", "from", "into"]` (proc-macro derives for newtype boilerplate
  on the correlation-ID types in `src/ids.rs` and the GitHub-specific
  ID types in `src/providers/github.rs`. `Display` makes
  `tracing::info!(req_id = %req_id, …)` transparent; `From<T>` gives
  ergonomic construction from the inner primitive; `AsRef<str>`
  lets the newtypes pass through `&str`-taking APIs at FFI
  boundaries (HTTP headers, JSON serialisation) without manual
  `.as_str()` calls everywhere. Feature trim drops the rest of
  derive_more's catalog (~30 derives we don't use) to keep compile
  surface narrow. `syn`/`quote`/`proc-macro2` are already in our
  build graph via serde-derive and thiserror, so the marginal
  build cost is one small derive crate.)
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
  Picked over `jsonwebtoken` because that crate's monolithic
  `Algorithm` enum keeps ed25519-dalek / curve25519-dalek / p256 /
  p384 / hmac in the binary even when only RS256 is called — the
  linker can't prove the unused enum arms unreachable. RSASSA-
  PKCS1-v1_5 with SHA-256 is one of the most thoroughly specified
  JOSE algorithms; the actual signing is a single `rsa::SigningKey`
  call. Output is locked by a known-vector test in
  `jwt_rs256::tests::known_vector_round_trip`.
- `hex` (encode/decode for the per-line PSK file format in
  `src/psk_store.rs`, the enroll output's `psk_hex` field in
  `src/admin.rs`, and the client binary's PSK file load in
  `src/bin/git_credential_symbolon.rs`. Pure-Rust, zero runtime
  deps, dual MIT/Apache.)
- `listenfd` (consumer side of the systemd `LISTEN_FDS` env
  protocol — used in `src/daemon.rs::take_env_listeners` to reclaim
  the TCP wire socket + admin UDS that the supervisor (systemd
  `.socket` unit or `systemfd` wrapper) pre-bound. Returns `std`
  socket types which compio wraps via `from_std` with no `unsafe`
  at our call site. Apache-2.0, by the same author as `systemfd`.
  Pulls `uuid` as a transitive (Windows code path; unused on our
  musl targets but in the dep graph regardless). Picked over
  rolling our own ~50-LOC env reader for the PID-check correctness
  and the consume-on-read env-var hygiene listenfd does for free.)
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
  forbids `unsafe_code` internally. Drives `Noise_NKpsk2_25519_
  ChaChaPoly_BLAKE2s` in `src/transport.rs` (responder side in
  the daemon, initiator side in the `git-credential-symbolon`
  client binary). Feature trim drops aes-gcm / sha2 /
  blake3 / p256 / pqcrypto since our pattern uses only
  ChaCha20-Poly1305 + BLAKE2s + X25519.)
- `curve25519-dalek` with `default-features = false` (one call:
  `MontgomeryPoint::mul_base_clamped` in
  `src/broker_key.rs::derive_public`, deriving the broker's public
  key from the 32-byte private key at startup. Already in the
  dependency graph transitively via snow's `use-curve25519`
  feature — and it is the exact function snow's own
  `Dh25519::derive_pubkey` uses, so our derivation is bit-identical
  to what the handshake computes; the explicit dep adds zero binary
  weight. snow deliberately doesn't re-export a pub-from-priv
  helper, and the alternative `x25519-dalek` wrapper would add a
  new crate for the same underlying call. Version pinned to the
  4.x line to stay unified with snow's requirement — `cargo add
  curve25519-dalek` alone picks 5.x and silently doubles the
  crate in the graph.)
- `serde`, `serde_json`, `toml` (config + provider responses)
- `strum` with `features = ["derive"]` (proc-macro derives that
  generate `Into<&'static str>` and `Display` from enum variant
  names, eliminating hand-written variant→string match tables on
  `EventKind` in `src/events.rs` and on the `RState` / `IState`
  state machines in `src/transport.rs`. The PROTOCOLS.md logging
  schema names every `evt` exactly once in the wire vocabulary,
  and the snake-case rendering (`#[strum(serialize_all =
  "snake_case")]`) keeps the enum variant `EventKind::MintDenied`
  in lockstep with the wire string `"mint_denied"` — adding a
  new variant cannot drift away from the schema by accident.
  The state-machine `name()` methods use the PascalCase form
  (`WantHsBody` etc.) for `WrongState` error context only; no
  external consumer depends on them. Pure compile-time;
  `syn`/`quote`/`proc-macro2` are already in the build graph via
  serde-derive and thiserror, so the marginal cost is one small
  proc-macro crate.)
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
- `futures-channel` (`oneshot` for the result hand-back from the
  signing-backend actor threads in `src/providers/tpm_backend.rs`
  and `src/providers/agent_backend.rs`; the fd-owning OS thread
  sends the computed value back to the awaiting compio task.)
- `tpm2-protocol` (zero-dependency, `no_std`-capable TPM 2.0
  marshaler/unmarshaler by the kernel TPM maintainer; drives the
  `TPM2_ReadPublic` / `TPM2_Sign` wire format in
  `src/providers/tpm_backend.rs`. Chosen over hand-rolling the two
  commands: it models TPM2B buffers, the `TPM_RS_PW` session, the
  null hashcheck ticket, and format-0/format-1 response-code
  decoding correctly, all against caller-provided `&mut [u8]`
  buffers with no allocator — a good fit for the musl targets. Pure
  Rust, no C.)
- `seccompiler` (Firecracker's seccomp-BPF compiler; pulls only
  `libc`. Builds the `src/providers/agent.rs` syscall allowlist
  into a `SECCOMP_RET_KILL_PROCESS` filter. Hand-rolling the BPF
  was the alternative; seccompiler gives arch-portable syscall
  numbering and validated program construction for ~no marginal
  surface. It closes the UDP / raw-socket exfiltration hole
  Landlock's network layer — which governs `connect`/`bind`, not
  `socket` creation — leaves open in the key subprocess.)
- `base64` (URL-safe-no-pad encoding in `src/providers/jwt_rs256.rs`
  for the JWT header / payload / signature segments. Listed as a
  top-level dep so the audit surface is explicit.)
- `ulid` (request IDs)
- `thiserror` (errors)
- `signal-hook-registry` (long-lived OS-level signal handler
  installed once at startup; the kernel disposition stays bound
  to our handler for the process lifetime. `compio::signal` would
  be the obvious alternative but its `signal()` is one-shot — it
  reverts to `SigDfl` on listener drop, and a SIGTERM delivered in
  that gap would kill the daemon without giving the shutdown loop
  a chance to drain. We register synchronous handlers per signal
  that set an AtomicBool + call `AtomicWaker::wake` on a
  `SignalNotifier`; the compio task loop awaits a re-armable
  `Notified` future. Both the AtomicBool store and the
  AtomicWaker wake are lock-free, alloc-free, reentrant, and
  async-signal-safe.)
- `synchrony` with features `async_flag,event,mutex` (sync primitives
  for `compio`. `sync::event::Event` is the re-armable wakeup used by
  `ConnectionTracker`'s "drain empty" notification and by the
  singleflight cache in `providers::github`. `unsync::mutex::Mutex<()>`
  is the single-permit async mutex on `SharedState.mutation_lock`
  that serialises concurrent `enroll_client`/`revoke_client` so
  their on-disk writes can't race across `atomic_write` `.await`s.
  The signal-handler notifier uses raw `AtomicBool` +
  `futures_util::task::AtomicWaker` directly rather than `AsyncFlag`
  because `AsyncFlag::wait` is consume-on-wait, which doesn't fit
  the permanent handler loop. `async_flag` feature stays enabled
  because synchrony co-builds the primitives.)
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
`codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`,
`overflow-checks = true` (silent integer wrap-around becomes an
abort — in a credential broker the arithmetic is lengths, TTLs,
and counters, exactly where a quiet wrap is worst; the few percent
of size/speed are invisible at broker traffic).

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
- Default to `pub` for items reachable across modules; mark items
  not used outside their module as private (no qualifier). `pub(crate)`
  is not used — this crate ships only as the daemon + client binaries
  (no external library consumer), so the lib/binary boundary is
  internal-only and the extra `(crate)` is ceremony without value.
- Default to no comments. Add a doc comment only when the *why* or
  the contract isn't obvious from the name and signature: hidden
  invariants, surprising edge cases, security-load-bearing rules
  (e.g. the CR/LF rejection in `git_credential`). Don't restate what
  well-named code already says.
- Prefer `?` over `match { Ok(v) => v, Err(e) => return Err(<conv>) }`.
  Add `impl From<OtherError> for <YourError>` next to the enum so
  `?` performs the conversion automatically (see
  `impl From<WorkerDead> for GithubError`). For error constructors
  that need extra context (e.g. status code + body), use an
  inherent `Self::from_*` method on the enum rather than a free
  function or a tuple-receiving `From`.
- Trait async methods: declare with `#[async_trait::async_trait(?Send)]`.
  `?Send` is required because compio is single-threaded; the default
  `Send + 'static` bound would force an unnecessary contract on every
  impl. See `impl Provider for GitHubProvider` in `src/providers/github.rs`.
- RAII guards: default Drop is the rollback path; the success
  path is an explicit `commit_*` method that consumes `self` and
  transitions an internal state, so the shared Drop logic still
  fires. See `InFlightGuard` in `src/providers/github.rs`: default
  state is `Failed` (invalidate + notify on Drop); `commit_done`
  transitions to `Done` (put_done + notify on Drop). Avoids
  `armed: bool` + a separate `disarm_and_notify` shape.
- Witness tokens / typestate for **security-critical ordering that
  fails silently**. When getting an order wrong is a vulnerability
  rather than a loud runtime error, make the wrong order
  unrepresentable: a witness ZST minted only by the step that must
  come first and required by the step that must come after
  (`Sandboxed` — invariant #17), or a consume-`self` witness where
  the guarded operation exists only on it (`Locked::serve` in
  `src/providers/agent.rs`: `Locked` is minted only by
  `lock_down`). Apply this ONLY to silent-failure orderings;
  orderings that already fail loudly at runtime (a denied syscall,
  a missing file) get a plain comment, not a token — the runtime is
  the check. Don't sprinkle typestate on ordinary control flow, and
  prefer a single witness over a multi-rung typestate ladder unless
  every rung's ordering is itself a silent risk.

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
  admin.rs             # admin Unix socket + CLI dispatch (enroll/revoke/etc.)
  atomic_fs.rs         # tempfile + fsync + rename + fsync-parent write
  broker_key.rs        # broker static X25519 keypair newtypes + pub derivation
  config.rs            # config.toml + clients.json parsing
  connection_tracker.rs# spawn / drain abstraction for accept loops
  daemon.rs            # TCP accept loop, per-connection driver, Service shape
  events.rs            # closed-set EventKind enum for structured logs
  git_credential.rs    # protocol parse/emit; CR/LF rejection mandatory
  identity.rs          # validated PSK identity newtype
  ids.rs               # ReqId / OutReqId correlation-id newtypes
  loader.rs            # async config/clients.json file reads
  logging.rs           # tracing-subscriber JSON setup (stdout/stderr split)
  mlock.rs             # mlockall(MCL_CURRENT|MCL_FUTURE) wrapper
  note.rs              # validated operator-note newtype
  psk.rs               # 32-byte PSK newtype (redacted Debug, LowerHex)
  psk_store.rs         # in-memory identity → PSK store, file-backed
  rate_limit.rs        # token bucket bounding attacker-triggerable log events
  ready.rs             # sd_notify + pidfile (atomic) at startup
  sandbox.rs           # landlock (FS + TCP + UDS scope + signal scope)
  signals.rs           # signal-hook-registry handlers → CancelToken
  singleflight_cache.rs# no-TTL memo + singleflight coordinator
  transport.rs         # Responder/Initiator sans-IO state machines, framing, identity TLV
  ttl_cache.rs         # generic expiring cache (clock-parameterised, sweep-on-access)
  providers/
    mod.rs             # `Provider` trait + abstract `ProviderError` / outcomes
    github.rs          # GitHub: repo-ID resolution + mint (holds a `dyn JwtBackend`)
    jwt_backend.rs     # the signing seam: `JwtBackend` trait + `JwtClaims`
    jwt_rs256.rs       # RS256 JWS framing: signing_input / assemble / whole-token sign
    tpm_backend.rs     # `tpm` backend: vTPM signer, fd-owning actor thread
    agent_backend.rs   # `file` backend daemon side: socketpair spawn + actor
    agent_protocol.rs  # daemon↔agent SEQPACKET message types
    agent.rs           # `__sign-agent` subprocess: key custody + self-sandbox + serve
tests/
  admin.rs             # admin UDS protocol against a spawned daemon
  client_binary.rs     # end-to-end smoke against a one-shot Noise responder
  daemon.rs            # TCP wire round-trip against the daemon
  github_provider.rs   # wiremock-rs against the GitHub provider
  common/              # shared test scaffolding
  fixtures/            # test_app_key.pem
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

For blocking work (there is no CPU-bound work left in-process —
RSA now happens in a vTPM or the key subprocess), the pattern is a
**dedicated fd-owning OS-thread actor**: a `std::thread` owns the
blocking fd (TPM device / agent socketpair) for the process
lifetime, receives requests over an `mpsc` channel, and replies via
a `futures_channel::oneshot`. See
`src/providers/tpm_backend.rs` and `src/providers/agent_backend.rs`
— both take the same shape. The actor thread is spawned
*post-sandbox* via `sandbox::spawn(&Sandboxed, …)` (`into_backend`
takes the `&Sandboxed` witness — invariant #17) so it inherits the
Landlock ruleset; the fd it owns is opened/created *pre-sandbox*.
Blocking read/write on an already-open fd is unaffected by
Landlock, so the split is safe. `sandbox::spawn` is the ONLY
OS-thread-spawning API in the daemon — don't reach for
`std::thread::spawn` directly, or the witness guarantee is lost.
There was a shared `CpuWorker` here for in-process RSA; it was
removed with the in-process signer.

`sandbox::spawn` also caps the thread stack at 128 KiB — musl's own
per-thread default (`DEFAULT_STACK_SIZE` in
`src/internal/pthread_impl.h`); Rust's default is 2 MiB. This
matters because of `mlockall(MCL_CURRENT | MCL_FUTURE)` without
`MCL_ONFAULT` (invariant #14): a spawned thread's entire stack is
pre-faulted into locked, unevictable memory, so stack size is
locked RSS, not just address space. Actor working buffers live on
the heap; frames stay far below the cap, and overflow hits the
guard page (loud SIGSEGV, not corruption). Threads that take
Rust's default — compio's blocking pool, where DNS `getaddrinfo`
runs (worst-case measured frame ~16 KiB on musl) — can't be sized
through compio's API; deployments opt in via the
`RUST_MIN_STACK=131072` env var (see INSTALL.md §§3.10–3.11).

For one-off CPU bursts, **`compio::runtime::spawn_blocking(f)`**
still exists (compio's pool lazily spawns up to 256 threads, 60 s
idle reap) — good when work is occasional, bad for high-frequency
recurring work.

For long-but-async work, sprinkle explicit yield points via
`compio_runtime`'s yield helpers (tokio's analogue is
`tokio::task::yield_now().await`).

## Security tooling

**Miri** is not used. The `unsafe` surface is small and entirely
FFI into `libc`/`landlock`/`seccompiler` at the process-hardening
boundary — the signing agent (`src/providers/agent.rs`:
`recv`/`send`/`prctl`/`mlockall`), the agent spawn
(`src/providers/agent_backend.rs`: `socketpair`/`pre_exec` fcntl),
and a `libc::kill` in a `src/sandbox.rs` test. Miri can't model
those syscalls, and compio's io_uring backend has no Miri shim
either (the `#[compio::test]` tests would be unrunnable regardless).
The FFI is validated instead by the integration tests that spawn
the real agent under real Landlock + seccomp. Skipping miri.

**Fuzzing** is set up for the two parsers that consume attacker-
controlled bytes:

- `symbolon::parse_identity_tlv`: the identity TLV decrypted out
  of Noise handshake msg1 — peer-controlled bytes once the msg1
  decrypt succeeds. Identity selection depends on it (AGENTS.md
  invariant #7).
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
cargo fuzz run identity_tlv_parse -- -max_total_time=600
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

- **Static-PIE release binaries (ASLR).** Both shipped musl
  binaries are `ET_EXEC` — position-dependent static executables
  with no image ASLR — because `cargo zigbuild`'s `zig cc` (0.16.0)
  does not implement `-static-pie` and discards it with an
  "argument unused" warning. rustc's x86_64-musl target spec
  enables static-PIE (`static_position_independent_executables`)
  and passes `-static-pie` to the linker driver, so a plain
  `cargo build --release --target x86_64-unknown-linux-musl`
  (rustc's bundled musl + self-contained crt, host cc for ring's C)
  produces a correct static-PIE (`ET_DYN`, no `INTERP`,
  `DF_1_PIE`); splitting the release pipeline that way was
  considered and rejected — build symmetry across the two targets
  is worth more than defense-in-depth ASLR on a memory-safe
  binary with a tiny FFI surface. aarch64 is blocked deeper:
  its rustc target spec lacks the static-PIE flag entirely, so
  rustc emits `-no-pie` (which conflicts with any injected
  `-static-pie`) even though `rcrt1.o` already ships in the
  aarch64-musl sysroot. Reopen when any of: zig implements
  `-static-pie`; cargo-zigbuild translates or at least surfaces
  the dropped flag; rustc's `aarch64-unknown-linux-musl` spec
  gains `static_position_independent_executables = true` (one-line
  change, x86_64 precedent). All three are upstream-filing
  candidates.
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