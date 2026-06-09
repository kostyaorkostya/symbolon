# Symbolon — git credentials broker

*Symbolon* (σύμβολον): in Ancient Greek, an object broken in two
halves; each party kept one, and matching them proved identity. Fits
a daemon that authenticates clients by PSK and hands them
short-lived, single-repository git credentials.

**Symbolon keeps long-lived GitHub credentials off your dev VMs.** It
holds the GitHub App private key on a trusted broker host and mints
≤1-hour, single-repository tokens to clients on demand.

Currently supports GitHub (including GitHub Enterprise Server). Designed
so additional providers (e.g. GitLab) can be added without disturbing
the core daemon, the transport, or existing clients. **Optimized for
trusted-network homelab deployment.**

## Why this exists

You want to clone and push from sandboxed clients (VMs evaluating
untrusted code, containers running supply-chain-vulnerable build
pipelines, machines running agentic coding tools) without putting
long-lived credentials on them. SSH keys, personal access tokens, and
OAuth tokens are all "good for everything the user can do" — a client
compromise leaks them and the attacker has account-wide access for as
long as the credential lives.

Symbolon holds the platform's privileged identity (e.g. a GitHub App's
private key) on a trusted broker host and mints short-lived,
repository-scoped tokens to clients on demand. A client compromise
bounds the attacker to the broker's narrow per-mint scope for ≤1 hour
(GitHub's installation-token TTL — see
[GitHub docs](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)).

## Architecture

```
┌──────────────────────────┐                ┌───────────────────────────┐
│   client                 │                │       broker host         │
│ (VM or container)        │                │                           │
│                          │                │  symbolon :9418           │
│  git → git-credential-   │  Noise NNpsk0  │  (TCP listen,             │
│        symbolon          ├──────────────► │   PSK identity →          │
│           │              │                │   per-client lookup)      │
│           │              │ ◄── git creds ─┤                           │
└──────────────────────────┘                │       │ HTTPS             │
                                            │       ▼                   │
                                            │  provider API             │
                                            │  (api.github.com today)   │
                                            │  mints per-repo token     │
                                            └───────────────────────────┘
```

Per request: `git` invokes the bundled `git-credential-symbolon` helper
on the client. The helper opens a TCP connection to the broker, sends a
small identity prelude, and runs the responder side of `Noise_NNpsk0_
25519_ChaChaPoly_BLAKE2s` against the PSK both sides hold. Handshake
completion authenticates the connection; the daemon looks up the
matching client metadata, dispatches the request to the configured
provider, mints a single-repo token, and writes it back through the
authenticated Noise transport. The token expires within an hour.
Nothing is persisted on either side.

## Threat model (summary)

A client compromise buys the attacker:

- Up to ~1 hour of token use against repositories accessible to the
  configured provider identity.
- The ability to request fresh tokens for those repos until the
  operator removes the client or removes the repo from the provider's
  access set.

A client compromise does NOT buy the attacker:

- Access to repos the provider identity hasn't been granted.
- The ability to modify CI workflow files (the GitHub App lacks the
  `Workflows` permission; pushes touching `.github/workflows/*.yml`
  are rejected by the provider).
- Secret reads, issue management, PR management, or anything outside
  the configured minimum permissions.
- Other clients' traffic (per-client PSKs over TLS).
- Persistent access (no long-lived tokens; the provider's private key
  never leaves the broker host).

Full threat model and architectural decisions: see [AGENTS.md](./AGENTS.md).

## Non-goals

- **Cross-untrusted-network deployment.** This design assumes source-IP
  attestation is provided by the surrounding environment (e.g. libvirt
  `clean-traffic` plus host-bridge anti-rogue-DHCP, or equivalent).
  Running broker and clients across the public internet would require
  a different transport and identity story.
- **Multi-tenancy.** One trust boundary, one operator, one provider
  identity per provider kind. Not a SaaS.
- **Hot-reload of provider private keys.** Restart the daemon to
  rotate keys.
- **Real-time provider-side change detection.** Webhooks are not
  consumed; `symbolon github selfcheck` is the on-demand check.
- **Token persistence or caching.** Every token is freshly minted;
  none are stored anywhere.

## Quick start

1. **Create a GitHub App** (Contents R/W + Metadata R only) and install
   it on the repos you want exposed.
2. **Deploy `symbolon` to a trusted-network host.** See
   [docs/INSTALL.md](docs/INSTALL.md). No TLS proxy needed — the
   daemon terminates Noise NNpsk0 in-process.
3. **Enroll each client:** `symbolon github enroll <name> --ip <ip>`.
   The command prints a paste-ready snippet for the client.

## Documentation

- **[AGENTS.md](./AGENTS.md)** — design rationale, architectural
  invariants, conventions, agent guidance.
- **[docs/INSTALL.md](./docs/INSTALL.md)** — deploying the broker and
  enrolling clients.
- **[docs/OPERATIONS.md](./docs/OPERATIONS.md)** — operator commands,
  logging, troubleshooting.
- **[docs/PROTOCOLS.md](./docs/PROTOCOLS.md)** — wire formats, file
  schemas, daemon lifecycle, logging schema.
- **[docs/REFERENCES.md](./docs/REFERENCES.md)** — authoritative URLs.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
