# Symbolon — git credentials broker

*Symbolon* (σύμβολον) keeps long-lived **GitHub** credentials off
your dev VMs. It holds the platform's privileged identity (e.g. a
GitHub App's private key) on a trusted broker host and mints
short-lived, single-repository tokens to clients on demand.

Currently supports **GitHub** (including GitHub Enterprise Server).
Other providers are designed to plug in without changing the
daemon, transport, or existing clients. **Optimized for
trusted-network homelab deployment.**

## Why this exists

You want to clone and push from sandboxed clients (VMs evaluating
untrusted code, containers running supply-chain-vulnerable build
pipelines, machines running agentic coding tools) without putting
long-lived credentials on them. SSH keys, personal access tokens,
and OAuth tokens are all "good for everything the user can do" — a
client compromise leaks them and the attacker has account-wide
access for as long as the credential lives.

Symbolon holds the platform's privileged identity on a trusted
broker host and mints short-lived, repository-scoped tokens on
demand. A client compromise bounds the attacker to the broker's
narrow per-mint scope for ≤1 hour (the TTL of the provider's
installation token).

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
                                            │  (GitHub today)           │
                                            │  mints per-repo token     │
                                            └───────────────────────────┘
```

Per request: `git` invokes the bundled `git-credential-symbolon`
helper on the client. The helper opens an authenticated, encrypted
session to the broker. Handshake completion proves the client's
identity; the daemon dispatches the request to the configured
provider, mints a single-repo token, and writes it back through the
session. The token expires within an hour. Nothing is persisted on
either side. Wire format: see
[docs/PROTOCOLS.md](docs/PROTOCOLS.md).

## Threat model (summary)

A client compromise buys the attacker:

- Up to ~1 hour of token use against repositories accessible to the
  configured provider identity.
- The ability to request fresh tokens for those repos until the
  operator removes the client or removes the repo from the
  provider's access set.

A client compromise does NOT buy the attacker:

- Access to repos the provider identity hasn't been granted.
- Anything outside the per-mint permission set the broker requests
  from the provider (minimum-permissions; for GitHub the
  `Workflows` permission is intentionally not granted, so pushes
  touching `.github/workflows/*.yml` are rejected). See
  [AGENTS.md](./AGENTS.md) for the full per-provider permission
  set.
- Other clients' traffic (per-client PSKs).
- Persistent access (no long-lived tokens; the provider's private
  key never leaves the broker host).

Full threat model and architectural decisions: see [AGENTS.md](./AGENTS.md).

## Non-goals

- **Cross-untrusted-network deployment.** This design assumes
  source-IP attestation is provided by the surrounding environment
  (e.g. libvirt `clean-traffic` plus host-bridge anti-rogue-DHCP,
  or equivalent). Running broker and clients across the public
  internet would require a different transport and identity story.
- **Multi-tenancy.** One trust boundary, one operator, one
  provider identity per provider kind. Not a SaaS.
- **Hot-reload of provider private keys.** Restart the daemon to
  rotate keys.
- **Real-time provider-side change detection.** Webhooks are not
  consumed; per-provider selfcheck commands (e.g.
  `symbolon github selfcheck`) are the on-demand check.
- **Token persistence or caching.** Every token is freshly minted;
  none are stored anywhere.

## Quick start

Full setup in [docs/INSTALL.md](docs/INSTALL.md). The short
version for the currently supported provider (GitHub):

1. **Create a GitHub App** (Contents R/W + Metadata R only) and
   install it on the repos you want exposed.
2. **Deploy `symbolon` to a trusted-network host.** No TLS proxy
   needed — the client session is terminated in-process.
3. **Enroll each client:** `symbolon github enroll <name>`. The
   command prints a paste-ready snippet for the client.

## Documentation

- **[AGENTS.md](./AGENTS.md)** — design rationale, architectural
  invariants, conventions, agent guidance.
- **[docs/INSTALL.md](./docs/INSTALL.md)** — deploying the broker
  and enrolling clients.
- **[docs/OPERATIONS.md](./docs/OPERATIONS.md)** — operator
  commands, logging, troubleshooting.
- **[docs/PROTOCOLS.md](./docs/PROTOCOLS.md)** — wire formats,
  file schemas, daemon lifecycle, logging schema.
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
