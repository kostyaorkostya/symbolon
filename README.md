# Symbolon — git credentials broker

*Symbolon* (σύμβολον) keeps long-lived git credentials off your dev
VMs. It holds the platform's privileged identity on a trusted
broker host and mints short-lived, single-repository tokens to
clients on demand.

Currently supports **GitHub** — see
[docs/providers/github.md](docs/providers/github.md) for the
per-provider setup, guarantees, and bounds. Other providers are
designed to plug in without changing the daemon, transport, or
existing clients. **Optimized for trusted-network homelab
deployment.**

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
demand. A client compromise is bounded by the per-provider token
lifetime and per-mint scope — the concrete numbers and what each
provider does and doesn't guarantee are in
[docs/providers/](docs/providers/).

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
                                            │  mints per-repo token     │
                                            └───────────────────────────┘
```

Per request: `git` invokes the bundled `git-credential-symbolon`
helper on the client. The helper opens an authenticated, encrypted
session to the broker. Handshake completion proves the client's
identity; the daemon dispatches the request to the configured
provider, mints a single-repo token, and writes it back through the
session. The token's lifetime and exact scope are determined by
the provider — see [docs/providers/](docs/providers/). Nothing is
persisted on either side. Wire format:
[docs/PROTOCOLS.md](docs/PROTOCOLS.md).

## Threat model (summary)

A client compromise buys the attacker:

- Tokens for the per-mint scope, valid for the per-provider TTL,
  for any repository the configured provider identity can reach.
- The ability to request fresh tokens for those repos until the
  operator removes the client or removes the repo from the
  provider's access set.

A client compromise does NOT buy the attacker:

- Access to repos the provider identity hasn't been granted.
- Anything outside the per-mint permission set the broker
  requests from the provider. The exact set is per-provider; see
  [docs/providers/](docs/providers/) for the concrete bounds per
  provider.
- Other clients' traffic (per-client PSKs).
- Persistent access — no long-lived tokens; the provider's
  private key never leaves the broker host.

Full threat model and architectural decisions: [AGENTS.md](./AGENTS.md).

## Non-goals

- **Cross-untrusted-network deployment.** This design assumes
  source-IP attestation is provided by the surrounding
  environment (e.g. libvirt `clean-traffic` plus host-bridge
  anti-rogue-DHCP, or equivalent). Running broker and clients
  across the public internet would require a different transport
  and identity story.
- **Multi-tenancy.** One trust boundary, one operator, one
  provider identity per provider kind. Not a SaaS.
- **Hot-reload of provider private keys.** Restart the daemon to
  rotate keys.
- **Real-time provider-side change detection.** Webhooks are not
  consumed; per-provider selfcheck commands are the on-demand
  check.
- **Token persistence or caching.** Every token is freshly
  minted; none are stored anywhere.

## Quick start

Daemon install (provider-agnostic): [docs/INSTALL.md](docs/INSTALL.md).

Per-provider setup (App creation, config block, commands):
[docs/providers/github.md](docs/providers/github.md) for GitHub.

## Documentation

- **[AGENTS.md](./AGENTS.md)** — design rationale, architectural
  invariants, conventions, agent guidance.
- **[docs/INSTALL.md](./docs/INSTALL.md)** — daemon install,
  cross-provider.
- **[docs/OPERATIONS.md](./docs/OPERATIONS.md)** — operator
  commands, logging, troubleshooting (cross-provider).
- **[docs/PROTOCOLS.md](./docs/PROTOCOLS.md)** — wire formats,
  file schemas, daemon lifecycle, logging schema.
- **[docs/providers/](./docs/providers/)** — one file per
  supported provider.
- **[docs/REFERENCES.md](./docs/REFERENCES.md)** — authoritative
  URLs.

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
