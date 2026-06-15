# Symbolon: git credentials broker

*Symbolon* (σύμβολον) keeps long-lived git credentials off your dev
VMs. It holds the platform's privileged identity on a trusted
broker host and mints short-lived, single-repository tokens to
clients on demand.

Currently supports **GitHub**. See
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
and OAuth tokens are all "good for everything the user can do":
a client compromise leaks them and the attacker has account-wide
access for as long as the credential lives.

Symbolon holds the platform's privileged identity on a trusted
broker host and mints short-lived, repository-scoped tokens on
demand. A client compromise is bounded by the per-provider token
lifetime and per-mint scope. The concrete numbers are in
[docs/providers/](docs/providers/); the full architecture and
threat model is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

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

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how the system
  works. Diagram, trust boundary, identity model, sandbox,
  concurrency.
- [docs/INSTALL.md](docs/INSTALL.md): deploy the daemon.
- [docs/OPERATIONS.md](docs/OPERATIONS.md): day-to-day operations
  and troubleshooting.
- [docs/PROTOCOLS.md](docs/PROTOCOLS.md): wire formats, file
  schemas, log event catalog.
- [docs/PROVIDER_CONTRACT.md](docs/PROVIDER_CONTRACT.md): what a
  provider implementation has to satisfy (RFC-2119).
- [docs/providers/](docs/providers/): one file per supported
  provider.
- [docs/REFERENCES.md](docs/REFERENCES.md): external URLs.
- [AGENTS.md](./AGENTS.md): design invariants, dependency audit,
  style notes for contributors and LLM agents.

## Quick start

Daemon install (cross-provider): [docs/INSTALL.md](docs/INSTALL.md).

Per-provider setup (App creation, config block, commands):
[docs/providers/github.md](docs/providers/github.md) for GitHub.

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
