# References

Authoritative URLs cited from elsewhere in the project. If a link rots,
the URL changes here, not in 5 different files.

## Provider APIs

- [GitHub REST API for App installations](https://docs.github.com/en/rest/apps/installations)
- [Generating an installation access token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)
- [Choosing permissions for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app)

## Protocols

- [Noise Protocol Framework, revision 34](https://noiseprotocol.org/noise_rev34.html)
  — the cryptographic protocol family `symbolon` uses for its
  client-server transport (pattern `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`).
- [git-credential](https://git-scm.com/docs/git-credential) — the helper
  invocation interface.
- [gitcredentials(7)](https://git-scm.com/docs/gitcredentials) — config
  surface and helper protocol.

## RFCs

- [JWT (RFC 7519)](https://www.rfc-editor.org/rfc/rfc7519)

## Tools

- [compio](https://docs.rs/compio/) — async runtime.
- [cyper](https://docs.rs/cyper/) — HTTPS client on compio.
- [snow](https://github.com/mcginty/snow) — pure-Rust Noise Protocol
  implementation; drives the transport in `src/transport.rs`.
- [rsa](https://docs.rs/rsa/) — RSASSA-PKCS1-v1_5 RS256 signing for
  the GitHub App JWT.

## Build & reproducibility

- [The Rust Style Guide](https://doc.rust-lang.org/style-guide/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Reproducible Builds — Rust](https://reproducible-builds.org/docs/rust/)
- [min-sized-rust](https://github.com/johnthagen/min-sized-rust)

## Security background

- [Clone2Leak — Git security vulnerabilities announced (Jan 2025)](https://github.blog/open-source/git/git-security-vulnerabilities-announced-5/)
  — origin of the CR/LF rejection requirement in the git-credential
  parser (PROTOCOLS.md).