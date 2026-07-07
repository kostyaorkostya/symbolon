# References

Authoritative URLs cited from elsewhere in the project. When a
link rots, the URL changes here, not in five different files.
Provider API links live with their provider doc under
[`providers/`](providers/).

## Protocols

- [Noise Protocol Framework, revision 34](https://noiseprotocol.org/noise_rev34.html):
  the cryptographic protocol family `symbolon` uses for its
  client-server transport (pattern
  `Noise_NKpsk2_25519_ChaChaPoly_BLAKE2s`).
- [git-credential](https://git-scm.com/docs/git-credential):
  the helper invocation interface.
- [gitcredentials(7)](https://git-scm.com/docs/gitcredentials):
  config surface and helper protocol.

## RFCs

- [JWT (RFC 7519)](https://www.rfc-editor.org/rfc/rfc7519)

## Tools

- [compio](https://docs.rs/compio/): async runtime.
- [cyper](https://docs.rs/cyper/): HTTPS client on compio.
- [snow](https://github.com/mcginty/snow): pure-Rust Noise
  Protocol implementation. Drives the transport in
  `src/transport.rs`.
- [rsa](https://docs.rs/rsa/): RSASSA-PKCS1-v1_5 RS256 signing
  used by the GitHub provider's JWT.

## Build & reproducibility

- [The Rust Style Guide](https://doc.rust-lang.org/style-guide/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Reproducible Builds for Rust](https://reproducible-builds.org/docs/rust/)
- [min-sized-rust](https://github.com/johnthagen/min-sized-rust)

## Security background

- [Clone2Leak: Git security vulnerabilities announced (Jan 2025)](https://github.blog/open-source/git/git-security-vulnerabilities-announced-5/):
  origin of the CR/LF rejection requirement in the
  git-credential parser (PROTOCOLS.md).

## Documentation framework

- [Diátaxis](https://diataxis.fr/): the four-mode framework
  (tutorial, how-to, reference, explanation) that informs how
  this project's docs are split. Quick primer at
  [diataxis.fr/start-here/](https://diataxis.fr/start-here/).
