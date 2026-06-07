#!/usr/bin/env bash
# Reproduce the CI release build locally with the same path-trim
# and post-strip pass. Works for any user — `$HOME` and the repo
# root from `git rev-parse` are resolved per machine, so no
# usernames or local paths end up in the resulting binary.
#
# Usage:
#   ./scripts/release-build.sh                            # x86_64-musl
#   ./scripts/release-build.sh aarch64-unknown-linux-musl
#
# Requires `cargo-zigbuild` and `zig` on $PATH.

set -euo pipefail

TARGET="${1:-x86_64-unknown-linux-musl}"
REPO="$(git rev-parse --show-toplevel)"

# Mirrors the CI workflow's Build step. --remap-path-scope=all is
# required to cover macro-expanded paths (rust-lang/rust#83635);
# without it the tracing callsite metadata keeps the full path.
export CARGO_BUILD_RUSTFLAGS="--remap-path-scope=all \
--remap-path-prefix=${HOME}/.cargo/registry/src/=cr/ \
--remap-path-prefix=${HOME}/.rustup/toolchains/=tc/ \
--remap-path-prefix=${REPO}/=./"

cd "${REPO}"
cargo zigbuild --release --locked --target "${TARGET}"

# Drop stack-unwind tables. Safe because panic = "abort" — see the
# matching step in .github/workflows/release.yml for the full
# rationale.
BIN="target/${TARGET}/release/gcb"
BEFORE="$(stat -c%s "${BIN}")"
strip --strip-debug \
	--remove-section=.eh_frame \
	--remove-section=.eh_frame_hdr \
	--remove-section=.gcc_except_table \
	"${BIN}"
AFTER="$(stat -c%s "${BIN}")"
echo "Stripped ${BIN}: ${BEFORE} -> ${AFTER} bytes ($((BEFORE - AFTER)) saved)"
ls -l "${BIN}"
