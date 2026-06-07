#!/usr/bin/env bash
# Reproduce the CI release build locally with the same path-trim
# and post-strip pass. Works for any user — `$HOME` and the repo
# root from the script's own location are resolved per machine,
# so no usernames or local paths end up in the resulting binary.
#
# Usage:
#   ./scripts/release-build.sh                            # x86_64-musl
#   ./scripts/release-build.sh aarch64-unknown-linux-musl
#
# Requires `cargo-zigbuild` and `zig` on $PATH. No git checkout
# required — the script anchors off its own filesystem location.

set -euo pipefail

TARGET="${1:-x86_64-unknown-linux-musl}"
# Anchor off this script's own path: scripts/release-build.sh sits
# one level below the repo root, regardless of CWD or whether `.git`
# exists. Works from any caller and from extracted tarballs.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "${SCRIPT_DIR}")"

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
