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

# Auto-discover the active crates.io registry-source directory.
# Cargo recently switched the hash algorithm to `rustc-stable-hash`
# (per the Cargo changelog) and the
# `index.crates.io-<hash>/` directory name changed once already;
# globbing avoids hardcoding the current hash and breaking on the
# next algorithm bump. `ls -td` picks the most recently used one
# in case stale dirs from older cargo versions linger.
CARGO_REG_SRC="${CARGO_HOME:-${HOME}/.cargo}/registry/src"
INDEX_DIR="$(ls -td "${CARGO_REG_SRC}"/index.crates.io-* 2>/dev/null | head -1)"
if [ -n "${INDEX_DIR}" ] && [ -d "${INDEX_DIR}" ]; then
	CRATES_REMAP="--remap-path-prefix=${INDEX_DIR}/=cr/"
else
	# Registry not populated yet (fresh checkout). Fall back to
	# trimming what we know about; the hash will remain visible
	# but no usernames leak.
	CRATES_REMAP="--remap-path-prefix=${CARGO_REG_SRC}/="
fi

# Mirrors the CI workflow's Build step. --remap-path-scope=all is
# required to cover macro-expanded paths (rust-lang/rust#83635);
# without it the tracing callsite metadata keeps the full path.
export CARGO_BUILD_RUSTFLAGS="--remap-path-scope=all \
${CRATES_REMAP} \
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
