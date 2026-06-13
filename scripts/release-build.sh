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

# Preflight: `llvm-strip` and `llvm-readelf` are the multi-target
# stand-ins for GNU `strip` / `readelf`. The host binutils is
# single-target, so a bare `strip` cannot recognise the cross-
# compiled aarch64 ELF emitted by `cargo zigbuild --target
# aarch64-unknown-linux-musl` on an x86_64 host. Fail-fast with an
# actionable hint rather than letting the per-binary loop blow up
# with "command not found".
for tool in llvm-strip llvm-readelf; do
	if ! command -v "${tool}" >/dev/null; then
		echo "release-build.sh: '${tool}' not found on \$PATH." >&2
		echo "  Install with 'apt install llvm' on Debian/Ubuntu (or your distro's equivalent)." >&2
		exit 1
	fi
done

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
#
# We previously tried a round of LLVM-args size levers
# (machine-outliner, linkonceodr-outlining, global-merge-func,
# inline-threshold=50) plus LLD --icf=safe. The empirical gain
# was small relative to the operational cost: --icf was outright
# rejected by zigcc's arg-allowlist (rust-cross/cargo-zigbuild#162),
# and the LLVM-args flag names drift between LLVM versions
# (mergefunc → enable-global-merge-func already). Reverted in
# favour of keeping the rustflags stable.
export CARGO_BUILD_RUSTFLAGS="--remap-path-scope=all \
${CRATES_REMAP} \
--remap-path-prefix=${HOME}/.rustup/toolchains/=tc/ \
--remap-path-prefix=${REPO}/=./"

cd "${REPO}"
cargo zigbuild --release --locked --target "${TARGET}" \
	--bin symbolon --bin git-credential-symbolon

# Drop stack-unwind tables. Safe because panic = "abort" — see the
# matching step in .github/workflows/release.yml for the full
# rationale. Stripping is applied to both shipped binaries: the
# daemon (`symbolon`) and the client helper
# (`git-credential-symbolon`).
#
# `llvm-strip` rather than GNU `strip`: host binutils is built
# single-target, so on an x86_64 host the bare `strip` cannot
# recognise an aarch64 ELF input. `llvm-strip` is multi-target
# by design and is CLI-compatible with GNU strip for the flags
# we use here. Install with `apt install llvm` (or your distro's
# equivalent) if it isn't already on $PATH.
for name in symbolon git-credential-symbolon; do
	BIN="target/${TARGET}/release/${name}"
	BEFORE="$(stat -c%s "${BIN}")"
	llvm-strip --strip-debug \
		--remove-section=.eh_frame \
		--remove-section=.eh_frame_hdr \
		--remove-section=.gcc_except_table \
		"${BIN}"
	AFTER="$(stat -c%s "${BIN}")"
	echo "Stripped ${BIN}: ${BEFORE} -> ${AFTER} bytes ($((BEFORE - AFTER)) saved)"
	# Belt-and-braces: confirm the sections we just asked to remove
	# are actually gone. Catches a silent no-op (wrong flag name on
	# a future llvm-strip version, etc.) before the binary ships.
	if llvm-readelf -S "${BIN}" | grep -qE '\.eh_frame|\.gcc_except_table'; then
		echo "unwind sections still present in ${BIN} after strip" >&2
		exit 1
	fi
	ls -l "${BIN}"
done
