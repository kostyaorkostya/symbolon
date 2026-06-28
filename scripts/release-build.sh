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

# Preflight + resolve: `llvm-strip` and `llvm-readelf` are the
# multi-target stand-ins for GNU `strip` / `readelf`. The host
# binutils is single-target, so a bare `strip` cannot recognise the
# cross-compiled aarch64 ELF emitted by `cargo zigbuild --target
# aarch64-unknown-linux-musl` on an x86_64 host. The unversioned
# `/usr/bin/llvm-strip` symlink is only installed by the `llvm`
# metapackage; Clang-installed-via-apt brings in `llvm-strip-N`
# only. Try the unversioned name first; fall back to common
# versioned names. Fail-fast with an actionable hint otherwise.
#
# `|| true` defends against `set -e` + `pipefail`: when none of the
# candidates exist, `command -v` exits 1 and pipefail propagates;
# without the swallow, the script dies silently HERE — before reaching
# the diagnostic check below.
find_first_cmd() {
	for cand in "$@"; do
		if command -v "$cand" >/dev/null 2>&1; then
			printf '%s\n' "$cand"
			return 0
		fi
	done
	return 1
}
LLVM_STRIP="$(find_first_cmd llvm-strip llvm-strip-21 llvm-strip-20 llvm-strip-19 llvm-strip-18 llvm-strip-17 || true)"
LLVM_READELF="$(find_first_cmd llvm-readelf llvm-readelf-21 llvm-readelf-20 llvm-readelf-19 llvm-readelf-18 llvm-readelf-17 || true)"
for var in LLVM_STRIP LLVM_READELF; do
	if [ -z "${!var}" ]; then
		echo "release-build.sh: no ${var,,} binary found on \$PATH." >&2
		echo "  Install with 'apt install llvm' on Debian/Ubuntu (or your distro's equivalent)." >&2
		exit 1
	fi
done
echo "using ${LLVM_STRIP} and ${LLVM_READELF}"

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
# Use the `$LLVM_STRIP` / `$LLVM_READELF` paths resolved by the
# preflight at the top of this script. See the comment block there
# for why we don't just call bare `strip`.
for name in symbolon git-credential-symbolon; do
	BIN="target/${TARGET}/release/${name}"
	BEFORE="$(stat -c%s "${BIN}")"
	"${LLVM_STRIP}" --strip-debug \
		--remove-section=.eh_frame \
		--remove-section=.eh_frame_hdr \
		--remove-section=.gcc_except_table \
		"${BIN}"
	AFTER="$(stat -c%s "${BIN}")"
	echo "Stripped ${BIN}: ${BEFORE} -> ${AFTER} bytes ($((BEFORE - AFTER)) saved)"
	# Belt-and-braces: confirm the sections we just asked to remove
	# are actually gone. Catches a silent no-op (wrong flag name on
	# a future llvm-strip version, etc.) before the binary ships.
	if "${LLVM_READELF}" -S "${BIN}" | grep -qE '\.eh_frame|\.gcc_except_table'; then
		echo "unwind sections still present in ${BIN} after strip" >&2
		exit 1
	fi
	ls -l "${BIN}"
done
