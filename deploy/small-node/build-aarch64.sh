#!/bin/sh
# Cross-build furcate-small and furcate-leaf-link for a 64-bit Arm Linux board.
#
# Run on a Linux build host that has the Rust toolchain with the
# aarch64-unknown-linux-gnu target and the cross linker
# (aarch64-linux-gnu-gcc), from a clean checkout of the commit to deploy.
# Never on a board and never on a shared GPU host. Prints the SHA-256 of the
# result; deploy.sh refuses a binary whose hash it was not given.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
: "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR to a directory of its own for this checkout}"
command -v aarch64-linux-gnu-gcc >/dev/null || { echo "no aarch64-linux-gnu-gcc on this host" >&2; exit 1; }
cd "$repo"
git diff --quiet HEAD -- || { echo "the checkout has uncommitted changes; build a pushed commit" >&2; exit 1; }
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    nice -n 10 cargo build --release --target aarch64-unknown-linux-gnu -p furcate-leaf --bin furcate-small -p furcate-leaf-link --bin furcate-leaf-link -j 4
echo "commit  $(git rev-parse HEAD)"
for name in furcate-small furcate-leaf-link; do
    bin="$CARGO_TARGET_DIR/aarch64-unknown-linux-gnu/release/$name"
    echo "binary  $bin"
    sha256sum "$bin"
done
