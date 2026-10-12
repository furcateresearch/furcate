#!/bin/sh
# Assemble the language and inference runtimes that ship inside the Furcate
# system extension.
#
#   ./deploy/runtimes.sh [--arch x86_64|aarch64] [--only node,python,llama] <out-dir>
#
# --arch defaults to this machine's. It names the machine the runtimes are for,
# not the one assembling them: a board extension is staged on a build host of
# another architecture, and nothing here executes the artefacts it fetches.
# --only limits the tree to the named components (default: all three).
#
# <out-dir> becomes /usr, so this writes:
#   <out>/lib/furcate/runtimes/node/bin/node       JavaScript applications
#   <out>/lib/furcate/runtimes/python/uv           Python applications
#   <out>/lib/furcate/runtimes/llama/llama-server  local model inference
#   <out>/lib/environment.d/60-furcate-runtimes.conf
#
# ## Why this file exists
#
# It did not, and that was the bug. `crates/open/furcatectl/src/deploy.rs` names
# /usr/lib/furcate/runtimes in the unit it writes for every supervised site, and
# nothing in this repository ever put anything there. The runtimes were unpacked
# onto one machine by hand.
#
# So the tree the code depends on was not reproducible, not versioned, and not
# reviewable, and a second node would have been silently missing it — which is
# precisely the drift a system extension exists to prevent. A runtime referenced
# by committed code has to be produced by committed code.
#
# ## Why the versions are pinned with digests
#
# /usr is read-only and delivered whole. An extension that fetched "latest" would
# make two nodes built a week apart run different interpreters while reporting
# the same Furcate version, and the difference would surface as an application
# bug rather than as a platform difference.
#
# Every digest is the publisher's: node and uv publish SHA-256 files beside
# their downloads, and llama.cpp's release assets carry the SHA-256 GitHub
# computed when they were uploaded (the `digest` field of the release API).
set -eu

NODE_VER=24.21.0
UV_VER=0.12.23

# ggml-org/llama.cpp. Serves an OpenAI-compatible API including tool calling,
# which is what lets an application treat a local model exactly like a cloud one.
#
# The VULKAN build, deliberately, for both kinds of node at once: it ships every
# CPU backend (libggml-cpu-*.so) alongside libggml-vulkan.so, so the same binary
# runs on a machine with no accelerator and offloads on one that has a card. The
# alternative — a CPU image and a GPU image — means the extension a node is
# running becomes another thing that can be wrong about it.
#
# Vulkan rather than CUDA because upstream publishes no Linux CUDA binaries at
# all (the cuda assets are Windows-only), and Vulkan drives NVIDIA, AMD and Intel
# from one artefact.
#
# The same flavour on arm64, for the same reason: one artefact serves a board
# with a Vulkan-capable GPU and a board with none. Which device a model runs on
# is decided per serve from what the runtime reports, and CPU serving is the
# operator's explicit choice (`furcatectl model serve --cpu`), never a quiet
# consequence of a missing driver.
LLAMA_VER=b10590

usage() { echo "usage: $0 [--arch x86_64|aarch64] [--only node,python,llama] <out-dir>" >&2; exit 2; }

arch=$(uname -m)
only=node,python,llama
OUT=
while [ $# -gt 0 ]; do
  case "$1" in
    --arch) [ $# -ge 2 ] || usage; arch=$2; shift 2 ;;
    --only) [ $# -ge 2 ] || usage; only=$2; shift 2 ;;
    -*) usage ;;
    *) [ -z "$OUT" ] || usage; OUT=$1; shift ;;
  esac
done
[ -n "$OUT" ] || usage

want() { case ",$only," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
for c in $(echo "$only" | tr ',' ' '); do
  case "$c" in node|python|llama) ;; *) echo "unknown component $c" >&2; usage ;; esac
done

# One row per architecture, every digest the publisher's. An architecture
# without a row refuses here rather than assembling a tree that fails on the
# node.
case "$arch" in
  x86_64|amd64|x86-64)
    arch=x86_64
    NODE_ARCH=x64
    NODE_SHA=fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6
    UV_TRIPLE=x86_64-unknown-linux-gnu
    UV_SHA=9167d72b3319674b6303c4cbe071854bba13ebdf3d76b1a7cbdc175471fb66d6
    LLAMA_FLAVOUR=vulkan-x64
    LLAMA_SHA=6932dafd63607aac1acaeceea13fe80e79058119bb6a0b54743504bf5016cd6c
    ;;
  aarch64|arm64)
    arch=aarch64
    NODE_ARCH=arm64
    NODE_SHA=6ad1325edbdb5649c379b75a237147a666c95d4f9ae8d340fef2d1575d289ad2
    UV_TRIPLE=aarch64-unknown-linux-gnu
    UV_SHA=6524bd338177ed50d035d39354e12545e993bbeba2ecbddf0480c5b3a81d313f
    LLAMA_FLAVOUR=vulkan-arm64
    LLAMA_SHA=695a004dc44a5059b7944639b3c124f1b3bdf0365914922f425a7257fafc437d
    ;;
  *)
    echo "REFUSING: no pinned runtimes for $arch (x86_64 and aarch64 are pinned)." >&2
    exit 1
    ;;
esac

for t in curl tar sha256sum xz; do
  command -v "$t" >/dev/null || { echo "missing $t" >&2; exit 1; }
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() {
  # fetch <url> <sha256> <dest>
  echo "  fetching $(basename "$3")"
  curl -fsSL --retry 3 --retry-delay 2 -o "$3" "$1"
  got=$(sha256sum "$3" | cut -d' ' -f1)
  [ "$got" = "$2" ] || {
    echo "REFUSING: digest mismatch for $1" >&2
    echo "  expected $2" >&2
    echo "  got      $got" >&2
    exit 1
  }
}

R="$OUT/lib/furcate/runtimes"
mkdir -p "$R"

# --- node -------------------------------------------------------------------
if want node; then
mkdir -p "$R/node"
fetch "https://nodejs.org/dist/v$NODE_VER/node-v$NODE_VER-linux-$NODE_ARCH.tar.xz" \
      "$NODE_SHA" "$work/node.tar.xz"
tar xJf "$work/node.tar.xz" -C "$work"
# --strip-components would work but this is explicit about what lands where.
cp -a "$work/node-v$NODE_VER-linux-$NODE_ARCH/." "$R/node/"
# Documentation and headers are a third of the tree and no application needs
# them at runtime. The extension is mounted on every node; size is not free.
rm -rf "$R/node/include" "$R/node/share/doc" "$R/node/share/man" \
       "$R/node/CHANGELOG.md" "$R/node/README.md"
fi

# --- uv ---------------------------------------------------------------------
# Python goes through uv rather than python3 -m venv: Debian splits out
# ensurepip, and /usr is read-only, so venv creation fails on exactly the second
# deploy of every Python site.
if want python; then
mkdir -p "$R/python"
fetch "https://github.com/astral-sh/uv/releases/download/$UV_VER/uv-$UV_TRIPLE.tar.gz" \
      "$UV_SHA" "$work/uv.tar.gz"
tar xzf "$work/uv.tar.gz" -C "$work"
find "$work" -name uv -type f -perm -u+x -exec cp {} "$R/python/uv" \;
find "$work" -name uvx -type f -perm -u+x -exec cp {} "$R/python/uvx" \;
chmod 755 "$R/python/uv" "$R/python/uvx" 2>/dev/null || true
fi

# --- llama.cpp --------------------------------------------------------------
if want llama; then
mkdir -p "$R/llama"
fetch "https://github.com/ggml-org/llama.cpp/releases/download/$LLAMA_VER/llama-$LLAMA_VER-bin-ubuntu-$LLAMA_FLAVOUR.tar.gz" \
      "$LLAMA_SHA" "$work/llama.tar.gz"
tar xzf "$work/llama.tar.gz" -C "$work"
# The server and the shared objects it loads. The rest of the release is
# benchmarking and conversion tools that a node serving a model does not run.
srv=$(find "$work" -name llama-server -type f | head -1)
[ -n "$srv" ] || { echo "llama-server not found in the release archive" >&2; exit 1; }
cp "$srv" "$R/llama/llama-server"
chmod 755 "$R/llama/llama-server"
find "$(dirname "$srv")" -maxdepth 1 -name '*.so*' -exec cp -a {} "$R/llama/" \;
# What this runtime is, readable without executing it.
printf 'llama.cpp %s %s sha256:%s\n' "$LLAMA_VER" "$LLAMA_FLAVOUR" "$LLAMA_SHA" > "$R/llama/VERSION"
fi

# --- PATH -------------------------------------------------------------------
# llama is deliberately absent from PATH. node and uv are invoked by name from
# build commands and unit files; llama-server is invoked by absolute path from
# the unit `furcatectl model serve` writes, and putting a model server on every
# process's PATH invites it being started outside that supervision.
if want node || want python; then
mkdir -p "$OUT/lib/environment.d"
cat > "$OUT/lib/environment.d/60-furcate-runtimes.conf" <<EOF
PATH=/usr/lib/furcate/runtimes/node/bin:/usr/lib/furcate/runtimes/python:\$PATH
EOF
fi

echo
echo "runtimes assembled in $OUT ($arch)"
if want node; then echo "  node        v$NODE_VER"; fi
if want python; then echo "  uv          $UV_VER"; fi
if want llama; then echo "  llama       $LLAMA_VER ($LLAMA_FLAVOUR)"; fi
echo "  total       $(du -sh "$R" | cut -f1)"
