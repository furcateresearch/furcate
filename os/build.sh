#!/bin/sh
# Build a Furcate OS image for one board. Run as root on the build host from a
# clean checkout; each step is resumable.
#
#   os/build.sh <board> version                 print the version this commit builds
#   os/build.sh <board> preflight               check every tool the steps below need
#   os/build.sh <board> extension <bin-dir> [open|full]  stage the furcate extension (unsigned; open by default)
#     ... sign <out>/ext/roothash with os/release/sign-on, then:
#   os/build.sh <board> seal <signature.b64>    seal the extension with that signature
#   os/build.sh <board> hw-extension <base-usr-list>
#                                               stage the board userspace extension
#                                               (hw-<board>) for a base without it
#   os/build.sh <board> hw-seal <signature.b64> seal it (sign <out>/hw/roothash first)
#   os/build.sh <board> model-extension <base-usr-list>
#                                               stage the model-server extension
#                                               (the inference runtime)
#   os/build.sh <board> model-seal <signature.b64>
#                                               seal it (sign <out>/model/roothash first)
#   os/build.sh <board> leafhead-extension <base-usr-list> <leaf-firmware-checkout>
#                                               stage the leaf-head extension (the head
#                                               service and Python's cryptography); the
#                                               head's code is built from that checkout
#   os/build.sh <board> leafhead-seal <signature.b64>
#                                               seal it (sign <out>/leafhead/roothash first)
#   os/build.sh <board> image                   assemble the disk image with mkosi
#     ... sign <out>/<image>.sha256 with os/release/sign-on, then:
#   os/build.sh <board> finish <signature.b64>  attach and check the image signature
#
# Output: $FURCATE_OS_OUT/<version>/ (default /srv/build/furcate-os/out).
# The heavy steps run under a memory cap. When the caller already applies one
# (a capped build wrapper), set FURCATE_OS_CAPPED=1: a nested systemd-run
# scope would move the work out of the caller's cap. $MKOSI names the mkosi
# to run (default: mkosi on PATH).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
board=${1:?usage: os/build.sh <board> <step> ...}
step=${2:?usage: os/build.sh <board> <step> ...}
shift 2
case "$board" in rpi5) arch=arm64 ;; *) echo "unknown board $board" >&2; exit 2 ;; esac

sha=$(git -C "$repo" rev-parse --short HEAD)
n=$(git -C "$repo" rev-list --count HEAD)
dirty=""
[ -z "$(git -C "$repo" status --porcelain)" ] || dirty="+dirty"
version="1.0.$n-$sha$dirty"
if [ -n "$dirty" ] && [ "${FURCATE_ALLOW_DIRTY:-0}" != 1 ] && [ "$step" != version ]; then
    echo "refusing: the checkout has uncommitted changes; a release is built from a commit" >&2
    exit 1
fi
out="${FURCATE_OS_OUT:-/srv/build/furcate-os/out}/$version"
name="furcate-os-$board-$version"
# Everything a step needs, checked before it starts, so a missing tool fails
# in seconds and not an hour into a build.
preflight() {
    missing=""
    for t in "$@"; do
        case "$t" in
            py:*) mod=${t#py:}
                  "$mkosi_python" -c "import $mod" 2>/dev/null || missing="$missing\n  python module '$mod' for $mkosi_python" ;;
            *) command -v "$t" >/dev/null 2>&1 || missing="$missing\n  $t" ;;
        esac
    done
    if [ -n "$missing" ]; then
        printf 'preflight: missing on this build host:%b\n' "$missing" >&2
        exit 1
    fi
}
mkosi_bin=$(command -v "${MKOSI:-mkosi}" || true)
mkosi_python=python3
if [ -n "$mkosi_bin" ]; then
    shebang=$(head -1 "$mkosi_bin" | sed -n 's/^#! *//p' | awk '{print $1}')
    case "$shebang" in */python*) mkosi_python=$shebang ;; esac
fi
tools_extension="systemd-repart mkfs.erofs sfdisk python3 file sha256sum openssl dd"
# mkosi with Format=disk: package manager and sandbox, repart and the file
# systems it formats, mtools for the FAT boot partitions, zstd for the release;
# pefile because mkosi inspects kernel images with it.
tools_image="${MKOSI:-mkosi} bwrap apt-get dpkg systemd-repart mkfs.erofs mkfs.vfat mkfs.ext4 mcopy sfdisk zstd python3 openssl cmp py:pefile"
tools_test="qemu-system-aarch64 dtc mcopy sfdisk zstd ssh ssh-keyscan python3"

capped() {
    if [ "${FURCATE_OS_CAPPED:-0}" = 1 ]; then "$@"
    else systemd-run --quiet --scope -p MemoryMax="${FURCATE_OS_MEM:-16G}" -p MemorySwapMax=0 nice -n 10 "$@"; fi
}

case "$step" in
version)
    echo "$version"
    ;;
preflight)
    preflight $tools_extension $tools_image $tools_test
    echo "preflight: every tool for extension, image and test is present (mkosi python: $mkosi_python)"
    ;;
extension)
    bins=${1:?usage: os/build.sh <board> extension <bin-dir> [open|full]}
    preflight $tools_extension
    capped "$here/extensions/furcate/build" stage "$bins" "$out/ext" "$version" "$arch" "${2:-open}"
    echo "next: sign $out/ext/roothash, then os/build.sh $board seal <signature.b64>"
    ;;
seal)
    "$here/extensions/furcate/build" seal "$out/ext" "${1:?signature file}"
    ;;
hw-extension)
    list=${1:?usage: os/build.sh <board> hw-extension <base-usr-list>}
    preflight $tools_extension dpkg-deb comm
    capped "$here/extensions/hw-$board/build" stage "$list" "$out/hw" "$version" "$arch"
    echo "next: sign $out/hw/roothash, then os/build.sh $board hw-seal <signature.b64>"
    ;;
hw-seal)
    "$here/extensions/hw-$board/build" seal "$out/hw" "${1:?signature file}"
    ;;
model-extension)
    list=${1:?usage: os/build.sh <board> model-extension <base-usr-list>}
    preflight $tools_extension curl tar xz readelf
    capped "$here/extensions/modelserver/build" stage "$list" "$out/model" "$version" "$arch"
    echo "next: sign $out/model/roothash, then os/build.sh $board model-seal <signature.b64>"
    ;;
model-seal)
    "$here/extensions/modelserver/build" seal "$out/model" "${1:?signature file}"
    ;;
leafhead-extension)
    list=${1:?usage: os/build.sh <board> leafhead-extension <base-usr-list> <leaf-firmware-checkout>}
    leaf=${2:?usage: os/build.sh <board> leafhead-extension <base-usr-list> <leaf-firmware-checkout>}
    preflight $tools_extension dpkg-deb comm readelf git
    capped "$here/extensions/leafhead/build" stage "$list" "$out/leafhead" "$version" "$arch" "$leaf"
    echo "next: sign $out/leafhead/roothash, then os/build.sh $board leafhead-seal <signature.b64>"
    ;;
leafhead-seal)
    "$here/extensions/leafhead/build" seal "$out/leafhead" "${1:?signature file}"
    ;;
image)
    preflight $tools_image
    [ -f "$out/ext/furcate.raw" ] || { echo "no sealed extension in $out/ext" >&2; exit 1; }
    # The store directory is the extension's own version: the boot selector
    # refuses an extension whose FURCATE_VERSION does not match its directory,
    # and the seeded extension may come from an earlier build than the base.
    extver=$(sed -n 's/^FURCATE_VERSION=//p' "$out/ext/furcate.release" | tr -d '"' | tail -1)
    case "$extver" in
        ''|*/*|.*) echo "$out/ext/furcate.release has no usable FURCATE_VERSION" >&2; exit 1 ;;
    esac
    [ "$extver" = "$version" ] || echo "seeding furcate extension $extver into base $version"
    seed="$out/seed/var/lib/furcate/extensions/furcate/$extver"
    rm -rf "$out/seed"
    mkdir -p "$seed"
    cp "$out/ext/furcate.raw" "$out/ext/furcate.release" "$seed/"
    cmp -s "$repo/deploy/os/furcate-release.crt" "$here/rootfs/usr/lib/verity.d/furcate-release.crt" \
        || { echo "os/rootfs/usr/lib/verity.d/furcate-release.crt differs from deploy/os/furcate-release.crt" >&2; exit 1; }
    mkdir -p "$out/mkosi" "${FURCATE_OS_CACHE:-/srv/build/furcate-os/cache}"
    capped "${MKOSI:-mkosi}" -C "$here" --profile "$board" --image-version "$version" \
        --extra-tree "$out/seed:/" \
        --output-directory "$out/mkosi" \
        --workspace-directory "${FURCATE_OS_WORK:-/srv/build/furcate-os/work}" \
        --cache-directory "${FURCATE_OS_CACHE:-/srv/build/furcate-os/cache}" \
        --force build
    raw=$(ls "$out/mkosi/"*"_$version.raw" "$out/mkosi/"*.raw 2>/dev/null | head -1)
    [ -f "$raw" ] || { echo "mkosi produced no image" >&2; exit 1; }
    # Development access for a specific deployment: OpenSSH public keys from
    # $FURCATE_SSH_AUTHORIZED_KEYS are added to furcate-node.txt in both boot
    # slots (installed for the furcate account at first boot). Public keys only.
    if [ -n "${FURCATE_SSH_AUTHORIZED_KEYS:-}" ]; then
        if grep -q "PRIVATE KEY" "$FURCATE_SSH_AUTHORIZED_KEYS"; then
            echo "refusing: $FURCATE_SSH_AUTHORIZED_KEYS contains a private key" >&2; exit 1
        fi
        tmp=$(mktemp -d)
        for label in boot-a boot-b; do
            off=$(sfdisk -J "$raw" | python3 -c '
import json, sys
t = json.load(sys.stdin)["partitiontable"]
print([p for p in t["partitions"] if p.get("name") == sys.argv[1]][0]["start"] * t.get("sectorsize", 512))' "$label")
            mcopy -n -i "$raw@@$off" ::furcate-node.txt "$tmp/node.txt"
            printf '\n# Development access, added at build time.\n' >> "$tmp/node.txt"
            grep -E '^(ssh-|ecdsa-|sk-)' "$FURCATE_SSH_AUTHORIZED_KEYS" | sed 's/^/ssh_authorized_key=/' >> "$tmp/node.txt"
            mcopy -o -i "$raw@@$off" "$tmp/node.txt" ::furcate-node.txt
        done
        echo "added $(grep -cE '^(ssh-|ecdsa-|sk-)' "$FURCATE_SSH_AUTHORIZED_KEYS") SSH public key(s) to furcate-node.txt"
        rm -rf "$tmp"
    fi
    capped zstd -T4 -12 -f -q "$raw" -o "$out/$name.img.zst"
    (cd "$out" && sha256sum "$name.img.zst" > "$name.img.zst.sha256")
    cp "$repo/deploy/os/furcate-release.crt" "$out/furcate-release.crt"
    echo "next: sign $out/$name.img.zst.sha256, then os/build.sh $board finish <signature.b64>"
    ;;
finish)
    base64 -d < "${1:?signature file}" > "$out/$name.img.zst.sha256.p7s"
    openssl smime -verify -inform DER -in "$out/$name.img.zst.sha256.p7s" \
        -content "$out/$name.img.zst.sha256" -CAfile "$out/furcate-release.crt" \
        -purpose any -binary -out /dev/null
    (cd "$out" && sha256sum -c "$name.img.zst.sha256")
    echo "release: $out/$name.img.zst (+ .sha256, .sha256.p7s, furcate-release.crt)"
    ;;
*)
    echo "unknown step $step" >&2; exit 2 ;;
esac
