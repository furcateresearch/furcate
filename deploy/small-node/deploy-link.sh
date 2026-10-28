#!/bin/sh
# Install the leaf link on a board. Read this before running it.
#
#   deploy-link.sh --released BINARY SHA256 SSH-COMMAND...
#
# The same method as deploy.sh, for furcate-leaf-link: the binary under
# /opt/tools and the unit under /etc/systemd/system, hash checked on the board,
# systemd reloaded. It writes no configuration, enrols no leaf and does not
# enable or start the service. It does not read the board's key: see the
# README for what reading it takes.
set -eu
[ "${1:-}" = "--released" ] || { echo "refusing: pass --released once the board is free (see deploy.sh)" >&2; exit 2; }
bin=${2:?binary}; want=${3:?sha256}; shift 3
here=$(cd "$(dirname "$0")" && pwd)
got=$(sha256sum "$bin" | cut -d' ' -f1)
[ "$got" = "$want" ] || { echo "refusing: $bin is $got, not $want" >&2; exit 1; }
{
    echo 'set -eu'
    echo 't=$(mktemp -d /tmp/furcate-leaf-link-deploy.XXXXXX)'
    echo 'trap "rm -rf $t" EXIT'
    echo 'base64 -d > "$t/furcate-leaf-link" <<'"'B64'"
    base64 < "$bin"
    echo B64
    echo 'base64 -d > "$t/unit" <<'"'B64'"
    base64 < "$here/furcate-leaf-link.service"
    echo B64
    echo "want=$want"
    cat <<'EOS'
got=$(sha256sum "$t/furcate-leaf-link" | cut -d' ' -f1)
[ "$got" = "$want" ] || { echo "hash differs on the board" >&2; exit 1; }
sudo install -d -m 755 /opt/tools
sudo install -m 755 "$t/furcate-leaf-link" /opt/tools/furcate-leaf-link
sudo install -m 644 "$t/unit" /etc/systemd/system/furcate-leaf-link.service
sudo systemctl daemon-reload
EOS
} | "$@" sh -s
echo "installed; the service is not enabled. Next: the README."
