#!/bin/sh
# Install the small processing node on a board. Read this before running it.
#
#   deploy.sh --released BINARY SHA256 SSH-COMMAND...
#
# SSH-COMMAND is the command that reaches the board as the `furcate` account,
# for example:  ssh JUMP-HOST ssh -o BatchMode=yes furcate@BOARD-ADDRESS
#
# It sends the binary and the unit as a script on standard input (so the same
# command works through a jump host), checks the hash on the board, installs
# the binary under /opt/tools and the unit under /etc/systemd/system, and
# reloads systemd. It writes no configuration, enrols nothing, and does not
# enable or start the service: that is the README, after the operator has
# written /etc/furcate/small-node.env.
#
# Do not run it on a board while another session is measuring it or an update
# is planned for it. --released says someone has checked that.
set -eu
[ "${1:-}" = "--released" ] || { echo "refusing: pass --released once the board is free (see the header)" >&2; exit 2; }
bin=${2:?binary}; want=${3:?sha256}; shift 3
here=$(cd "$(dirname "$0")" && pwd)
got=$(sha256sum "$bin" | cut -d' ' -f1)
[ "$got" = "$want" ] || { echo "refusing: $bin is $got, not $want" >&2; exit 1; }
{
    echo 'set -eu'
    echo 't=$(mktemp -d /tmp/furcate-small-deploy.XXXXXX)'
    echo 'trap "rm -rf $t" EXIT'
    echo 'base64 -d > "$t/furcate-small" <<'"'B64'"
    base64 < "$bin"
    echo B64
    echo 'base64 -d > "$t/unit" <<'"'B64'"
    base64 < "$here/furcate-small-node.service"
    echo B64
    echo "want=$want"
    cat <<'EOS'
got=$(sha256sum "$t/furcate-small" | cut -d' ' -f1)
[ "$got" = "$want" ] || { echo "hash differs on the board" >&2; exit 1; }
sudo install -d -m 755 /opt/tools
sudo install -m 755 "$t/furcate-small" /opt/tools/furcate-small
sudo install -m 644 "$t/unit" /etc/systemd/system/furcate-small-node.service
sudo systemctl daemon-reload
/opt/tools/furcate-small identity --backend rpi-fw-crypto
EOS
} | "$@" sh -s
echo "installed; the service is not enabled. Next: the README, then verify.sh."
