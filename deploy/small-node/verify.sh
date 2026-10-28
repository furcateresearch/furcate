#!/bin/sh
# Check an installed small processing node. Light: one replay of a recorded
# capture in memory and a read of the node's identity. It changes nothing.
#
#   verify.sh CAPTURE SSH-COMMAND...
#
# CAPTURE is crates/open/furcate-sense/tests/fixtures/nicla-standalone-usb.txt
# from the checkout that was deployed.
set -eu
cap=${1:?capture}; shift
{
    echo 'set -eu'
    echo 't=$(mktemp -d /tmp/furcate-small-verify.XXXXXX)'
    echo 'trap "rm -rf $t" EXIT'
    echo 'base64 -d > "$t/capture.txt" <<'"'B64'"
    base64 < "$cap"
    echo B64
    cat <<'EOS'
echo '--- identity'
/opt/tools/furcate-small identity --backend rpi-fw-crypto
echo '--- replay'
/opt/tools/furcate-small replay "$t/capture.txt"
echo '--- unit'
systemctl is-enabled furcate-small-node.service || true
systemctl is-active furcate-small-node.service || true
EOS
} | "$@" sh -s
