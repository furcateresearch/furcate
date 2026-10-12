#!/bin/sh
# Packages fl-gateway as one self-contained file: a Python zipapp holding
# fl_gateway.py and the protocol module host/fl_proto.py. No Mac tooling.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here/fl-gateway.pyz}
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp "$here/fl_gateway.py" "$stage/__main__.py"
cp "$here/../fl_proto.py" "$stage/fl_proto.py"
python3 -m zipapp "$stage" -p "/usr/bin/env python3" -o "$out"
echo "$out"
