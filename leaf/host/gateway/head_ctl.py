#!/usr/bin/env python3
"""Sends one JSON request to the head's control socket, prints the answer."""
import json, socket, sys
path, req = sys.argv[1], json.loads(sys.argv[2])
if len(sys.argv) > 3:
    import base64
    req["input_b64"] = base64.b64encode(open(sys.argv[3], "rb").read()).decode()
if len(sys.argv) > 4:
    req["grant"] = json.load(open(sys.argv[4]))
k = socket.socket(socket.AF_UNIX); k.settimeout(150); k.connect(path)
k.sendall(json.dumps(req).encode() + b"\n")
b = b""
while not b.endswith(b"\n"):
    d = k.recv(65536)
    if not d: break
    b += d
print(b.decode().strip())
