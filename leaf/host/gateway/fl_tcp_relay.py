#!/usr/bin/env python3
"""Byte relay for the leaf's Wi-Fi link. It accepts the leaf's outbound TCP
connection on the gateway's LAN address and copies bytes to and from one
upstream TCP endpoint on loopback (an ssh tunnel to the node that holds the
keys). It holds no key and makes no decision.

  fl_tcp_relay.py LAN_ADDR:PORT 127.0.0.1:UPSTREAM_PORT

Bind it to the LAN address in the leaf's signed config, never to 0.0.0.0,
so the port is not offered on other interfaces (overlay, VPN). One leaf
connection at a time; a redial replaces the previous one, as the controller
does. Each connection is logged on stderr with its peer address.
"""

import select
import socket
import sys
import time


def addr(s):
    h, p = s.rsplit(":", 1)
    return h, int(p)


def log(m):
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {m}", file=sys.stderr, flush=True)


def main():
    listen, upstream = addr(sys.argv[1]), addr(sys.argv[2])
    if listen[0] in ("0.0.0.0", "::", ""):
        sys.exit("bind to the leaf's LAN address, not a wildcard")
    if upstream[0] not in ("127.0.0.1", "::1", "localhost"):
        sys.exit("the upstream must be on loopback")
    srv = socket.create_server(listen)
    pair = None  # (leaf socket, upstream socket)

    def close():
        nonlocal pair
        for k in pair or ():
            try:
                k.close()
            except OSError:
                pass
        pair = None

    while True:
        r, _, _ = select.select([srv] + list(pair or ()), [], [], 1.0)
        if srv in r:
            k, peer = srv.accept()
            close()
            try:
                u = socket.create_connection(upstream, timeout=5)
            except OSError as e:
                log(f"{peer[0]}: upstream unreachable: {e}")
                k.close()
                continue
            for s in (k, u):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.settimeout(None)
            pair = (k, u)
            log(f"leaf connected from {peer[0]}:{peer[1]}")
            continue
        if not pair:
            continue
        for a, b in (pair, pair[::-1]):
            if a in r:
                try:
                    d = a.recv(65536)
                except OSError:
                    d = b""
                if not d:
                    close()
                    break
                try:
                    b.sendall(d)
                except OSError:
                    close()
                    break


if __name__ == "__main__":
    main()
