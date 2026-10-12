#!/usr/bin/env python3
"""Byte relay between a leaf's USB serial console and one TCP client.

The machine running this holds no key and makes no decision: it copies bytes
both ways. The node (for example a controller signing with its TPM) reaches it
through an SSH reverse tunnel:

  fl_relay.py /dev/cu.usbserial-0001 7777 [console.log] &
  ssh -R 7777:127.0.0.1:7777 <controller> 'FL_PORT=tcp://127.0.0.1:7777 ...'

With no client connected, console output is still read (and logged when a
log path is given) so the client never receives stale frames.
"""

import select
import socket
import sys
import time

import serial  # pyserial


def main():
    port, tcp = sys.argv[1], int(sys.argv[2])
    log = open(sys.argv[3], "ab", buffering=0) if len(sys.argv) > 3 else None
    ser = serial.Serial(port, 115200, timeout=0)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", tcp))
    srv.listen(1)
    srv.setblocking(False)
    client = None
    while True:
        r, _, _ = select.select([srv] + ([client] if client else []), [], [], 0.01)
        if srv in r:
            c, _ = srv.accept()
            if client:
                client.close()
            client = c
            client.setblocking(True)
        if client and client in r:
            try:
                d = client.recv(4096)
            except OSError:
                d = b""
            if d:
                ser.write(d)
            else:
                client.close()
                client = None
        d = ser.read(4096)
        if d:
            if log:
                log.write(d)
            if client:
                try:
                    client.sendall(d)
                except OSError:
                    client.close()
                    client = None
        else:
            time.sleep(0.005)


if __name__ == "__main__":
    main()
