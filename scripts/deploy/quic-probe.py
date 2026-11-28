#!/usr/bin/env python3
"""QUIC reachability probe: send an Initial-shaped packet with an unknown
version and expect a Version Negotiation reply listing QUIC v1.

    python3 quic-probe.py HOST PORT
"""
import os
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
dcid, scid = os.urandom(8), os.urandom(8)
packet = bytes([0xC0]) + bytes.fromhex("1a2a3a4a") + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
packet += bytes(1200 - len(packet))
family = socket.AF_INET6 if ":" in host else socket.AF_INET
s = socket.socket(family, socket.SOCK_DGRAM)
s.settimeout(4)
try:
    s.sendto(packet, (host, port))
    reply, _ = s.recvfrom(2048)
except OSError as e:
    print(f"{host}:{port} no QUIC reply ({e})")
    sys.exit(1)
ok = reply[0] & 0x80 and reply[1:5] == b"\0\0\0\0" and bytes.fromhex("00000001") in reply[5:]
print(f"{host}:{port} {'QUIC v1 endpoint answered (version negotiation)' if ok else 'unexpected reply ' + reply[:16].hex()}")
sys.exit(0 if ok else 1)
