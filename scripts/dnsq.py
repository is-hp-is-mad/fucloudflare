"""End-to-end DNS smoke check: python scripts/dnsq.py HOST PORT NAME TYPE [tcp]

Sends one raw query and prints rcode, flags and decoded records.
"""
import socket
import struct
import sys

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}
NAMES = {v: k for k, v in TYPES.items()}


def read_name(b, p):
    labels, end = [], None
    while True:
        n = b[p]
        if n == 0:
            p += 1
            break
        if n & 0xC0 == 0xC0:
            if end is None:
                end = p + 2
            p = struct.unpack("!H", b[p:p + 2])[0] & 0x3FFF
            continue
        labels.append(b[p + 1:p + 1 + n].decode())
        p += 1 + n
    return ".".join(labels), end or p


def main():
    host, port, name, qtype = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    tcp = len(sys.argv) > 5
    q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(l)]) + l.encode() for l in name.strip(".").split(".")) + b"\0"
    q += struct.pack("!HH", TYPES[qtype], 1)
    if tcp:
        s = socket.create_connection((host, port), timeout=3)
        s.sendall(struct.pack("!H", len(q)) + q)
        data = b""
        while len(data) < 2 or len(data) < 2 + struct.unpack("!H", data[:2])[0]:
            data += s.recv(65535)
        b = data[2:]
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(q, (host, port))
        b = s.recv(65535)
    _, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", b[:12])
    print(f"{name} {qtype}{' tcp' if tcp else ''}: rcode={flags & 15} aa={flags >> 10 & 1} tc={flags >> 9 & 1} an={an} ns={ns} ar={ar}")
    _, p = read_name(b, 12)
    p += 4
    for i in range(an + ns + ar):
        owner, p = read_name(b, p)
        t, _, ttl, rdlen = struct.unpack("!HHIH", b[p:p + 10])
        rd = b[p + 10:p + 10 + rdlen]
        if t == 1:
            val = socket.inet_ntoa(rd)
        elif t in (2, 5):
            val = read_name(b, p + 10)[0]
        elif t == 15:
            val = f"{struct.unpack('!H', rd[:2])[0]} {read_name(b, p + 12)[0]}"
        elif t == 6:
            m, p2 = read_name(b, p + 10)
            r, p2 = read_name(b, p2)
            val = f"{m} {r} serial={struct.unpack('!I', b[p2:p2 + 4])[0]}"
        else:
            val = rd.hex()
        sec = "AN" if i < an else "NS" if i < an + ns else "AR"
        print(f"  {sec} {owner} {ttl} {NAMES.get(t, t)} {val}")
        p += 10 + rdlen


main()
