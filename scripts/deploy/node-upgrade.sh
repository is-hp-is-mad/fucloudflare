#!/usr/bin/env bash
# On a node, as root.
#   node-upgrade.sh status               what runs here and how this node sees the others (read-only)
#   node-upgrade.sh deploy TAG SHA256    binary-only upgrade to release TAG, whose binary has this SHA-256
# The upgrade leaves /etc/fucf/fucf.env and the unit alone, keeps the build before as
# /usr/local/bin/fucf.prev, turns the running process into the new binary with SIGUSR2 (its
# listeners stay open), and puts the build before back when the node is not healthy on the new one.
set -euo pipefail
trap 'echo "exit $?"' EXIT
[ "$(id -u)" = 0 ] || { echo "!!!! run as root"; exit 5; }
. /etc/fucf/fucf.env
api() { curl -fsS -m 8 -K <(printf 'header = "Authorization: Bearer %s"\n' "$FUCF_API_TOKEN") "http://127.0.0.1:8787/client/v4$1"; }
running() { api /system | python3 -c 'import sys, json; print(json.load(sys.stdin)["result"].get("exe") or "")'; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

if [ "${1:-}" = status ]; then
    api /system | python3 -c '
import sys, json
r = json.load(sys.stdin)["result"]
print("%s (%s) running %s, configuration %s" % (r.get("node"), r.get("role"), (r.get("exe") or "")[:12], (r.get("version") or "")[:10]))
for name, p in sorted((r.get("peers") or {}).items()):
    print("  %-4s %-7s %-9s %s" % (name, "online" if p.get("online") else "OFFLINE", "in sync" if p.get("in_sync") else "DIFFERENT", (p.get("exe") or "")[:12]))
'
    exit 0
fi

tag=${2:-} want=${3:-}
[ "${1:-}" = deploy ] && [ -n "$tag" ] && [ "${#want}" = 64 ] || { echo "usage: $0 status | deploy TAG SHA256"; exit 2; }
exec 9> /run/fucf-upgrade.lock
flock -n 9 || { echo "!!!! another upgrade is under way here"; exit 4; }
if [ "$(sha /usr/local/bin/fucf)" = "$want" ] && [ "$(running)" = "$want" ]; then
    echo "OK already running ${want:0:12}"; exit 0
fi
curl -fsSL --retry 3 -m 600 -o /tmp/fucf "https://github.com/is-hp-is-mad/fucloudflare/releases/download/$tag/fucf-linux-x86_64"
[ "$(sha /tmp/fucf)" = "$want" ] || { echo "!!!! the download is not build ${want:0:12}"; rm -f /tmp/fucf; exit 3; }

STATE=/var/lib/fucf/releases/state.json
cp -p /usr/local/bin/fucf /usr/local/bin/fucf.prev
[ -e "$STATE" ] && cp -p "$STATE" "$STATE.prev" || true
install -m 0755 /tmp/fucf /usr/local/bin/fucf
rm -f /tmp/fucf
healthy() {
    systemctl is-active --quiet fucf || return 1
    api /system > /dev/null || return 1
    python3 -c '
import socket, sys
q = bytes([0x5f, 0xcf, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, ("127.0.0.1", 5353)); r = s.recv(512)
sys.exit(0 if r[:2] == q[:2] and r[2] & 0x80 else 1)' 2>/dev/null
}
settled() {
    local good=0 restarts; restarts=$(systemctl show fucf -p NRestarts --value)
    for _ in $(seq 1 40); do
        sleep 1
        [ "$(systemctl show fucf -p NRestarts --value)" = "$restarts" ] || return 1
        if healthy; then good=$((good + 1)); else good=0; fi
        [ "$good" -ge 10 ] && return 0
    done; return 1
}
back() {
    journalctl -u fucf -n 15 --no-pager -o cat || true
    install -m 0755 /usr/local/bin/fucf.prev /usr/local/bin/fucf
    [ -e "$STATE.prev" ] && cp -p "$STATE.prev" "$STATE" || true
    systemctl restart fucf; settled && echo "!!!! the build before is back"
}
PID=$(systemctl show fucf -p MainPID --value); kill -USR2 "$PID"; sleep 3
[ "$(systemctl show fucf -p MainPID --value)" = "$PID" ] && echo "turned into the new binary in place (pid $PID)"
if ! settled; then echo "!!!! not healthy on the new build: going back"; back; exit 1; fi
now=$(running) || now=
if [ "$now" != "$want" ]; then echo "!!!! healthy, but still running ${now:0:12}: going back"; back; exit 3; fi
echo "OK running ${now:0:12}"
