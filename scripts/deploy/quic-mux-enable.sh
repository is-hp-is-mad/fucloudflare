#!/usr/bin/env bash
# Runs ON a node (as root): quic-mux-enable.sh
#
# Moves Hysteria 2 from UDP 443 to 127.0.0.1:14443 and lets fucf own UDP 443
# directly with its built-in QUIC Initial SNI demultiplexer (--quic-fallback):
#   - Any SNI belonging to a zone hosted in fucf (or the panel / CNAME base)
#     is served natively by fucf's multi-domain HTTP/3 (QUIC) engine.
#   - All other SNIs / IP-direct / Hysteria 2 proxy traffic is transparently
#     forwarded to Hysteria 2 on 127.0.0.1:14443.
#
# Automatic rollback if either service fails to come up or HTTP/3 self-probe fails.
set -euo pipefail
FALLBACK_SNI=${1:-}
HY2_CFG=/etc/hysteria/config.yaml
FUCF_ENV=/etc/fucf/fucf.env
FB_ADDR=127.0.0.1:14443

[ -f "$HY2_CFG" ] || { echo "no $HY2_CFG on this node; nothing to mux"; exit 0; }
[ -f "$FUCF_ENV" ] || { echo "no $FUCF_ENV on this node" >&2; exit 1; }

[ -e "$HY2_CFG.pre-quic-mux" ] || cp -p "$HY2_CFG" "$HY2_CFG.pre-quic-mux"
[ -e "$FUCF_ENV.pre-quic-mux" ] || cp -p "$FUCF_ENV" "$FUCF_ENV.pre-quic-mux"
cp -p "$HY2_CFG" "$HY2_CFG.before-mux"
cp -p "$FUCF_ENV" "$FUCF_ENV.before-mux"

rollback() {
    echo "!!!! quic-mux failed; rolling back Hysteria 2 and fucf" >&2
    cp -p "$FUCF_ENV.before-mux" "$FUCF_ENV"
    systemctl restart fucf || true
    cp -p "$HY2_CFG.before-mux" "$HY2_CFG"
    systemctl restart hysteria-server || true
    rm -f "$HY2_CFG.before-mux" "$FUCF_ENV.before-mux"
    exit 1
}

# 1. Move Hysteria 2 listen address to 127.0.0.1:14443 (frees UDP 443).
python3 - "$HY2_CFG" "$FB_ADDR" <<'PY'
import re, sys
p, fb = sys.argv[1], sys.argv[2]
txt = open(p).read()
if re.search(r'^listen:\s*', txt, flags=re.M):
    txt = re.sub(r'^listen:.*$', f'listen: {fb}', txt, count=1, flags=re.M)
else:
    txt = f'listen: {fb}\n' + txt
open(p, 'w').write(txt)
PY
systemctl restart hysteria-server || rollback
sleep 1
systemctl is-active --quiet hysteria-server || rollback

# 2. Switch fucf to native UDP 443 QUIC SNI mux with fallback -> 127.0.0.1:14443,
#    while keeping 127.0.0.1:18480 open as a plain-HTTP masquerade safety net for Hysteria 2
#    (without FUCF_H3_FRONT_CERT, so Alt-Svc is driven by fucf's multi-domain native QUIC).
python3 - "$FUCF_ENV" "$FB_ADDR" "$FALLBACK_SNI" <<'PY'
import sys
p, fb, fb_sni = sys.argv[1], sys.argv[2], sys.argv[3]
lines = [l for l in open(p).read().splitlines()
         if not l.startswith(('FUCF_HTTP3_LISTEN=', 'FUCF_QUIC_FALLBACK=', 'FUCF_QUIC_FALLBACK_SNI=', 'FUCF_H3_FRONT_LISTEN=', 'FUCF_H3_FRONT_CERT='))]
lines.append('FUCF_HTTP3_LISTEN=[::]:443')
lines.append(f'FUCF_QUIC_FALLBACK={fb}')
lines.append('FUCF_H3_FRONT_LISTEN=127.0.0.1:18480')
if fb_sni:
    lines.append(f'FUCF_QUIC_FALLBACK_SNI={fb_sni}')
open(p, 'w').write('\n'.join(lines) + '\n')
PY
systemctl restart fucf || rollback

# 3. Verify both services and native HTTP/3 over UDP 443.
ok=
for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    if systemctl is-active --quiet fucf && systemctl is-active --quiet hysteria-server \
        && /usr/local/bin/fucf h3-get https://cdn.fucloudflare.com/cdn-cgi/fucf-trace --connect 127.0.0.1 2>&1 | grep -q '^HTTP/3'; then
        ok=yes
        break
    fi
done
[ -n "$ok" ] || rollback

rm -f "$HY2_CFG.before-mux" "$FUCF_ENV.before-mux"
echo "QUIC SNI mux active on $(hostname): UDP 443 -> native multi-domain fucf H3 + fallback $FB_ADDR"
/usr/local/bin/fucf h3-get https://cdn.fucloudflare.com/cdn-cgi/fucf-trace --connect 127.0.0.1 | grep -E '^(HTTP/3|fl=|colo=|dc=|http=)'
