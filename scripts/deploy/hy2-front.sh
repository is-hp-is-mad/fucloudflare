#!/usr/bin/env bash
# Runs ON a node (as root). UDP 443 on these nodes belongs to a Hysteria 2
# server. This gives it a "masquerade": whoever speaks ordinary HTTP/3 to it
# (anything that is not a Hysteria client) is passed on to the fucf edge
# next door, which answers as the CDN. Hysteria clients are not affected.
#
# What visitors get to see is Hysteria's certificate, so browsers only use
# HTTP/3 for host names that certificate covers -- and fucf only advertises
# it for those (FUCF_H3_FRONT_CERT, written by install-node.sh).
#
# The change is one block appended to the configuration, followed by a
# restart of the Hysteria service (its clients reconnect). If Hysteria does
# not come back, or HTTP/3 does not reach fucf, the previous configuration
# is put back. Undo by hand: cp /etc/hysteria/config.yaml.pre-fucf-front
# /etc/hysteria/config.yaml; systemctl restart hysteria-server
set -euo pipefail
CFG=/etc/hysteria/config.yaml
UNIT=hysteria-server
FRONT=${1:-${FRONT:-127.0.0.1:18480}}

[ -f "$CFG" ] || { echo "no $CFG on this node: nothing to do"; exit 0; }
# HTTP/3 to the local Hysteria: under a name its certificate covers if it
# has one (it may insist on that, see hy2-sni.sh), else by the node's address.
probe() {
    local host cert
    cert=$(awk '$1 == "tls:" { tls = 1; next } /^[^ #]/ { tls = 0 } tls && $1 == "cert:" { print $2; exit }' "$CFG")
    host=$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null | grep -o 'DNS:[^, ]*' | head -1 | sed 's/^DNS://; s/^\*\./h3-probe./')
    [ -n "$host" ] || host=$(sed -n 's/^FUCF_EDGE_IPS=\([^,]*\).*/\1/p' /etc/fucf/fucf.env)
    /usr/local/bin/fucf h3-get "https://$host/cdn-cgi/fucf-trace" --connect 127.0.0.1 --insecure 2>&1
}
works() {
    systemctl is-active --quiet "$UNIT" || return 1
    probe | grep -qE '^fl=[0-9]+f[0-9]+'
}

if grep -qE '^masquerade:' "$CFG"; then
    if grep -q "http://$FRONT" "$CFG"; then
        if works; then echo "already in place: HTTP/3 on UDP 443 is answered by fucf"; exit 0; fi
        echo "the masquerade is configured, but HTTP/3 does not reach fucf:" >&2; probe >&2 || true; exit 1
    fi
    echo "$CFG has a masquerade of its own: leaving it alone" >&2; exit 1
fi
ss -ltnH "sport = :${FRONT##*:}" | grep -q . || { echo "fucf does not listen on $FRONT: deploy the current build first" >&2; exit 1; }

cp -p "$CFG" "$CFG.pre-fucf-front"
cat >> "$CFG" <<YAML

# Ordinary HTTP/3 clients are passed on to the fucf edge (scripts/deploy/hy2-front.sh).
masquerade:
  type: proxy
  proxy:
    url: http://$FRONT
    rewriteHost: false
    xForwarded: true
YAML
systemctl restart "$UNIT"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    if works; then
        echo "HTTP/3 on UDP 443 is answered by fucf now:"
        probe | grep -E '^(HTTP/3|fl=|ip=|http=|h=)' | sed 's/^/  /'
        exit 0
    fi
done
echo "!!!! that did not work: putting the previous Hysteria configuration back" >&2
probe >&2 || true
cp -p "$CFG.pre-fucf-front" "$CFG"
systemctl restart "$UNIT"
sleep 2
systemctl is-active "$UNIT" >&2
exit 1
