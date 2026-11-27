#!/usr/bin/env bash
# Runs ON a node (as root). Installs fucf behind the existing haproxy SNI
# split and makes it the node's public DNS server.
#
# Expects /tmp/fucf (binary) and /tmp/fucf.service, and the environment:
#   NODE       node name (us / eu / au)
#   PRIMARY    name of the primary node (holds the configuration)
#   EDGE_IPS   public addresses of this node, comma separated
#   CACHE_MB   edge cache size
#   API_TOKEN  management API token (shared by the fleet)
#   NS_NAMES   name servers of the CDN domain, comma separated (optional)
#   RELEASE_KEY  public key that releases are signed with (optional; with
#              it the node takes the builds the fleet rolls out by itself)
#
# If the new build does not come up healthy, the previous binary and its
# configuration are put back and the script fails.
#
# Rollback: systemctl disable --now fucf; cp /etc/haproxy/haproxy.cfg.pre-fucf
# /etc/haproxy/haproxy.cfg; systemctl reload haproxy; docker start fucloudflare-edge;
# systemctl enable --now fucloudflare-geodns (us/eu)
set -euo pipefail
REPLACE_CADDY=${REPLACE_CADDY:-0}
for arg in "$@"; do
    case "$arg" in
        --replace-caddy) REPLACE_CADDY=1 ;;
        *) echo "unknown option: $arg" >&2; exit 1 ;;
    esac
done
NODE=${NODE:-${FUCF_NODE_NAME:-}}
: "${NODE:?}" "${PRIMARY:?}" "${EDGE_IPS:?}" "${CACHE_MB:?}" "${API_TOKEN:?}"
DOMAIN=${DOMAIN:-fucloudflare.com}
PANEL_HOST=${PANEL_HOST:-dashboard.${DOMAIN}}
CNAME_BASE=${CNAME_BASE:-cdn.${DOMAIN}}
NS_NAMES=${NS_NAMES:-ns1.${DOMAIN},ns2.${DOMAIN},ns3.${DOMAIN},ns4.${DOMAIN},ns5.${DOMAIN}}
ROLE=${ROLE:-${FUCF_ROLE:-peer}}
case "$ROLE" in
    peer|accelerate) ;;
    *) echo "invalid ROLE '$ROLE' (expected peer or accelerate)" >&2; exit 1 ;;
esac
PEERS=${PEERS:-${FUCF_PEERS:-}}
NODE_NAME=${NODE_NAME:-${FUCF_NODE_NAME:-$NODE}}
PROXY_LISTEN=${PROXY_LISTEN:-${FUCF_PROXY_LISTEN:-}}
PROXY_TLS_LISTEN=${PROXY_TLS_LISTEN:-${FUCF_PROXY_TLS_LISTEN:-}}
# Where Hysteria (UDP 443) hands ordinary HTTP/3 visitors to fucf, see hy2-front.sh.
FRONT=${FRONT:-127.0.0.1:18480}
if [ "$ROLE" = "accelerate" ] || [ "$NODE" = "jp" ]; then
    DEFAULT_MEM_HIGH=160M
    DEFAULT_MEM_MAX=200M
else
    DEFAULT_MEM_HIGH=260M
    DEFAULT_MEM_MAX=320M
fi
MEMORY_HIGH=${MEMORY_HIGH:-$DEFAULT_MEM_HIGH}
MEMORY_MAX=${MEMORY_MAX:-$DEFAULT_MEM_MAX}

# What runs now, in case the new build does not work out.
STATE=/var/lib/fucf/releases/state.json
for f in /usr/local/bin/fucf /etc/fucf/fucf.env "$STATE"; do
    if [ -e "$f" ]; then cp -p "$f" "$f.prev"; else rm -f "$f.prev"; fi
done

install -m 0755 /tmp/fucf /usr/local/bin/fucf
id fucf >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin fucf

# Public DNS binds the node's own addresses (systemd-resolved keeps 127.0.0.53).
dns_addrs=$(ip -o addr show scope global | awk '$3=="inet"{sub(/\/.*/,"",$4); print $4":53"} $3=="inet6"{sub(/\/.*/,"",$4); print "["$4"]:53"}' | paste -sd, -)

install -d -m 0750 /etc/fucf
umask 077
{
cat <<EOF
FUCF_DNS_LISTEN=127.0.0.1:5353,${dns_addrs}
FUCF_NS=${NS_NAMES}
# Every name under this domain resolves to the edge (steered per visitor).
FUCF_CNAME_BASE=${CNAME_BASE}
FUCF_GEOIP_DB=/var/lib/fucf-geoip/GeoLite2-Country.mmdb
FUCF_GEOIP_ASN_DB=/var/lib/fucf-geoip/GeoLite2-ASN.mmdb
FUCF_API_LISTEN=127.0.0.1:8787
EOF
if [ -f /etc/haproxy/haproxy.cfg ]; then
cat <<EOF
FUCF_HTTP_LISTEN=off
# TCP 443 is haproxy's (SNI split); it hands traffic to this port.
FUCF_HTTPS_LISTEN=127.0.0.1:18443
FUCF_PROXY_PROTOCOL=true
# UDP 443 belongs to Hysteria 2; Hysteria passes ordinary HTTP/3 visitors on to the front listener.
FUCF_HTTP3_LISTEN=off
FUCF_H3_FRONT_LISTEN=${FRONT}
EOF
else
cat <<EOF
# Dedicated edge host (no HAProxy/Hysteria): fucf binds 80 and TCP+UDP 443 directly.
FUCF_HTTP_LISTEN=[::]:80
FUCF_HTTPS_LISTEN=[::]:443
FUCF_HTTP3_LISTEN=[::]:443
FUCF_PROXY_PROTOCOL=false
EOF
fi
cat <<EOF
FUCF_NODE_NAME=${NODE_NAME}
FUCF_ROLE=${ROLE}
FUCF_EDGE_IPS=${EDGE_IPS}
FUCF_CACHE_MB=${CACHE_MB}
FUCF_API_TOKEN=${API_TOKEN}
EOF
if [ -n "$PROXY_LISTEN" ]; then
    echo "FUCF_PROXY_LISTEN=${PROXY_LISTEN}"
fi
if [ -n "$PROXY_TLS_LISTEN" ]; then
    echo "FUCF_PROXY_TLS_LISTEN=${PROXY_TLS_LISTEN}"
fi
# HTTP/3 is advertised for the host names that Hysteria's certificate covers.
hy2_cert=$(awk '$1 == "tls:" { tls = 1; next } /^[^ #]/ { tls = 0 } tls && $1 == "cert:" { print $2; exit }' /etc/hysteria/config.yaml 2>/dev/null || true)
if [ -n "$hy2_cert" ]; then
    echo "FUCF_H3_FRONT_CERT=${hy2_cert}"
fi
if [ -n "${RELEASE_KEY:-}" ]; then
    echo "# Builds signed with this key are taken when the fleet rolls them out."
    echo "FUCF_RELEASE_KEY=${RELEASE_KEY}"
fi
if [ -n "${SMTP_LISTEN:-}" ]; then
    echo "FUCF_SMTP_LISTEN=${SMTP_LISTEN}"
fi
if [ -n "${MAIL_HOST:-}" ]; then
    echo "FUCF_MAIL_HOST=${MAIL_HOST}"
fi
if [ -n "${MAIL_RELAY:-}" ]; then
    echo "FUCF_MAIL_RELAY=${MAIL_RELAY}"
fi
if [ "$NODE" = "$PRIMARY" ] && [ "$ROLE" != "accelerate" ]; then
    echo "FUCF_PANEL_HOST=${PANEL_HOST}"
fi
if [ -n "$PEERS" ]; then
    echo "FUCF_PEERS=${PEERS}"
elif [ "$NODE" != "$PRIMARY" ]; then
    echo "# sync with peer/primary"
    echo "FUCF_PEERS=${PANEL_HOST}"
fi
} > /etc/fucf/fucf.env
umask 022
install -m 0644 /tmp/fucf.service /etc/systemd/system/fucf.service
sed -i -e "s/^MemoryHigh=.*/MemoryHigh=${MEMORY_HIGH}/" -e "s/^MemoryMax=.*/MemoryMax=${MEMORY_MAX}/" /etc/systemd/system/fucf.service
systemctl daemon-reload

# Free 127.0.0.1:18443: stop the old nginx edge but keep it for rollback.
if docker ps -a --format '{{.Names}}' | grep -qx fucloudflare-edge; then
    docker update --restart=no fucloudflare-edge >/dev/null
    docker stop fucloudflare-edge >/dev/null 2>&1 || true
fi
# fucf answers DNS itself now (with the same continent steering and more).
if systemctl list-unit-files fucloudflare-geodns.service >/dev/null 2>&1; then
    systemctl disable --now fucloudflare-geodns >/dev/null 2>&1 || true
fi
if [ "$REPLACE_CADDY" = "1" ] && systemctl list-unit-files caddy.service >/dev/null 2>&1; then
    systemctl disable --now caddy >/dev/null 2>&1 || true
fi

# haproxy must tell fucf who the client is and route DOMAIN to be_fucloudflare.
CFG=/etc/haproxy/haproxy.cfg
if [ -f "$CFG" ]; then
[ -e "$CFG.pre-fucf" ] || cp -p "$CFG" "$CFG.pre-fucf"
python3 - "$CFG" "$DOMAIN" "$REPLACE_CADDY" <<'PY'
import re, sys
path, domain, replace_caddy = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
txt = open(path).read()
# Ensure existing fucf1 server has send-proxy.
txt = re.sub(r'^(\s*server fucf1 127\.0\.0\.1:18443)\s*$', r'\1 send-proxy', txt, flags=re.M)
# Ensure backend be_fucloudflare exists.
if not re.search(r'^backend\s+be_fucloudflare\b', txt, flags=re.M):
    txt = txt.rstrip() + "\n\nbackend be_fucloudflare\n    server fucf1 127.0.0.1:18443 send-proxy\n"
# Ensure SNI rule for DOMAIN (apex + subdomains) exists before default_backend in the 443 frontend.
rule_end = f"    use_backend be_fucloudflare if {{ req_ssl_sni -m end .{domain} }}"
rule_eq  = f"    use_backend be_fucloudflare if {{ req_ssl_sni -i {domain} }}"
add = []
if f".{domain}" not in txt:
    add.append(rule_end)
if f"-i {domain}" not in txt:
    add.append(rule_eq)
if add:
    txt, n = re.subn(r'^(\s*default_backend\s+\S*reality\S*)', "\n".join(add) + r"\n\1", txt, count=1, flags=re.M)
    if n == 0:
        sys.exit("cannot find reality default_backend in haproxy.cfg")
# If --replace-caddy / REPLACE_CADDY=1, add send-proxy to servers in backend bk_caddy.
if replace_caddy:
    lines = txt.splitlines(keepends=True)
    in_bk_caddy = False
    for i, line in enumerate(lines):
        if re.match(r'^\s*(frontend|backend|listen|global|defaults)\b', line):
            in_bk_caddy = bool(re.match(r'^\s*backend\s+bk_caddy\b', line))
        elif in_bk_caddy and re.match(r'^\s*server\s+\S+\s+\S+', line):
            if not re.search(r'\bsend-proxy\b', line):
                if '#' in line:
                    idx = line.index('#')
                    before = line[:idx].rstrip()
                    after = line[idx:]
                    lines[i] = f"{before} send-proxy {after}"
                else:
                    updated = re.sub(r'(\r?\n)$', r' send-proxy\1', line)
                    lines[i] = updated if updated != line else line + ' send-proxy'
    txt = "".join(lines)
open(path, "w").write(txt)
PY
grep -q 'server fucf1 127.0.0.1:18443 send-proxy' "$CFG"
haproxy -c -q -f "$CFG"
fi

# Does the node work? The service is up, the API answers, and so does DNS.
healthy() {
    systemctl is-active --quiet fucf || return 1
    curl -fsS -m 5 -o /dev/null -K <(printf 'header = "Authorization: Bearer %s"\n' "$API_TOKEN") http://127.0.0.1:8787/client/v4/system || return 1
    python3 -c '
import socket, sys
q = bytes([0x5f, 0xcf, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(q, ("127.0.0.1", 5353))
r = s.recv(512)
sys.exit(0 if r[:2] == q[:2] and r[2] & 0x80 else 1)' 2>/dev/null
}
# ... and stays that way for ten seconds in a row, without being restarted.
settled() {
    local good=0 restarts
    restarts=$(systemctl show fucf -p NRestarts --value)
    for _ in $(seq 1 40); do
        sleep 1
        [ "$(systemctl show fucf -p NRestarts --value)" = "$restarts" ] || return 1
        if healthy; then good=$((good + 1)); else good=0; fi
        [ "$good" -ge 10 ] && return 0
    done
    return 1
}

systemctl enable fucf >/dev/null 2>&1
systemctl restart fucf
[ -f "$CFG" ] && systemctl reload haproxy
if ! settled; then
    echo "!!!! the new build does not come up healthy on $NODE:" >&2
    journalctl -u fucf -n 12 --no-pager -o cat >&2 || true
    if [ -e /usr/local/bin/fucf.prev ]; then
        echo "!!!! putting the previous build back" >&2
        install -m 0755 /usr/local/bin/fucf.prev /usr/local/bin/fucf
        cp -p /etc/fucf/fucf.env.prev /etc/fucf/fucf.env
        if [ -e "$STATE.prev" ]; then cp -p "$STATE.prev" "$STATE"; else rm -f "$STATE"; fi
        systemctl restart fucf
        if settled; then echo "!!!! $NODE runs its previous build again" >&2; else echo "!!!! and the previous build does not come up either: look at $NODE now" >&2; fi
    fi
    rm -f /tmp/fucf /tmp/fucf.service
    exit 1
fi
if [ -f "$CFG" ]; then systemctl is-active fucf haproxy; else systemctl is-active fucf; fi
ss -tulnpH | grep -E '"fucf"' | awk '{print $1, $5}' | sort -u | tr '\n' ' '; echo
rm -f /tmp/fucf /tmp/fucf.service
