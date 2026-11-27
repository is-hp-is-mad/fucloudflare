#!/usr/bin/env bash
# Runs ON a node (as root): hy2-sync-fucf-cert.sh [DOMAIN] [strict|disable]
#
# Exports the wildcard certificate for DOMAIN (managed by fucf's built-in ACME
# DNS-01 and replicated across all nodes) into /etc/hy2-site-cert/{cert,key}.pem,
# installs a daily cron job to keep it fresh, points Hysteria 2 at it with the
# requested sniGuard mode, and tells fucf (FUCF_H3_FRONT_CERT) so HTTP/3 is
# advertised for the covered host names.
set -euo pipefail
DOMAIN=${1:-fucloudflare.com}
GUARD=${2:-disable}
case "$GUARD" in strict|disable) ;; *) echo "guard must be 'strict' or 'disable'" >&2; exit 1 ;; esac
CFG=/etc/hysteria/config.yaml
UNIT=hysteria-server
DIR=/etc/hy2-site-cert
SYNC=/usr/local/bin/fucf-hy2-cert-sync

cat > "$SYNC" <<'PY'
#!/usr/bin/env python3
import json, os, sys

domain = sys.argv[1] if len(sys.argv) > 1 else "fucloudflare.com"
out_dir = "/etc/hy2-site-cert"
state_path = "/var/lib/fucf/state.json"
if not os.path.exists(state_path):
    sys.exit(f"missing {state_path}")
data = json.load(open(state_path))
zones = {z["id"]: z["name"] for z in data.get("zones", [])}
want = {domain, f"*.{domain}"}
picked = None
for c in data.get("custom_certificates", []):
    if zones.get(c.get("zone_id")) == domain or want.issubset(set(c.get("hosts", []))):
        picked = c
        break
if not picked:
    for p in data.get("certificate_packs", []):
        if p.get("status") == "active" and p.get("certificate") and p.get("private_key"):
            if zones.get(p.get("zone_id")) == domain or want.issubset(set(p.get("hosts", []))):
                picked = p
                break
if not picked:
    sys.exit(f"no active certificate for {domain} in {state_path} yet")
os.makedirs(out_dir, exist_ok=True)
os.chmod(out_dir, 0o755)
def atomic_write(path, content, mode):
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
atomic_write(f"{out_dir}/key.pem", picked["private_key"], 0o600)
atomic_write(f"{out_dir}/cert.pem", picked["certificate"], 0o644)
print(f"synced {domain} cert to {out_dir}")
PY
chmod 0755 "$SYNC"
"$SYNC" "$DOMAIN"
printf '23 4 * * * root %s %s >/dev/null 2>&1\n' "$SYNC" "$DOMAIN" > /etc/cron.d/fucf-hy2-cert

[ -f "$CFG" ] || { echo "no $CFG on this node" >&2; exit 1; }
[ -e "$CFG.pre-sni" ] || cp -p "$CFG" "$CFG.pre-sni"
cp -p "$CFG" "$CFG.before"
python3 - "$CFG" "$DIR/cert.pem" "$DIR/key.pem" "$GUARD" <<'PY'
import re, sys
path, cert, key, guard = sys.argv[1:5]
out, in_tls = [], False
for line in open(path).read().split("\n"):
    if re.match(r"^tls:\s*$", line):
        in_tls = True
        out += [line, f"  cert: {cert}", f"  key: {key}", f"  sniGuard: {guard}"]
        continue
    if in_tls:
        if re.match(r"^\s+(cert|key|sniGuard):", line):
            continue
        if line and not line[0].isspace() and not line.startswith("#"):
            in_tls = False
    out.append(line)
open(path, "w").write("\n".join(out))
PY
systemctl restart "$UNIT"
sleep 2
if ! systemctl is-active --quiet "$UNIT"; then
    echo "!!!! Hysteria failed to restart; rolling back" >&2
    cp -p "$CFG.before" "$CFG" && rm -f "$CFG.before"
    systemctl restart "$UNIT"
    exit 1
fi
rm -f "$CFG.before"

ENV=/etc/fucf/fucf.env
if [ -f "$ENV" ] && ! grep -qx "FUCF_H3_FRONT_CERT=$DIR/cert.pem" "$ENV"; then
    cp -p "$ENV" "$ENV.pre-sni"
    if grep -q '^FUCF_H3_FRONT_CERT=' "$ENV"; then
        sed -i "s|^FUCF_H3_FRONT_CERT=.*|FUCF_H3_FRONT_CERT=$DIR/cert.pem|" "$ENV"
    else
        echo "FUCF_H3_FRONT_CERT=$DIR/cert.pem" >> "$ENV"
    fi
    systemctl restart fucf
fi
echo "Hysteria on $(hostname) now serves $DOMAIN (sniGuard: $GUARD)"
