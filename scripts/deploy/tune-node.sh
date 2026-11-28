#!/usr/bin/env bash
# Runs ON a node (as root): transport tuning for long, lossy paths (visitors
# 150-260 ms away with 5-15% loss), and the GeoIP databases used for steering.
set -euo pipefail

cat > /etc/sysctl.d/90-fucf-edge.conf <<'EOF'
# fucloudflare edge: long fat lossy paths.
# BBR keeps its sending rate under random loss; fq provides the pacing it needs.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
# TCP Fast Open for clients and servers.
net.ipv4.tcp_fastopen = 3
# Large TCP windows: at 250 ms RTT a 6 MB window is needed for ~200 Mbit/s.
# (net.core.rmem_max/wmem_max are left to the hosts' own 99-proxy.conf.)
net.ipv4.tcp_rmem = 4096 131072 33554432
net.ipv4.tcp_wmem = 4096 131072 33554432
# QUIC (HTTP/3) runs in user space on UDP sockets.
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.netdev_max_backlog = 8192
# Keep the congestion window across idle periods of keep-alive connections.
net.ipv4.tcp_slow_start_after_idle = 0
# Recover from path-MTU black holes instead of stalling.
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 131072
EOF
modprobe tcp_bbr 2>/dev/null || true
sysctl -q --system
sysctl -n net.ipv4.tcp_congestion_control net.core.default_qdisc net.ipv4.tcp_fastopen net.ipv4.tcp_rmem net.ipv4.tcp_slow_start_after_idle | tr '\n' ' '; echo

# GeoIP databases (City for country+province + ASN), refreshed weekly.
install -d /var/lib/fucf-geoip
cat > /usr/local/bin/fucf-geoip-update <<'EOF'
#!/bin/sh
# Download to a temporary name and only replace a database with a plausible file.
set -eu
cd /var/lib/fucf-geoip
changed=0
for db in GeoLite2-City GeoLite2-ASN; do
    if curl -fsSL -m 180 -o "$db.new" "https://github.com/P3TERX/GeoLite.mmdb/raw/download/$db.mmdb" \
        && [ "$(stat -c %s "$db.new")" -gt 1000000 ]; then
        cmp -s "$db.new" "$db.mmdb" 2>/dev/null || { mv "$db.new" "$db.mmdb"; changed=1; }
    fi
    rm -f "$db.new"
done
if [ -f GeoLite2-City.mmdb ]; then
    ln -sfn GeoLite2-City.mmdb GeoLite2-Country.mmdb
fi
[ "$changed" = 1 ] && [ "${1:-}" = "--restart" ] && systemctl try-restart fucf
exit 0
EOF
chmod 0755 /usr/local/bin/fucf-geoip-update
/usr/local/bin/fucf-geoip-update
printf '17 4 * * 1 root /usr/local/bin/fucf-geoip-update --restart\n' > /etc/cron.d/fucf-geoip
ls -la /var/lib/fucf-geoip | tail -n +2 | awk '{print $5, $9}' | tr '\n' ' '; echo
