#!/usr/bin/env bash
# Runs ON the AU node (as root): remove SafeLine WAF completely.
set -euo pipefail
cd /data/safeline
docker compose down --volumes --remove-orphans
docker images --format '{{.Repository}}:{{.Tag}}' | grep '^chaitin/safeline' | xargs -r docker rmi
docker network rm safeline-ce 2>/dev/null || true
cd /
rm -rf /data/safeline
rmdir /data 2>/dev/null || true
echo "--- remaining containers"; docker ps -a --format '{{.Names}} {{.Status}}'
echo "--- remaining images"; docker images --format '{{.Repository}}:{{.Tag}}'
echo "--- listeners 9443/65443/8088"; ss -tlnH | grep -E ':(9443|65443|8088)\s' || echo none
free -m | sed -n 2p
df -h / | tail -1
