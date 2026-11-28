#!/usr/bin/env bash
# Keep a copy of certificates other tools manage (Caddy, acme.sh, certbot)
# where fucf can read them, and follow their renewals.
#
# fucf runs as an unprivileged user with ProtectHome=, so it can neither see
# /root/... nor read root-only private keys. This copies certificate and key
# files from the given source directories into $DEST (root:fucf, 0640 for
# keys), keeping the layout, and installs a systemd path unit that repeats the
# copy whenever a source changes (plus a daily timer, in case a change goes
# unnoticed). Point fucf at the copy with FUCF_TLS_CERT_DIR=$DEST.
#
#   cert-sync.sh install SRC [SRC ...]   copy now, then follow changes
#   cert-sync.sh run                     copy once (what the units call)
#   cert-sync.sh status                  what is installed and copied
#   cert-sync.sh uninstall               remove the units (the copy stays)
#
# Runs as root on the node.
set -euo pipefail
DEST=${DEST:-/etc/fucf/certs}
CONF=/etc/fucf/cert-sync.sources
GROUP=${GROUP:-fucf}
UNIT=fucf-cert-sync

copy() {
    [ -s "$CONF" ] || { echo "no sources configured ($CONF)" >&2; exit 1; }
    install -d -m 0750 -o root -g "$GROUP" "$DEST"
    local tmp n=0
    tmp=$(mktemp -d "$DEST/.sync.XXXXXX")
    trap 'rm -rf "$tmp"' RETURN
    while IFS= read -r src; do
        [ -n "$src" ] && [ -d "$src" ] || continue
        n=$((n + 1))
        local into="$tmp/$n-$(basename "$src")"
        # certificates and keys only: no account keys or CA material of the tool itself
        (cd "$src" && find . -maxdepth 6 -type f \( -name '*.crt' -o -name '*.cer' -o -name '*.pem' -o -name '*.key' \) \
            -not -path '*/acme/*' -not -path '*/pki/*' -not -path '*/accounts/*' -not -name 'ca.cer' -print0) |
        while IFS= read -r -d '' f; do
            install -D -m 0640 -o root -g "$GROUP" "$src/$f" "$into/$f"
        done
    done < "$CONF"
    chmod -R u=rwX,g=rX,o= "$tmp"
    chgrp -R "$GROUP" "$tmp"
    # swap in the new copy in one step
    local old
    old=$(mktemp -d "$DEST/.old.XXXXXX")
    find "$DEST" -mindepth 1 -maxdepth 1 -not -name '.sync.*' -not -name '.old.*' -exec mv {} "$old/" \;
    find "$tmp" -mindepth 1 -maxdepth 1 -exec mv {} "$DEST/" \;
    rm -rf "$old"
    echo "copied $(find "$DEST" -type f | wc -l) file(s) from $n source(s) to $DEST"
}

case "${1:-}" in
install)
    shift
    [ $# -gt 0 ] || { echo "usage: $0 install SRC [SRC ...]" >&2; exit 1; }
    id "$GROUP" >/dev/null 2>&1 || { echo "group $GROUP does not exist (install fucf first)" >&2; exit 1; }
    install -d -m 0755 /etc/fucf
    : > "$CONF"
    for s in "$@"; do
        s=$(readlink -f "$s")
        [ -d "$s" ] || { echo "not a directory: $s" >&2; exit 1; }
        echo "$s" >> "$CONF"
    done
    install -m 0755 "$(readlink -f "$0")" /usr/local/bin/fucf-cert-sync
    {
        echo "[Unit]"; echo "Description=fucf: copy certificates other tools renew"
        echo "[Service]"; echo "Type=oneshot"; echo "ExecStart=/usr/local/bin/fucf-cert-sync run"
    } > /etc/systemd/system/$UNIT.service
    {
        echo "[Unit]"; echo "Description=fucf: follow certificate renewals"
        echo "[Path]"
        while IFS= read -r s; do echo "PathChanged=$s"; done < "$CONF"
        # Caddy and acme.sh write renewals one level down
        while IFS= read -r s; do find "$s" -mindepth 1 -maxdepth 4 -type d -not -path '*/pki*' -not -path '*/acme/*' | sed 's/^/PathChanged=/'; done < "$CONF"
        echo "[Install]"; echo "WantedBy=multi-user.target"
    } > /etc/systemd/system/$UNIT.path
    {
        echo "[Unit]"; echo "Description=fucf: copy certificates daily"
        echo "[Timer]"; echo "OnCalendar=daily"; echo "RandomizedDelaySec=1h"; echo "Persistent=true"
        echo "[Install]"; echo "WantedBy=timers.target"
    } > /etc/systemd/system/$UNIT.timer
    systemctl daemon-reload
    copy
    systemctl enable --now $UNIT.path $UNIT.timer >/dev/null
    echo "following: $(paste -sd' ' "$CONF")"
    echo "set FUCF_TLS_CERT_DIR=$DEST in /etc/fucf/fucf.env"
    ;;
run) copy ;;
status)
    echo "sources:"; sed 's/^/  /' "$CONF" 2>/dev/null || echo "  (none)"
    systemctl is-active $UNIT.path $UNIT.timer 2>/dev/null | paste -sd' ' | sed 's/^/units: /'
    find "$DEST" -type f -name '*.crt' -o -type f -name '*.cer' -o -type f -name 'fullchain.pem' 2>/dev/null | sed "s#^$DEST/#  #"
    ;;
uninstall)
    systemctl disable --now $UNIT.path $UNIT.timer 2>/dev/null || true
    rm -f /etc/systemd/system/$UNIT.service /etc/systemd/system/$UNIT.path /etc/systemd/system/$UNIT.timer /usr/local/bin/fucf-cert-sync
    systemctl daemon-reload
    echo "units removed; $DEST is left in place"
    ;;
*) sed -n '2,17p' "$0"; exit 1 ;;
esac
