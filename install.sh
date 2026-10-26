#!/bin/sh
set -eu

[ "$(id -u)" = 0 ] || { printf '%s\n' 'Run this installer as root.' >&2; exit 1; }
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for tool in nft python3 systemctl systemd-analyze install flock mktemp; do
    command -v "$tool" >/dev/null || { printf 'Missing dependency: %s\n' "$tool" >&2; exit 1; }
done
python3 -m unittest discover -s "$BASE/tests" -v

STATE=/var/lib/port-traffic
umask 077
install -d -m 700 "$STATE" "$STATE/backups"
exec 9>"$STATE/install.lock"
flock -x 9
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP=$(mktemp -d "$STATE/backups/$STAMP.XXXXXX")
nft -j -a list ruleset > "$BACKUP/firewall-before.json"
for file in /usr/local/sbin/port-traffic /etc/systemd/system/port-traffic.service /etc/systemd/system/port-traffic-sync.service /etc/systemd/system/port-traffic-sync.timer; do
    if [ -e "$file" ]; then
        cp -p "$file" "$BACKUP/$(basename "$file").previous"
    fi
done
if [ -f "$STATE/state.json" ]; then
    /usr/local/sbin/port-traffic sync
    cp -p "$STATE/state.json" "$BACKUP/state-before.json"
fi
install -m 755 "$BASE/port_traffic.py" /usr/local/sbin/port-traffic
install -m 644 "$BASE/systemd/port-traffic.service" /etc/systemd/system/port-traffic.service
install -m 644 "$BASE/systemd/port-traffic-sync.service" /etc/systemd/system/port-traffic-sync.service
install -m 644 "$BASE/systemd/port-traffic-sync.timer" /etc/systemd/system/port-traffic-sync.timer
systemd-analyze verify /etc/systemd/system/port-traffic.service /etc/systemd/system/port-traffic-sync.service /etc/systemd/system/port-traffic-sync.timer
systemctl daemon-reload
systemctl enable --now port-traffic.service port-traffic-sync.timer
printf '\nInstalled. Existing firewall and tunnel services were not restarted.\n'
printf 'Pre-install snapshot: %s\n' "$BACKUP/firewall-before.json"
printf '%s\n' 'Enable a customer-facing port: port-traffic add PORT' 'Read its live usage: port-traffic PORT'
