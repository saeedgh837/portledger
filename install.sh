#!/bin/sh
set -eu

[ "$(id -u)" = 0 ] || { printf '%s\n' 'Run this installer as root.' >&2; exit 1; }
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

WITH_NGINX=0
REPLACE_DEFAULT_SITE=0

for arg in "$@"; do
    case "$arg" in
        --with-nginx)
            WITH_NGINX=1
            ;;
        --replace-default-site)
            REPLACE_DEFAULT_SITE=1
            ;;
        --help|-h)
            printf '%s\n' \
                "Usage: $0 [options]" \
                "Options:" \
                "  --with-nginx             Configure and reload Nginx reverse proxy on port 80" \
                "  --replace-default-site   Disable existing /etc/nginx/sites-enabled/default if configuring Nginx" \
                "  --help, -h               Show this help message"
            exit 0
            ;;
        *)
            printf 'Unknown argument: %s\n' "$arg" >&2
            exit 1
            ;;
    esac
done

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
for file in /usr/local/sbin/port-traffic /etc/systemd/system/port-traffic.service /etc/systemd/system/port-traffic-sync.service /etc/systemd/system/port-traffic-sync.timer /etc/systemd/system/port-traffic-web.service; do
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
install -m 644 "$BASE/systemd/port-traffic-web.service" /etc/systemd/system/port-traffic-web.service
systemd-analyze verify /etc/systemd/system/port-traffic.service /etc/systemd/system/port-traffic-sync.service /etc/systemd/system/port-traffic-sync.timer /etc/systemd/system/port-traffic-web.service
systemctl daemon-reload
systemctl enable --now port-traffic.service port-traffic-sync.timer port-traffic-web.service

NGINX_STATUS="not_configured"
if [ "$WITH_NGINX" -eq 1 ]; then
    if ! command -v nginx >/dev/null 2>&1 || [ ! -d /etc/nginx ]; then
        printf 'Error: --with-nginx specified but nginx is not installed or /etc/nginx is missing.\n' >&2
        exit 1
    fi

    NGINX_BACKUP="$BACKUP/nginx"
    install -d -m 700 "$NGINX_BACKUP"

    RESTORE_DEFAULT=0
    RESTORE_AVAILABLE=0
    RESTORE_ENABLED=0

    if [ -d /etc/nginx/sites-available ] && [ -d /etc/nginx/sites-enabled ]; then
        if [ -e /etc/nginx/sites-available/port-traffic.conf ]; then
            cp -p /etc/nginx/sites-available/port-traffic.conf "$NGINX_BACKUP/port-traffic.conf.previous"
            RESTORE_AVAILABLE=1
        fi
        if [ -e /etc/nginx/sites-enabled/port-traffic.conf ]; then
            cp -P /etc/nginx/sites-enabled/port-traffic.conf "$NGINX_BACKUP/port-traffic-enabled.previous" 2>/dev/null || true
            RESTORE_ENABLED=1
        fi

        if [ -e /etc/nginx/sites-enabled/default ]; then
            if [ "$REPLACE_DEFAULT_SITE" -eq 1 ]; then
                cp -P /etc/nginx/sites-enabled/default "$NGINX_BACKUP/default-enabled.previous"
                rm -f /etc/nginx/sites-enabled/default
                RESTORE_DEFAULT=1
            else
                printf 'Notice: /etc/nginx/sites-enabled/default exists. Leaving untouched (pass --replace-default-site to disable if port 80 conflicts).\n'
            fi
        fi

        install -m 644 "$BASE/nginx/port-traffic.conf" /etc/nginx/sites-available/port-traffic.conf
        ln -sf /etc/nginx/sites-available/port-traffic.conf /etc/nginx/sites-enabled/port-traffic.conf

        if ! nginx -t; then
            printf 'Error: nginx -t failed. Performing automatic rollback of nginx changes...\n' >&2
            rm -f /etc/nginx/sites-enabled/port-traffic.conf
            if [ "$RESTORE_ENABLED" -eq 1 ] && [ -e "$NGINX_BACKUP/port-traffic-enabled.previous" ]; then
                cp -P "$NGINX_BACKUP/port-traffic-enabled.previous" /etc/nginx/sites-enabled/port-traffic.conf
            fi
            if [ "$RESTORE_AVAILABLE" -eq 1 ]; then
                cp -p "$NGINX_BACKUP/port-traffic.conf.previous" /etc/nginx/sites-available/port-traffic.conf
            else
                rm -f /etc/nginx/sites-available/port-traffic.conf
            fi
            if [ "$RESTORE_DEFAULT" -eq 1 ]; then
                cp -P "$NGINX_BACKUP/default-enabled.previous" /etc/nginx/sites-enabled/default
            fi
            exit 1
        fi

        if ! systemctl reload nginx; then
            printf 'Error: systemctl reload nginx failed. Performing automatic rollback of nginx changes...\n' >&2
            rm -f /etc/nginx/sites-enabled/port-traffic.conf
            if [ "$RESTORE_ENABLED" -eq 1 ] && [ -e "$NGINX_BACKUP/port-traffic-enabled.previous" ]; then
                cp -P "$NGINX_BACKUP/port-traffic-enabled.previous" /etc/nginx/sites-enabled/port-traffic.conf
            fi
            if [ "$RESTORE_AVAILABLE" -eq 1 ]; then
                cp -p "$NGINX_BACKUP/port-traffic.conf.previous" /etc/nginx/sites-available/port-traffic.conf
            else
                rm -f /etc/nginx/sites-available/port-traffic.conf
            fi
            if [ "$RESTORE_DEFAULT" -eq 1 ]; then
                cp -P "$NGINX_BACKUP/default-enabled.previous" /etc/nginx/sites-enabled/default
            fi
            systemctl reload nginx 2>/dev/null || true
            exit 1
        fi
        NGINX_STATUS="active"
    elif [ -d /etc/nginx/conf.d ]; then
        RESTORE_CONFD=0
        if [ -e /etc/nginx/conf.d/port-traffic.conf ]; then
            cp -p /etc/nginx/conf.d/port-traffic.conf "$NGINX_BACKUP/confd-port-traffic.conf.previous"
            RESTORE_CONFD=1
        fi
        install -m 644 "$BASE/nginx/port-traffic.conf" /etc/nginx/conf.d/port-traffic.conf

        if ! nginx -t; then
            printf 'Error: nginx -t failed. Performing automatic rollback of nginx changes...\n' >&2
            if [ "$RESTORE_CONFD" -eq 1 ]; then
                cp -p "$NGINX_BACKUP/confd-port-traffic.conf.previous" /etc/nginx/conf.d/port-traffic.conf
            else
                rm -f /etc/nginx/conf.d/port-traffic.conf
            fi
            exit 1
        fi

        if ! systemctl reload nginx; then
            printf 'Error: systemctl reload nginx failed. Performing automatic rollback of nginx changes...\n' >&2
            if [ "$RESTORE_CONFD" -eq 1 ]; then
                cp -p "$NGINX_BACKUP/confd-port-traffic.conf.previous" /etc/nginx/conf.d/port-traffic.conf
            else
                rm -f /etc/nginx/conf.d/port-traffic.conf
            fi
            systemctl reload nginx 2>/dev/null || true
            exit 1
        fi
        NGINX_STATUS="active"
    fi
fi

printf '\nInstalled. Existing firewall and tunnel services were not restarted.\n'
printf 'Pre-install snapshot: %s\n' "$BACKUP/firewall-before.json"
printf 'Web service: systemd port-traffic-web.service active at http://127.0.0.1:9090\n'
if [ "$NGINX_STATUS" = "active" ]; then
    printf 'Nginx reverse proxy: active on port 80 -> 127.0.0.1:9090\n'
fi
printf '%s\n' 'Enable a customer-facing port: port-traffic add PORT' 'Read its live usage: port-traffic PORT'
