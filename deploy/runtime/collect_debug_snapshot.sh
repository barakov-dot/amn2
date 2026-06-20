#!/usr/bin/env bash
set -u

AMN_PROJECT_DIR="${AMN_PROJECT_DIR:-/opt/amn2}"
AMN_RUNTIME="${AMN_RUNTIME:-host_systemd}"
AMN_INTERFACE="${AMN_INTERFACE:-awg0}"
AMN_SERVICE_NAME="${AMN_SERVICE_NAME:-awg-quick@${AMN_INTERFACE}}"
AMN_CONTAINER_NAME="${AMN_CONTAINER_NAME:-amnezia-awg}"
AMN_SERVER_CONFIG="${AMN_SERVER_CONFIG:-servers.yml}"
AMN_SERVER_NAME="${AMN_SERVER_NAME:-debian-vps-1}"
AMN_DB_PATH="${AMN_DB_PATH:-data/amneziya.sqlite3}"
AMN_LOG_LINES="${AMN_LOG_LINES:-200}"
AMN_VPN_PORT="${AMN_VPN_PORT:-30001}"
AMN_WEB_PORT="${AMN_WEB_PORT:-3030}"

# Manual equivalent: python -m app.cli server check --config servers.yml --server debian-vps-1

section() {
    printf '\n===== %s =====\n' "$1"
}

note() {
    printf '[INFO] %s\n' "$1"
}

validate_port() {
    local name="$1"
    local value="$2"
    case "$value" in
        ''|*[!0-9]*)
            printf '[ERROR] %s must be a numeric TCP/UDP port\n' "$name" >&2
            exit 2
            ;;
    esac
    if [ "$value" -lt 1 ] || [ "$value" -gt 65535 ]; then
        printf '[ERROR] %s must be between 1 and 65535\n' "$name" >&2
        exit 2
    fi
}

redact_stream() {
    sed -E \
        -e 's/[0-9]{6,12}:[A-Za-z0-9_-]{20,}/[REDACTED_TELEGRAM_BOT_TOKEN]/g' \
        -e 's/(TELEGRAM_BOT_TOKEN=)[^[:space:]]+/\1[REDACTED]/g' \
        -e 's/(APP_SECRET_KEY=)[^[:space:]]+/\1[REDACTED]/g' \
        -e 's/(WEB_ADMIN_PASSWORD_HASH=)[^[:space:]]+/\1[REDACTED]/g' \
        -e 's/(WEB_ADMIN_SESSION_SECRET=)[^[:space:]]+/\1[REDACTED]/g' \
        -e 's/(SMTP_PASSWORD=)[^[:space:]]+/\1[REDACTED]/g' \
        -e 's/(VPS_SSH_PASSWORD=)[^[:space:]]+/\1[REDACTED]/g' \
        -e 's/(private_key_path:[[:space:]]*).+/\1[REDACTED]/g' \
        -e 's/(PrivateKey[[:space:]]*=[[:space:]]*).+/\1[REDACTED]/g' \
        -e 's/(PresharedKey[[:space:]]*=[[:space:]]*).+/\1[REDACTED]/g' \
        -e 's/(preshared-key[[:space:]]+)[^[:space:]]+/\1[REDACTED]/g'
}

run() {
    local title="$1"
    shift
    section "$title"
    printf '+'
    printf ' %q' "$@"
    printf '\n'
    "$@" 2>&1 | redact_stream || true
}

run_port_grep() {
    local title="$1"
    local port="$2"
    shift 2
    section "$title"
    printf '+ ss'
    printf ' %q' "$@"
    printf ' | grep -E %q\n' "[:.]${port}[[:space:]]"
    ss "$@" 2>&1 | grep -E "[:.]${port}[[:space:]]" | redact_stream || true
}

python_bin() {
    if [ -x "${AMN_PROJECT_DIR}/venv/bin/python" ]; then
        printf '%s\n' "${AMN_PROJECT_DIR}/venv/bin/python"
        return
    fi
    if command -v python3 >/dev/null 2>&1; then
        command -v python3
        return
    fi
    if command -v python >/dev/null 2>&1; then
        command -v python
        return
    fi
    printf '%s\n' "python3"
}

print_env_keys() {
    section ".env keys"
    if [ -f "${AMN_PROJECT_DIR}/.env" ]; then
        grep -E '^[A-Z0-9_]+=' "${AMN_PROJECT_DIR}/.env" | cut -d= -f1 | sort | redact_stream || true
    else
        note ".env not found at ${AMN_PROJECT_DIR}/.env"
    fi
}

collect_app_snapshot() {
    local py
    py="$(python_bin)"

    run "git revision" git -C "$AMN_PROJECT_DIR" log -1 --oneline --decorate
    run "git status" git -C "$AMN_PROJECT_DIR" status --short
    run "python version" "$py" --version
    run "project directories" ls -ld \
        "${AMN_PROJECT_DIR}/data" \
        "${AMN_PROJECT_DIR}/logs" \
        "${AMN_PROJECT_DIR}/backups" \
        "${AMN_PROJECT_DIR}/config_templates"
    print_env_keys

    run "server check dry-run" "$py" -m app.cli server check \
        --config "$AMN_SERVER_CONFIG" \
        --server "$AMN_SERVER_NAME" \
        --dry-run

    run "server check live read-only" "$py" -m app.cli server check \
        --config "$AMN_SERVER_CONFIG" \
        --server "$AMN_SERVER_NAME"

    run "runtime check" bash "${AMN_PROJECT_DIR}/deploy/runtime/check_vps.sh"
    run "bot network check" "$py" -m app.cli bot check-network
}

collect_system_snapshot() {
    run "utc time" date -u
    run "kernel" uname -a
    run "current user" id
    run "listening tcp ports" ss -lntp
    run "listening udp ports" ss -lun
    run_port_grep "web port grep" "$AMN_WEB_PORT" -lntp
    run_port_grep "vpn port grep" "$AMN_VPN_PORT" -lun
}

collect_host_systemd_snapshot() {
    run "systemd vpn active state" systemctl is-active "$AMN_SERVICE_NAME"
    run "systemd vpn properties" systemctl show "$AMN_SERVICE_NAME" \
        -p ActiveState \
        -p SubState \
        -p MainPID \
        -p NRestarts
    run "awg show host interface" awg show "$AMN_INTERFACE"
}

collect_docker_snapshot() {
    run "docker containers" docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
    run "docker inspect selected container" docker inspect "$AMN_CONTAINER_NAME" \
        --format '{{.Name}} {{.State.Status}} {{.Config.Image}} {{json .Mounts}}'
    run "awg show docker interface" docker exec "$AMN_CONTAINER_NAME" awg show "$AMN_INTERFACE"
}

collect_logs() {
    run "web systemd logs" journalctl -u amneziya-web -n "$AMN_LOG_LINES" --no-pager
    run "bot systemd logs" journalctl -u amneziya-bot -n "$AMN_LOG_LINES" --no-pager
    run "app log tail" tail -n "$AMN_LOG_LINES" "${AMN_PROJECT_DIR}/logs/app.log"
}

main() {
    validate_port AMN_WEB_PORT "$AMN_WEB_PORT"
    validate_port AMN_VPN_PORT "$AMN_VPN_PORT"

    section "debug snapshot settings"
    cat <<EOF | redact_stream
AMN_PROJECT_DIR=${AMN_PROJECT_DIR}
AMN_RUNTIME=${AMN_RUNTIME}
AMN_INTERFACE=${AMN_INTERFACE}
AMN_SERVICE_NAME=${AMN_SERVICE_NAME}
AMN_CONTAINER_NAME=${AMN_CONTAINER_NAME}
AMN_SERVER_CONFIG=${AMN_SERVER_CONFIG}
AMN_SERVER_NAME=${AMN_SERVER_NAME}
AMN_DB_PATH=${AMN_DB_PATH}
AMN_LOG_LINES=${AMN_LOG_LINES}
AMN_VPN_PORT=${AMN_VPN_PORT}
AMN_WEB_PORT=${AMN_WEB_PORT}
EOF

    cd "$AMN_PROJECT_DIR" 2>/dev/null || {
        note "cannot cd to ${AMN_PROJECT_DIR}; continuing from current directory"
    }

    collect_system_snapshot
    collect_app_snapshot

    case "$AMN_RUNTIME" in
        host_systemd)
            collect_host_systemd_snapshot
            ;;
        docker)
            collect_docker_snapshot
            ;;
        *)
            note "unsupported AMN_RUNTIME=${AMN_RUNTIME}; skipping runtime-specific snapshot"
            ;;
    esac

    collect_logs
}

main "$@"
