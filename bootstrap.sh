#!/usr/bin/env bash
# One-Script 稳定入口脚本

normalize_channel() {
    local channel
    channel=$(echo "${1:-}" | tr '[:upper:]' '[:lower:]')
    case "${channel}" in
        dev|main)
            echo "${channel}"
            ;;
        *)
            echo "main"
            ;;
    esac
}

parse_channel_args() {
    local channel="${ONE_SCRIPT_CHANNEL:-}"
    local remaining=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --channel)
                if [[ -n "${2:-}" ]]; then
                    channel="$2"
                    shift 2
                    continue
                fi
                shift
                continue
                ;;
            --channel=*)
                channel="${1#*=}"
                shift
                continue
                ;;
            *)
                remaining+=("$1")
                shift
                ;;
        esac
    done

    CHANNEL="$(normalize_channel "${channel}")"
    BASE_URL="https://raw.githubusercontent.com/charleslkx/one-script/${CHANNEL}"
    REMAINING_ARGS=("${remaining[@]}")
}

run_remote_script() {
    if command -v wget >/dev/null 2>&1; then
        ONE_SCRIPT_CHANNEL="${CHANNEL}" bash <(wget -qO- "${BASE_URL}/main.sh" 2>/dev/null) "${REMAINING_ARGS[@]}"
        return $?
    fi
    if command -v curl >/dev/null 2>&1; then
        ONE_SCRIPT_CHANNEL="${CHANNEL}" bash <(curl -fsSL "${BASE_URL}/main.sh" 2>/dev/null) "${REMAINING_ARGS[@]}"
        return $?
    fi
    echo "错误：未找到 wget 或 curl 工具" >&2
    return 1
}

main() {
    parse_channel_args "$@"
    run_remote_script
}

main "$@"
