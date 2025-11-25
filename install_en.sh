#!/usr/bin/env bash
# English wrapper for the One-Script V2Ray installer

set -euo pipefail

export ONE_SCRIPT_LANG="en"

Green="\033[32m"
Yellow="\033[33m"
Red="\033[31m"
Font="\033[0m"

BASE_URL="https://raw.githubusercontent.com/charleslkx/one-script/master/install.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_INSTALL="${SCRIPT_DIR}/install.sh"
TEMP_INSTALL="/tmp/one-script-install.sh"

echo -e "${Green}One-Script installer (English wrapper)${Font}"
echo -e "${Yellow}If a local install.sh exists it will be used, otherwise the latest will be downloaded.${Font}"

fetch_installer() {
    local target="$1"
    if command -v wget >/dev/null 2>&1; then
        wget -qO "$target" "$BASE_URL"
    elif command -v curl >/dev/null 2>&1; then
        curl -fsSL "$BASE_URL" -o "$target"
    else
        echo -e "${Red}wget or curl is required to download install.sh${Font}"
        exit 1
    fi
}

if [[ -f "$LOCAL_INSTALL" ]]; then
    echo -e "${Green}Using local install.sh at ${LOCAL_INSTALL}${Font}"
    bash "$LOCAL_INSTALL" "$@"
else
    echo -e "${Yellow}Local install.sh not found, downloading from repository...${Font}"
    if fetch_installer "$TEMP_INSTALL"; then
        echo -e "${Green}Download complete. Starting installer...${Font}"
        bash "$TEMP_INSTALL" "$@"
    else
        echo -e "${Red}Failed to download install.sh${Font}"
        exit 1
    fi
fi
