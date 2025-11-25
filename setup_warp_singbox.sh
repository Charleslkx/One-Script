#!/usr/bin/env bash

# ==============================================================================
# 用户自定义配置区 (User Configuration)
# ==============================================================================

# --- WARP 设置 ---
# WARP 账户模式
# 可选值: 
#   "free"       - 免费版 (自动注册，无需任何凭据，适合大多数用户)
#   "plus"       - WARP+ (需要 License Key)
#   "zerotrust"  - Zero Trust (团队版，需要 Team Name，且需手动完成浏览器/Token验证)
# 建议: 初次安装保持 "free"，需要高级功能时修改此处。
WARP_MODE="free"

# WARP+ License Key (仅当 WARP_MODE="plus" 时需要)
WARP_LICENSE_KEY=""

# Zero Trust 团队名称 (仅当 WARP_MODE="zerotrust" 时需要)
WARP_TEAM_NAME=""

# WARP 本地 SOCKS5 代理端口
# 建议: 40000 (避免与常用端口冲突)
WARP_PROXY_PORT=40000

# --- Sing-box 设置 ---
# Sing-box 入站监听端口 (Mixed 协议)
# 建议: 2080
SINGBOX_INBOUND_PORT=2080

# ==============================================================================

# 颜色定义
Red="\033[31m"
Green="\033[32m"
Yellow="\033[33m"
Blue="\033[34m"
Font="\033[0m"

LANGUAGE_CHOICE="${ONE_SCRIPT_LANG:-zh}"

lang_text() {
    local zh="$1"
    local en="$2"
    if [[ "${LANGUAGE_CHOICE}" == "en" ]]; then
        printf "%b" "${en}"
    else
        printf "%b" "${zh}"
    fi
}

lang_echo() {
    local zh="$1"
    local en="$2"
    if [[ "${LANGUAGE_CHOICE}" == "en" ]]; then
        echo -e "${en}"
    else
        echo -e "${zh}"
    fi
}

select_language() {
    if [[ -n "${ONE_SCRIPT_LANG}" ]]; then
        case "$(echo "${ONE_SCRIPT_LANG}" | tr '[:upper:]' '[:lower:]')" in
        2 | en | eng | english)
            LANGUAGE_CHOICE="en"
            ;;
        *)
            LANGUAGE_CHOICE="zh"
            ;;
        esac
        return
    fi

    echo -e "${Blue}请选择语言 / Select language:${Font}"
    echo -e "${Yellow}1.${Font} 中文 (默认)"
    echo -e "${Yellow}2.${Font} English"
    read -p "输入选择 [1/2]: " lang_pick
    case "$(echo "${lang_pick}" | tr '[:upper:]' '[:lower:]')" in
    2 | en | english)
        LANGUAGE_CHOICE="en"
        ;;
    *)
        LANGUAGE_CHOICE="zh"
        ;;
    esac
    export ONE_SCRIPT_LANG="${LANGUAGE_CHOICE}"
}

select_language

# 检查是否为 root 用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        lang_echo "${Red}错误：请使用 root 用户运行此脚本！${Font}" "${Red}Error: please run this script as root!${Font}"
        exit 1
    fi
}

# 检测系统
check_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
        CODENAME=${VERSION_CODENAME:-}
        if [[ -z "$CODENAME" && -x /usr/bin/lsb_release ]]; then
            CODENAME=$(lsb_release -cs 2>/dev/null || true)
        fi
    else
        lang_echo "${Red}无法检测操作系统，脚本仅支持 Debian/Ubuntu${Font}" "${Red}Cannot detect OS. Supported: Debian/Ubuntu only.${Font}"
        exit 1
    fi

    if [[ "$OS" != "debian" && "$OS" != "ubuntu" ]]; then
        lang_echo "${Red}不支持的操作系统: $OS。仅支持 Debian 和 Ubuntu。${Font}" "${Red}Unsupported OS: $OS. Only Debian and Ubuntu are supported.${Font}"
        exit 1
    fi
    
    if [[ -z "$CODENAME" ]]; then
        lang_echo "${Red}无法确定系统代号 (codename)，请手动设置 VERSION_CODENAME 环境变量。${Font}" "${Red}Could not determine OS codename; please set VERSION_CODENAME manually.${Font}"
        exit 1
    fi
}

# 安装 Cloudflare WARP
install_warp() {
    lang_echo "${Blue}正在安装 Cloudflare WARP...${Font}" "${Blue}Installing Cloudflare WARP...${Font}"
    
    # 安装依赖
    apt-get update
    apt-get install -y curl gpg lsb-release

    # 添加 GPG 密钥
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg

    # 添加源
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $CODENAME main" | tee /etc/apt/sources.list.d/cloudflare-client.list

    # 安装
    apt-get update
    apt-get install -y cloudflare-warp

    if ! command -v warp-cli &> /dev/null; then
        lang_echo "${Red}Cloudflare WARP 安装失败！${Font}" "${Red}Cloudflare WARP installation failed!${Font}"
        return 1
    fi
    
    lang_echo "${Green}Cloudflare WARP 安装成功！${Font}" "${Green}Cloudflare WARP installed!${Font}"
    configure_warp
}

# 配置 WARP
configure_warp() {
    lang_echo "${Blue}正在配置 Cloudflare WARP...${Font}" "${Blue}Configuring Cloudflare WARP...${Font}"
    lang_echo "${Yellow}当前模式: ${WARP_MODE}${Font}" "${Yellow}Current mode: ${WARP_MODE}${Font}"
    
    # 注册
    lang_echo "${Yellow}正在注册 WARP 客户端...${Font}" "${Yellow}Registering WARP client...${Font}"
    
    case "${WARP_MODE}" in
        "plus")
            if [[ -n "$WARP_LICENSE_KEY" ]]; then
                lang_echo "${Green}使用 License Key 注册 WARP+...${Font}" "${Green}Registering WARP+ with license key...${Font}"
                warp-cli registration license "$WARP_LICENSE_KEY"
            else
                lang_echo "${Red}错误: WARP_MODE 设置为 'plus' 但未提供 WARP_LICENSE_KEY。${Font}" "${Red}Error: WARP_MODE is 'plus' but WARP_LICENSE_KEY is missing.${Font}"
                lang_echo "${Yellow}回退到免费版注册...${Font}" "${Yellow}Falling back to free registration...${Font}"
                warp-cli registration new
            fi
            ;;
        "zerotrust")
            if [[ -n "$WARP_TEAM_NAME" ]]; then
                lang_echo "${Green}正在注册 Zero Trust 团队 '$WARP_TEAM_NAME'...${Font}" "${Green}Registering Zero Trust team '$WARP_TEAM_NAME'...${Font}"
                warp-cli registration organization "$WARP_TEAM_NAME"
                lang_echo "${Yellow}请注意：Zero Trust 模式通常需要浏览器验证或 Token。${Font}" "${Yellow}Note: Zero Trust mode often needs browser or token verification.${Font}"
                lang_echo "${Yellow}如果脚本卡住或无法连接，请手动运行 'warp-cli registration token <token>' 完成验证。${Font}" "${Yellow}If it hangs, run 'warp-cli registration token <token>' manually.${Font}"
            else
                 lang_echo "${Red}错误: WARP_MODE 设置为 'zerotrust' 但未提供 WARP_TEAM_NAME。${Font}" "${Red}Error: WARP_MODE is 'zerotrust' but WARP_TEAM_NAME is missing.${Font}"
                 lang_echo "${Yellow}回退到免费版注册...${Font}" "${Yellow}Falling back to free registration...${Font}"
                 warp-cli registration new
            fi
            ;;
        "free"|*)
            lang_echo "${Green}正在注册免费版账户...${Font}" "${Green}Registering free account...${Font}"
            warp-cli registration new
            ;;
    esac

    # 设置模式为代理
    warp-cli mode proxy
    
    # 设置端口
    lang_echo "${Green}设置 SOCKS5 代理端口为: ${WARP_PROXY_PORT}${Font}" "${Green}Setting SOCKS5 proxy port: ${WARP_PROXY_PORT}${Font}"
    warp-cli proxy port "$WARP_PROXY_PORT"
    
    # 连接
    warp-cli connect
    
    # 设置开机自启 (Always On)
    warp-cli enable-always-on
    
    lang_echo "${Green}WARP 配置完成！端口：${WARP_PROXY_PORT}${Font}" "${Green}WARP configured! Port: ${WARP_PROXY_PORT}${Font}"
    
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}WARP 配置信息：${Font}" "${Green}WARP configuration:${Font}"
    lang_echo "${Yellow}SOCKS5 端口: ${WARP_PROXY_PORT}${Font}" "${Yellow}SOCKS5 port: ${WARP_PROXY_PORT}${Font}"
    lang_echo "${Yellow}配置管理: 使用 'warp-cli' 命令${Font}" "${Yellow}Manage with 'warp-cli' commands${Font}"
    echo -e "${Blue}============================================${Font}"
    
    # 验证
    verify_warp
}

# 验证 WARP
verify_warp() {
    lang_echo "${Blue}正在验证 WARP 连接...${Font}" "${Blue}Verifying WARP connection...${Font}"
    sleep 5 # 等待连接建立
    
    local current_ip=$(curl -s https://ifconfig.me)
    local warp_ip=$(curl -s -x socks5://127.0.0.1:${WARP_PROXY_PORT} https://ifconfig.me)
    
    lang_echo "当前直连 IP: ${Yellow}$current_ip${Font}" "Direct IP: ${Yellow}$current_ip${Font}"
    lang_echo "WARP 代理 IP: ${Green}$warp_ip${Font}" "WARP proxy IP: ${Green}$warp_ip${Font}"
    
    if [[ "$current_ip" != "$warp_ip" && -n "$warp_ip" ]]; then
        lang_echo "${Green}验证成功！WARP 已生效。${Font}" "${Green}Success! WARP is active.${Font}"
    else
        lang_echo "${Red}验证失败！IP 未改变或无法连接 WARP。请检查日志。${Font}" "${Red}Verification failed! IP unchanged or WARP unreachable. Check logs.${Font}"
    fi
}

# 安装 Sing-box
install_singbox() {
    lang_echo "${Blue}检查 Sing-box 安装状态...${Font}" "${Blue}Checking Sing-box installation...${Font}"
    
    local singbox_path=""
    
    # 检查 install.sh 安装的路径
    if [[ -f "/etc/v2ray-agent/sing-box/sing-box" ]]; then
        singbox_path="/etc/v2ray-agent/sing-box/sing-box"
        lang_echo "${Yellow}检测到已通过 install.sh 安装 Sing-box：$singbox_path${Font}" "${Yellow}Detected Sing-box installed via install.sh at: $singbox_path${Font}"
    elif command -v sing-box &> /dev/null; then
        singbox_path=$(command -v sing-box)
        lang_echo "${Yellow}检测到系统已安装 Sing-box：$singbox_path${Font}" "${Yellow}Detected system Sing-box at: $singbox_path${Font}"
    else
        lang_echo "${Yellow}未检测到 Sing-box，开始安装最新稳定版...${Font}" "${Yellow}No Sing-box found, installing latest stable...${Font}"
        bash <(curl -fsSL https://sing-box.app/deb-install.sh)
        singbox_path=$(command -v sing-box)
    fi
    
    if [[ -z "$singbox_path" ]]; then
        lang_echo "${Red}Sing-box 安装失败！${Font}" "${Red}Sing-box installation failed!${Font}"
        return 1
    fi
    
    generate_config
}

# 生成 Config
generate_config() {
    lang_echo "${Blue}生成 Sing-box 配置文件模板...${Font}" "${Blue}Generating Sing-box config template...${Font}"
    
    local config_dir="/etc/sing-box"
    local config_file="$config_dir/config.json"
    
    # 如果是 install.sh 的路径
    if [[ -d "/etc/v2ray-agent/sing-box/conf" ]]; then
        config_dir="/etc/v2ray-agent/sing-box/conf"
        config_file="$config_dir/config_warp_template.json"
        lang_echo "${Yellow}注意：检测到 v2ray-agent 目录。为避免冲突，配置文件将生成为：$config_file${Font}" "${Yellow}Detected v2ray-agent directory; config will be created at $config_file to avoid conflicts.${Font}"
        lang_echo "${Yellow}请手动将此配置整合到您的主配置文件中。${Font}" "${Yellow}Please merge this config into your main config manually.${Font}"
    else
        mkdir -p "$config_dir"
        if [[ -f "$config_file" ]]; then
            mv "$config_file" "${config_file}.bak.$(date +%F_%T)"
            lang_echo "${Yellow}原配置文件已备份。${Font}" "${Yellow}Existing config backed up.${Font}"
        fi
    fi

    cat > "$config_file" <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "::",
      "listen_port": ${SINGBOX_INBOUND_PORT},
      "sniff": true
    }
    // =======================================================
    // [用户自定义区域]
    // 请在此处添加您的入站协议 (VLESS, VMess, Trojan 等)
    // 注意保持 JSON 格式正确 (逗号分隔)
    // =======================================================
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "socks",
      "tag": "warp-out",
      "server": "127.0.0.1",
      "server_port": ${WARP_PROXY_PORT}
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "rules": [
      {
        "rule_set": [
          "geosite-google",
          "geosite-openai"
        ],
        "outbound": "warp-out"
      },
      {
        "rule_set": [
          "geosite-cn",
          "geoip-cn"
        ],
        "outbound": "direct"
      }
    ],
    "rule_set": [
      {
        "tag": "geosite-google",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-google.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geosite-openai",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-openai.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-cn.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geoip-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/SagerNet/sing-geoip/raw/rule-set/geoip-cn.srs",
        "download_detour": "direct"
      }
    ],
    "final": "direct",
    "auto_detect_interface": true
  }
}
EOF

    lang_echo "${Green}配置文件已生成：$config_file${Font}" "${Green}Config generated at: $config_file${Font}"
    lang_echo "${Yellow}请务必编辑该文件，在 inbounds 中添加您的节点配置！${Font}" "${Yellow}Please edit the file and add your inbound nodes!${Font}"
    
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}核心配置文件路径：${Font}" "${Green}Key config paths:${Font}"
    lang_echo "${Yellow}Sing-box Config: ${config_file}${Font}" "${Yellow}Sing-box Config: ${config_file}${Font}"
    echo -e "${Blue}============================================${Font}"
    
    # 尝试重启 Sing-box 服务
    lang_echo "${Blue}尝试重启 Sing-box 服务...${Font}" "${Blue}Trying to restart Sing-box service...${Font}"
    if systemctl list-units --full -all | grep -q "sing-box.service"; then
        systemctl restart sing-box
        lang_echo "${Green}Sing-box 服务已重启。${Font}" "${Green}Sing-box service restarted.${Font}"
    elif systemctl list-units --full -all | grep -q "v2ray-agent-sing-box.service"; then
        systemctl restart v2ray-agent-sing-box
        lang_echo "${Green}v2ray-agent-sing-box 服务已重启。${Font}" "${Green}v2ray-agent-sing-box service restarted.${Font}"
    else
        lang_echo "${Yellow}未找到 Sing-box 服务，请手动启动。${Font}" "${Yellow}Sing-box service not found, please start manually.${Font}"
        lang_echo "${Yellow}命令示例: sing-box run -c $config_file${Font}" "${Yellow}Example: sing-box run -c $config_file${Font}"
    fi
}

# 卸载功能
uninstall() {
    lang_echo "${Red}警告：这将卸载 Cloudflare WARP 和 Sing-box (如果是通过此脚本安装的)${Font}" "${Red}Warning: this will uninstall Cloudflare WARP and Sing-box (if installed via this script).${Font}"
    read -p "$(lang_text "确定要继续吗？[y/N]: " "Are you sure? [y/N]: ")" confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        lang_echo "取消卸载。" "Uninstall cancelled."
        return
    fi

    lang_echo "${Blue}正在卸载 Cloudflare WARP...${Font}" "${Blue}Uninstalling Cloudflare WARP...${Font}"
    warp-cli disconnect
    apt-get remove -y cloudflare-warp
    rm -f /etc/apt/sources.list.d/cloudflare-client.list
    rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    
    lang_echo "${Blue}是否卸载 Sing-box？${Font}" "${Blue}Uninstall Sing-box as well?${Font}"
    read -p "$(lang_text "卸载 Sing-box? [y/N]: " "Uninstall Sing-box? [y/N]: ")" uninstall_sb
    if [[ "$uninstall_sb" =~ ^[Yy]$ ]]; then
        if [[ -f "/etc/v2ray-agent/sing-box/sing-box" ]]; then
            lang_echo "${Yellow}检测到 Sing-box 是通过 install.sh 安装的，建议使用 install.sh 进行卸载。${Font}" "${Yellow}Sing-box seems installed by install.sh; consider uninstalling via that script.${Font}"
        else
            apt-get remove -y sing-box
            rm -rf /etc/sing-box
        fi
    fi
    
    lang_echo "${Green}卸载完成。${Font}" "${Green}Uninstall finished.${Font}"
}

# 菜单
show_menu() {
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}    WARP & Sing-box 一键配置脚本${Font}" "${Green}    WARP & Sing-box quick setup${Font}"
    echo -e "${Blue}============================================${Font}"
    lang_echo "1. 安装/配置 WARP + Sing-box" "1. Install/Configure WARP + Sing-box"
    lang_echo "2. 仅配置 WARP (SOCKS5 模式)" "2. Configure WARP only (SOCKS5)"
    lang_echo "3. 验证 WARP 状态" "3. Verify WARP status"
    lang_echo "4. 卸载 WARP & Sing-box" "4. Uninstall WARP & Sing-box"
    lang_echo "0. 退出" "0. Exit"
    echo
    read -p "$(lang_text "请选择 [0-4]: " "Choose [0-4]: ")" choice
    
    case "$choice" in
        1)
            check_root
            check_os
            install_warp
            install_singbox
            ;;
        2)
            check_root
            check_os
            install_warp
            ;;
        3)
            verify_warp
            ;;
        4)
            check_root
            uninstall
            ;;
        0)
            exit 0
            ;;
        *)
            lang_echo "无效选择" "Invalid option"
            ;;
    esac
}

# 如果有参数，直接执行对应功能（预留给 main.sh 调用）
if [[ -n "$1" ]]; then
    case "$1" in
        "install")
            check_root
            check_os
            install_warp
            install_singbox
            ;;
        "uninstall")
            check_root
            uninstall
            ;;
        *)
            show_menu
            ;;
    esac
else
    show_menu
fi
