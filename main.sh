#!/usr/bin/env bash
#One-Script 主启动脚本 - 自动管理虚拟内存并提供脚本选择

# 颜色定义
Green="\033[32m"
Font="\033[0m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[34m"

clear() {
    :
}

CHANNEL="main"
BASE_URL=""
QUICK_SCRIPT_URL="https://raw.githubusercontent.com/charleslkx/quick-script/main/main.sh"
V2RAY_ORIGINAL_URL="https://raw.githubusercontent.com/mack-a/v2ray-agent/main/install.sh"
REMOTE_COMMAND_NAME="v2ray"
TEMP_DIR="/tmp"
release=""
installType=""
upgrade=""
removeType=""
updateReleaseInfoChange=""
ZRAM_SERVICE_FILE="/etc/systemd/system/one-script-zram.service"
ZRAM_SCRIPT_PATH="/usr/local/bin/one-script-zram"
ZRAM_ENV_FILE="/etc/one-script/zram.env"
SKIP_CLEAR_ONCE="false"

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

lang_text() {
    local zh="$1"
    printf "%b" "${zh}"
}

lang_echo() {
    local zh="$1"
    echo -e "${zh}"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

download_file() {
    local url="$1"
    local dest="$2"

    if command_exists wget; then
        wget -qO "$dest" "$url" 2>/dev/null
        return $?
    fi
    if command_exists curl; then
        curl -fsSL "$url" -o "$dest" 2>/dev/null
        return $?
    fi
    return 1
}

run_remote_script() {
    local url="$1"
    shift

    if command_exists wget; then
        ONE_SCRIPT_CHANNEL="${CHANNEL}" ONE_SCRIPT_BASE_URL="${BASE_URL}" \
            bash <(wget -qO- "$url" 2>/dev/null) "$@"
        return $?
    fi
    if command_exists curl; then
        ONE_SCRIPT_CHANNEL="${CHANNEL}" ONE_SCRIPT_BASE_URL="${BASE_URL}" \
            bash <(curl -fsSL "$url" 2>/dev/null) "$@"
        return $?
    fi
    return 1
}

GAI_CONF_FILE="/etc/gai.conf"
GAI_CONF_BACKUP="/etc/gai.conf.bak"

normalize_ip_preference() {
    local pref=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    case "${pref}" in
    ipv6 | 6)
        echo "ipv6"
        ;;
    ipv4 | 4 | "")
        echo "ipv4"
        ;;
    *)
        echo "ipv4"
        ;;
    esac
}

ensure_gai_conf_file() {
    if [[ ! -f "${GAI_CONF_FILE}" ]]; then
        touch "${GAI_CONF_FILE}"
    fi
    if [[ -f "${GAI_CONF_FILE}" && ! -f "${GAI_CONF_BACKUP}" ]]; then
        cp "${GAI_CONF_FILE}" "${GAI_CONF_BACKUP}"
    fi
}

detect_global_ip_preference() {
    if [[ -f "${GAI_CONF_FILE}" ]] && grep -Eq '^[[:space:]]*precedence[[:space:]]+::ffff:0:0/96[[:space:]]+100' "${GAI_CONF_FILE}"; then
        echo "ipv4"
    else
        echo "ipv6"
    fi
}

set_global_ip_preference() {
    local pref=$(normalize_ip_preference "$1")
    ensure_gai_conf_file

    if [[ "${pref}" == "ipv4" ]]; then
        if grep -Eq '^[#[:space:]]*precedence[[:space:]]+::ffff:0:0/96' "${GAI_CONF_FILE}"; then
            sed -i 's/^[#[:space:]]*precedence[[:space:]]\+::ffff:0:0\/96.*/precedence ::ffff:0:0\/96  100/' "${GAI_CONF_FILE}"
        else
            echo "precedence ::ffff:0:0/96  100" >>"${GAI_CONF_FILE}"
        fi
    else
        if grep -Eq '^[[:space:]]*precedence[[:space:]]+::ffff:0:0/96[[:space:]]+100' "${GAI_CONF_FILE}"; then
            sed -i 's/^[[:space:]]*precedence[[:space:]]\+::ffff:0:0\/96[[:space:]]\+100/# precedence ::ffff:0:0\/96  100/' "${GAI_CONF_FILE}"
        elif ! grep -Eq '^#?[[:space:]]*precedence[[:space:]]+::ffff:0:0/96' "${GAI_CONF_FILE}"; then
            echo "# precedence ::ffff:0:0/96  100" >>"${GAI_CONF_FILE}"
        fi
    fi
}

quick_switch_ip_priority() {
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}    快速切换服务器 IPv4/IPv6 优先级${Font}"
    echo -e "${Blue}============================================${Font}"
    echo

    local current_pref
    current_pref=$(detect_global_ip_preference)
    if [[ "${current_pref}" == "ipv4" ]]; then
        lang_echo "${Yellow}当前状态：IPv4 优先（通过 /etc/gai.conf 配置）${Font}"
    else
        lang_echo "${Yellow}当前状态：IPv6 优先（系统默认）${Font}"
    fi
    echo
    lang_echo "${Green}请选择目标优先级：${Font}"
    lang_echo "${Yellow}1.${Font} 设置为 IPv4 优先（解析域名时优先使用 IPv4）"
    lang_echo "${Yellow}2.${Font} 设置为 IPv6 优先（恢复系统默认策略）"
    lang_echo "${Yellow}3.${Font} 取消操作"
    echo
    read -p "$(lang_text "请输入选择 [1-3]: ")" ip_choice

    case "${ip_choice}" in
    1)
        set_global_ip_preference "ipv4"
        lang_echo "${Green}已设置为 IPv4 优先。对新发起的域名解析立即生效。${Font}"
        ;;
    2)
        set_global_ip_preference "ipv6"
        lang_echo "${Green}已恢复为 IPv6 优先。对新发起的域名解析立即生效。${Font}"
        ;;
    *)
        lang_echo "${Yellow}已取消操作。${Font}"
        ;;
    esac
}

# 安装简易命令（远程运行版本）
install_quick_command() {
    echo -e "${Blue}正在安装简易命令...${Font}"
    
    local command_name="${REMOTE_COMMAND_NAME}"
    local vasmaType=false
    
    # 显示当前环境信息
    echo -e "${Green}当前用户：$(whoami)${Font}"
    echo -e "${Green}安装模式：远程运行${Font}"
    echo
    
    # 创建远程运行脚本内容
    local remote_script_content='#!/usr/bin/env bash
# One-Script 远程运行快捷命令
# 此脚本将直接从远程仓库获取并运行最新版本

# 颜色定义
Green="\033[32m"
Font="\033[0m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[34m"

# 远程仓库地址
BASE_URL="https://raw.githubusercontent.com/charleslkx/one-script/'"${CHANNEL}"'"

# 检查网络连接
check_network() {
    echo -e "${Blue}正在检查网络连接...${Font}"
    if ping -c 1 raw.githubusercontent.com >/dev/null 2>&1; then
        echo -e "${Green}网络连接正常${Font}"
        return 0
    else
        echo -e "${Red}无法连接到远程仓库，请检查网络连接${Font}"
        return 1
    fi
}

# 运行远程脚本
run_remote_script() {
    echo -e "${Blue}正在从远程仓库获取最新版本...${Font}"
    echo -e "${Green}仓库地址：${BASE_URL}/main.sh${Font}"
    echo
    
    # 尝试使用 wget 或 curl 运行远程脚本
    if command -v wget >/dev/null 2>&1; then
        echo -e "${Blue}使用 wget 获取脚本...${Font}"
        bash <(wget -qO- "${BASE_URL}/main.sh" 2>/dev/null) "$@"
    elif command -v curl >/dev/null 2>&1; then
        echo -e "${Blue}使用 curl 获取脚本...${Font}"
        bash <(curl -fsSL "${BASE_URL}/main.sh" 2>/dev/null) "$@"
    else
        echo -e "${Red}错误：未找到 wget 或 curl 工具${Font}"
        echo -e "${Yellow}请安装 wget 或 curl 后重试${Font}"
        exit 1
    fi
}

# 显示帮助信息
show_help() {
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}      One-Script 远程运行命令${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    echo -e "${Green}用法：${Font}"
    echo -e "  v2ray [选项]"
    echo
    echo -e "${Green}选项：${Font}"
    echo -e "  ${Yellow}--help, -h${Font}              显示此帮助信息"
    echo -e "  ${Yellow}--version, -v${Font}           显示版本信息"
    echo -e "  ${Yellow}--install-command${Font}       重新安装远程运行命令"
    echo -e "  ${Yellow}--uninstall-command${Font}     卸载远程运行命令"
    echo
    echo -e "${Green}特性：${Font}"
    echo -e "  • 始终运行最新版本脚本"
    echo -e "  • 无需本地存储脚本文件"
    echo -e "  • 自动网络连接检查"
    echo
    echo -e "${Green}GitHub仓库：${Font}https://github.com/charleslkx/one-script"
    echo -e "${Blue}============================================${Font}"
}

# 主函数
main() {
    case "${1:-}" in
        "--help"|"-h")
            show_help
            exit 0
            ;;
        "--version"|"-v")
            echo -e "${Green}One-Script 远程运行命令 v1.0${Font}"
            echo -e "${Green}GitHub: https://github.com/charleslkx/one-script${Font}"
            exit 0
            ;;
        "--install-command")
            echo -e "${Yellow}请使用本地脚本的安装命令功能${Font}"
            exit 0
            ;;
        "--uninstall-command")
            echo -e "${Yellow}请使用本地脚本的卸载命令功能${Font}"
            exit 0
            ;;
    esac
    
    # 检查网络连接
    if ! check_network; then
        exit 1
    fi
    
    # 运行远程脚本
    run_remote_script "$@"
}

# 启动
main "$@"'
    
    # 尝试在 /usr/bin 中创建远程运行命令
    if [[ -d "/usr/bin/" ]]; then
        local bin_path="/usr/bin/${command_name}"
        echo -e "${Green}目标安装路径：${bin_path}${Font}"
        
        if [[ ! -f "$bin_path" ]]; then
            if echo "$remote_script_content" > "$bin_path" 2>/dev/null && chmod 755 "$bin_path" 2>/dev/null; then
                vasmaType=true
                echo -e "${Green}在 /usr/bin 中创建远程运行命令成功${Font}"
            else
                echo -e "${Yellow}在 /usr/bin 中创建远程运行命令失败${Font}"
            fi
        else
            echo -e "${Yellow}检测到 ${bin_path} 已存在${Font}"
            echo -e "${Yellow}是否要重新安装？[y/N]:${Font}"
            read -p "" reinstall_choice
            if [[ $reinstall_choice =~ ^[Yy]$ ]]; then
                rm -f "$bin_path"
                if echo "$remote_script_content" > "$bin_path" 2>/dev/null && chmod 755 "$bin_path" 2>/dev/null; then
                    vasmaType=true
                    echo -e "${Green}重新安装远程运行命令成功${Font}"
                fi
            fi
        fi
    fi
    
    # 如果 /usr/bin 失败，尝试 /usr/sbin
    if [[ "$vasmaType" == "false" && -d "/usr/sbin/" ]]; then
        local sbin_path="/usr/sbin/${command_name}"
        echo -e "${Green}尝试在 /usr/sbin 中安装：${sbin_path}${Font}"
        
        if [[ ! -f "$sbin_path" ]]; then
            if echo "$remote_script_content" > "$sbin_path" 2>/dev/null && chmod 755 "$sbin_path" 2>/dev/null; then
                vasmaType=true
                echo -e "${Green}在 /usr/sbin 中创建远程运行命令成功${Font}"
            else
                echo -e "${Yellow}在 /usr/sbin 中创建远程运行命令失败${Font}"
            fi
        fi
    fi
    
    # 如果以上都失败，尝试 /usr/local/bin
    if [[ "$vasmaType" == "false" ]]; then
        local local_bin_path="/usr/local/bin/${command_name}"
        echo -e "${Green}尝试在 /usr/local/bin 中安装：${local_bin_path}${Font}"
        
        # 确保目录存在
        if [[ ! -d "/usr/local/bin" ]]; then
            echo -e "${Yellow}/usr/local/bin 目录不存在，正在创建...${Font}"
            mkdir -p /usr/local/bin
        fi
        
        if [[ ! -f "$local_bin_path" ]]; then
            if echo "$remote_script_content" > "$local_bin_path" 2>/dev/null && chmod 755 "$local_bin_path" 2>/dev/null; then
                vasmaType=true
                echo -e "${Green}在 /usr/local/bin 中创建远程运行命令成功${Font}"
            else
                echo -e "${Red}在 /usr/local/bin 中创建远程运行命令失败${Font}"
            fi
        fi
    fi
    
    # 显示安装结果
    if [[ "$vasmaType" == "true" ]]; then
        echo
        echo -e "${Green}远程运行命令创建成功！${Font}"
        echo -e "${Yellow}使用方法：${Font}"
        echo -e "${Blue}  ${command_name}${Font}                # 从远程启动最新版本脚本"
        echo -e "${Blue}  sudo ${command_name}${Font}           # 以root权限从远程启动脚本"
        echo -e "${Blue}  ${command_name} --help${Font}         # 查看帮助信息"
        echo -e "${Blue}  ${command_name} --version${Font}      # 查看版本信息"
        echo
        echo -e "${Green}特性：${Font}"
        echo -e "${Green}  • 始终运行最新版本${Font}"
        echo -e "${Green}  • 无需本地存储脚本${Font}"
        echo -e "${Green}  • 自动检查网络连接${Font}"
        echo
        echo -e "${Yellow}注意：运行时需要网络连接到 GitHub${Font}"
    else
        echo -e "${Red}远程运行命令创建失败！${Font}"
        echo -e "${Yellow}请检查权限或手动创建${Font}"
    fi
}

# 卸载简易命令
uninstall_quick_command() {
    local command_name="${REMOTE_COMMAND_NAME}"
    local removed=false
    
    echo -e "${Yellow}正在卸载简易命令...${Font}"
    
    # 检查并删除 /usr/bin 中的命令
    if [[ -f "/usr/bin/${command_name}" ]]; then
        if rm -f "/usr/bin/${command_name}"; then
            echo -e "${Green}已从 /usr/bin 中移除 '${command_name}'${Font}"
            removed=true
        else
            echo -e "${Red}从 /usr/bin 中移除 '${command_name}' 失败${Font}"
        fi
    fi
    
    # 检查并删除 /usr/sbin 中的命令
    if [[ -f "/usr/sbin/${command_name}" ]]; then
        if rm -f "/usr/sbin/${command_name}"; then
            echo -e "${Green}已从 /usr/sbin 中移除 '${command_name}'${Font}"
            removed=true
        else
            echo -e "${Red}从 /usr/sbin 中移除 '${command_name}' 失败${Font}"
        fi
    fi
    
    # 检查并删除 /usr/local/bin 中的命令
    if [[ -f "/usr/local/bin/${command_name}" ]]; then
        if rm -f "/usr/local/bin/${command_name}"; then
            echo -e "${Green}已从 /usr/local/bin 中移除 '${command_name}'${Font}"
            removed=true
        else
            echo -e "${Red}从 /usr/local/bin 中移除 '${command_name}' 失败${Font}"
        fi
    fi
    
    if [[ "$removed" == "true" ]]; then
        echo -e "${Green}简易命令 '${command_name}' 卸载成功！${Font}"
    else
        echo -e "${Yellow}简易命令 '${command_name}' 未安装或已被移除${Font}"
    fi
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${Red}错误：此脚本必须以 root 权限运行！${Font}"
        exit 1
    fi
}

# 检查是否是完整的su登录模拟
check_su_login() {
    # 只在 root 用户且在 Linux 系统上检查
    if [[ $EUID -ne 0 ]] || [[ ! -f /etc/debian_version && ! -f /etc/redhat-release && ! -f /etc/alpine-release ]]; then
        return 0
    fi
    
    # 检查是否是通过 su - 进入的（完整登录模拟）
    # 完整登录模拟的特征：
    # 1. HOME 应该是 /root
    # 2. PATH 应该包含 /usr/sbin 和 /sbin
    # 3. USER 或 LOGNAME 应该是 root
    
    local is_proper_login=true
    
    # 检查 HOME 环境变量
    if [[ "${HOME}" != "/root" ]]; then
        is_proper_login=false
    fi
    
    # 检查 PATH 是否包含必要的系统路径
    if ! echo "${PATH}" | grep -q "/sbin" || ! echo "${PATH}" | grep -q "/usr/sbin"; then
        is_proper_login=false
    fi
    
    # 如果不是完整登录模拟，提示用户
    if [[ "${is_proper_login}" == "false" ]]; then
        echo -e "${Yellow}============================================${Font}"
        echo -e "${Yellow}警告：检测到您可能使用了 'su' 而非 'su -' 切换到 root${Font}"
        echo -e "${Yellow}这可能导致环境变量（如 PATH）不完整，影响脚本正常运行${Font}"
        echo -e "${Blue}============================================${Font}"
        echo -e "${Green}当前环境信息：${Font}"
        echo -e "  HOME: ${HOME}"
        echo -e "  PATH: ${PATH}"
        echo -e "${Blue}============================================${Font}"
        echo
        echo -e "${Green}建议：使用 'su -' 进行完整的登录模拟${Font}"
        echo -e "${Yellow}是否现在切换到完整登录模拟并重新运行脚本？ [Y/n]${Font}"
        read -r -p "请选择 (默认: Y): " choice
        choice=${choice:-Y}
        
        case "${choice}" in
            [Yy]|[Yy][Ee][Ss]|"")
                echo -e "${Green}正在切换到完整登录模拟...${Font}"
                # 使用 su - 切换并重新运行脚本
                exec su - -c "ONE_SCRIPT_CHANNEL=${CHANNEL} bash <(curl -fsSL ${BASE_URL}/main.sh)"
                ;;
            *)
                echo -e "${Yellow}继续使用当前环境运行脚本...${Font}"
                echo -e "${Red}注意：这可能会导致某些功能异常！${Font}"
                sleep 2
                ;;
        esac
    fi
}

# 检查OpenVZ
check_ovz() {
    if [[ -d "/proc/vz" ]]; then
        echo -e "${Red}错误：您的VPS基于OpenVZ，不支持创建swap！${Font}"
        exit 1
    fi
}

# 系统检测和环境初始化
check_system_environment() {
    echo -e "${Blue}正在检测系统环境...${Font}"
    
    # 检测系统发行版
    release=""
    installType=""
    upgrade=""
    removeType=""
    updateReleaseInfoChange=""
    
    if [[ -n $(find /etc -name "redhat-release") ]] || grep </proc/version -q -i "centos"; then
        mkdir -p /etc/yum.repos.d
        
        if [[ -f "/etc/centos-release" ]]; then
            centosVersion=$(rpm -q centos-release | awk -F "[-]" '{print $3}' | awk -F "[.]" '{print $1}')
            
            if [[ -z "${centosVersion}" ]] && grep </etc/centos-release -q -i "release 8"; then
                centosVersion=8
            fi
        fi
        
        release="centos"
        installType='yum -y install'
        removeType='yum -y remove'
        upgrade="yum update -y --skip-broken"
        
    elif { [[ -f "/etc/issue" ]] && grep -qi "Alpine" /etc/issue; } || { [[ -f "/proc/version" ]] && grep -qi "Alpine" /proc/version; }; then
        release="alpine"
        installType='apk add'
        upgrade="apk update"
        removeType='apk del'
        
    elif { [[ -f "/etc/issue" ]] && grep -qi "debian" /etc/issue; } || { [[ -f "/proc/version" ]] && grep -qi "debian" /proc/version; } || { [[ -f "/etc/os-release" ]] && grep -qi "ID=debian" /etc/os-release; }; then
        release="debian"
        installType='apt -y install'
        upgrade="apt update"
        updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
        removeType='apt -y autoremove'
        
    elif { [[ -f "/etc/issue" ]] && grep -qi "ubuntu" /etc/issue; } || { [[ -f "/proc/version" ]] && grep -qi "ubuntu" /proc/version; } || { [[ -f "/etc/os-release" ]] && grep -qi "ID=ubuntu" /etc/os-release; }; then
        release="ubuntu"
        installType='apt -y install'
        upgrade="apt update"
        updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
        removeType='apt -y autoremove'
        
        if grep </etc/issue -q -i "16."; then
            echo -e "${Red}Ubuntu 16版本不建议使用此脚本，建议升级系统${Font}"
            exit 0
        fi
    fi
    
    if [[ -z ${release} ]]; then
        echo -e "${Red}本脚本不支持此系统，请将下方日志反馈给开发者${Font}"
        echo -e "${Yellow}$(cat /etc/issue)${Font}"
        echo -e "${Yellow}$(cat /proc/version)${Font}"
        exit 0
    fi
    
    echo -e "${Green}检测到系统：${release}${Font}"
    echo -e "${Green}包管理器：${installType}${Font}"
}

# 检查CPU架构
check_cpu_vendor() {
    echo -e "${Blue}正在检测CPU架构...${Font}"
    
    if [[ -n $(which uname) ]]; then
        if [[ "$(uname)" == "Linux" ]]; then
            case "$(uname -m)" in
            'amd64' | 'x86_64')
                cpuVendor="amd64"
                echo -e "${Green}CPU架构：x86_64/amd64${Font}"
                ;;
            'armv8' | 'aarch64')
                cpuVendor="arm64"
                echo -e "${Green}CPU架构：arm64${Font}"
                ;;
            'armv7' | 'armv7l')
                cpuVendor="arm"
                echo -e "${Green}CPU架构：arm${Font}"
                ;;
            *)
                cpuVendor="amd64"
                echo -e "${Yellow}未知架构，默认使用 amd64${Font}"
                ;;
            esac
        fi
    else
        cpuVendor="amd64"
        echo -e "${Yellow}无法检测架构，默认使用 amd64${Font}"
    fi
}

# 检查并配置系统locale
check_and_configure_locale() {
    echo -e "${Blue}检查系统locale配置${Font}"
    
    # 检查locale配置文件是否已正确设置（避免重复配置）
    local localeConfigured=false
    if [[ -f /etc/default/locale ]] && grep -q "LANG=C.UTF-8" /etc/default/locale 2>/dev/null; then
        localeConfigured=true
    elif [[ -f /etc/locale.conf ]] && grep -q "LANG=C.UTF-8" /etc/locale.conf 2>/dev/null; then
        localeConfigured=true
    fi
    
    if [[ "${localeConfigured}" == "true" ]]; then
        echo -e "${Green} ---> locale配置文件已存在: C.UTF-8${Font}"
        # 为当前会话设置环境变量（即使locale -a检测不到）
        export LANG=C.UTF-8
        export LC_ALL=C.UTF-8
        export LANGUAGE=
        return 0
    fi
    
    # 检测当前locale设置
    local currentLang="${LANG:-}"
    local localeInstalled=false
    local effectiveLocale=""

    has_locale() {
        local loc="$1"
        if locale -a 2>/dev/null | grep -qi "^${loc}$"; then
            return 0
        fi
        # 兼容 en_US.utf8/C.utf8 变体
        if [[ "${loc}" == "en_US.UTF-8" ]] && locale -a 2>/dev/null | grep -qi "^en_US\.utf8$"; then
            return 0
        fi
        if [[ "${loc}" == "C.UTF-8" ]] && locale -a 2>/dev/null | grep -qi "^C\.utf8$"; then
            return 0
        fi
        return 1
    }
    
    # 检查是否已经配置了有效的C.UTF-8 locale
    if [[ -n "${currentLang}" ]] && has_locale "${currentLang}"; then
        if [[ "${currentLang}" == "C.UTF-8" ]] || [[ "${currentLang}" == "C.utf8" ]]; then
            echo -e "${Green} ---> locale已正确配置: C.UTF-8${Font}"
            return 0
        fi
    fi
    
    # 如果当前locale不是C.UTF-8，则需要配置
    
    echo -e "${Yellow} ---> 检测到locale配置问题，正在修复...${Font}"
    
    # 针对Debian/Ubuntu系统
    if [[ "${release}" == "debian" ]] || [[ "${release}" == "ubuntu" ]]; then
        # 检查并安装locales包
        if ! dpkg -l 2>/dev/null | grep -q "^ii.*locales"; then
            echo -e "${Green} ---> 安装locales包${Font}"
            ${installType} locales >/dev/null 2>&1
        fi
        
        # 生成常用的UTF-8 locales
        echo -e "${Green} ---> 生成UTF-8 locale${Font}"
        
        # 确保locale配置文件存在
        if [[ ! -f /etc/locale.gen ]]; then
            touch /etc/locale.gen
        fi
        
        # 确保C.UTF-8被生成（最优先）
        if ! grep -q "^C.UTF-8 UTF-8" /etc/locale.gen 2>/dev/null; then
             if grep -q "^#.*C.UTF-8 UTF-8" /etc/locale.gen 2>/dev/null; then
                 sed -i "s/^#.*C.UTF-8 UTF-8/C.UTF-8 UTF-8/" /etc/locale.gen
             else
                 echo "C.UTF-8 UTF-8" >> /etc/locale.gen
             fi
        fi
        
        # 取消注释或添加其他常用locale
        local targetLocales=("en_US.UTF-8 UTF-8" "zh_CN.UTF-8 UTF-8")
        for loc in "${targetLocales[@]}"; do
            if ! grep -q "^${loc}" /etc/locale.gen 2>/dev/null; then
                if grep -q "^#.*${loc}" /etc/locale.gen 2>/dev/null; then
                    sed -i "s/^#.*${loc}/${loc}/" /etc/locale.gen
                else
                    echo "${loc}" >> /etc/locale.gen
                fi
            fi
        done
        
        # 生成locale
        if command -v locale-gen >/dev/null 2>&1; then
            locale-gen >/dev/null 2>&1
            localeInstalled=true
        fi
        
        # 优先选择C.UTF-8作为系统locale
        if has_locale "C.UTF-8"; then
            effectiveLocale="C.UTF-8"
        elif has_locale "en_US.UTF-8"; then
             effectiveLocale="en_US.UTF-8"
             echo -e "${Yellow} ---> C.UTF-8未找到，使用备用locale: en_US.UTF-8${Font}"
        else
            # 尝试再次生成C.UTF-8
            echo -e "${Yellow} ---> C.UTF-8未找到，正在重新生成...${Font}"
            if ! grep -q "^C.UTF-8 UTF-8" /etc/locale.gen 2>/dev/null; then
                echo "C.UTF-8 UTF-8" >> /etc/locale.gen
            fi
            locale-gen C.UTF-8 >/dev/null 2>&1
            if has_locale "C.UTF-8"; then
                effectiveLocale="C.UTF-8"
                echo -e "${Green} ---> C.UTF-8 生成成功${Font}"
            else
                effectiveLocale="en_US.UTF-8"
                echo -e "${Yellow} ---> 使用备用locale: en_US.UTF-8${Font}"
                # 如果仍需生成en_US
                if ! has_locale "en_US.UTF-8"; then
                    locale-gen en_US.UTF-8 >/dev/null 2>&1
                fi
            fi
        fi
        
        # 更新系统默认locale
        if command -v update-locale >/dev/null 2>&1; then
            update-locale LANG="${effectiveLocale}" LC_ALL="${effectiveLocale}" >/dev/null 2>&1
        fi
        
        # 写入到/etc/default/locale
        cat > /etc/default/locale <<EOF
LANG=${effectiveLocale}
LC_ALL=${effectiveLocale}
LANGUAGE=
EOF
        
    # 针对CentOS/RHEL系统
    elif [[ "${release}" == "centos" ]]; then
        echo -e "${Green} ---> 配置CentOS locale${Font}"
        
        # 安装glibc-common（包含locale定义）
        if ! rpm -q glibc-common >/dev/null 2>&1; then
            ${installType} glibc-common >/dev/null 2>&1
        fi
        
        # 设置系统locale（强制使用C.UTF-8）
        effectiveLocale="C.UTF-8"
        
        # 如果C.UTF-8不可用，尝试使用en_US
        if ! has_locale "C.UTF-8"; then
            echo -e "${Yellow} ---> C.UTF-8未找到，正在安装语言包...${Font}"
            ${installType} glibc-langpack-en >/dev/null 2>&1 || true
            
            # 如果仍然不可用，使用备用locale
            if ! has_locale "C.UTF-8"; then
                if has_locale "en_US.UTF-8"; then
                    effectiveLocale="en_US.UTF-8"
                    echo -e "${Yellow} ---> 使用备用locale: en_US.UTF-8${Font}"
                fi
            else
                echo -e "${Green} ---> C.UTF-8 安装成功${Font}"
            fi
        fi
        
        if command -v localectl >/dev/null 2>&1; then
            localectl set-locale LANG="${effectiveLocale}" >/dev/null 2>&1
            localeInstalled=true
        fi
        
        # 写入到/etc/locale.conf
        cat > /etc/locale.conf <<EOF
LANG=${effectiveLocale}
LC_ALL=${effectiveLocale}
EOF
    fi
    
    # 验证locale是否真正可用
    if [[ -z "${effectiveLocale}" ]]; then
        effectiveLocale="C.UTF-8"
    fi
    
    # 先检查目标locale是否在系统中可用
    local localeAvailable=false
    if has_locale "${effectiveLocale}"; then
        localeAvailable=true
    fi
    
    # 只有在locale真正可用时才设置环境变量
    if [[ "${localeAvailable}" == "true" ]]; then
        export LANG="${effectiveLocale}"
        export LC_ALL="${effectiveLocale}"
        export LANGUAGE=
    else
        # 如果目标locale不可用，使用最小安全设置
        echo -e "${Yellow} ---> 警告: ${effectiveLocale} 尚未完全加载，使用备用配置${Font}"
        export LANG=C.UTF-8
        export LC_ALL=C.UTF-8
        export LANGUAGE=
    fi
    
    # 验证locale配置结果（检查配置文件和系统locale列表）
    local configFileOK=false
    local localeInSystem=false
    
    # 检查配置文件是否正确写入
    if [[ -f /etc/default/locale ]] && grep -q "LANG=${effectiveLocale}" /etc/default/locale 2>/dev/null; then
        configFileOK=true
    elif [[ -f /etc/locale.conf ]] && grep -q "LANG=${effectiveLocale}" /etc/locale.conf 2>/dev/null; then
        configFileOK=true
    fi
    
    # 检查locale是否在系统中可用
    if locale -a 2>/dev/null | grep -qi "C.utf8\|C.UTF-8\|en_US.utf8\|en_US.UTF-8"; then
        localeInSystem=true
    fi
    
    if [[ "${configFileOK}" == "true" ]]; then
        echo -e "${Green} ---> locale配置文件已成功写入${Font}"
        
        if [[ "${localeInSystem}" == "true" ]]; then
            echo -e "${Green} ---> locale已在系统中完全生效${Font}"
            # locale已完全可用，直接设置环境变量
            export LANG=${effectiveLocale}
            export LC_ALL=${effectiveLocale}
            export LANGUAGE=
        else
            echo -e "${Yellow} ---> locale配置已保存，将在下次登录时生效${Font}"
            echo -e "${Yellow} ---> 当前会话将使用备用配置继续运行${Font}"
            # 使用安全的备用配置
            export LANG=C.UTF-8
            export LC_ALL=C.UTF-8
            export LANGUAGE=
        fi
    else
        echo -e "${Yellow} ---> locale配置未完成，可能需要手动配置${Font}"
    fi
}

# 检查必要的系统组件（针对精简版系统）
check_essential_packages() {
    echo -e "${Blue}正在检查必要系统组件...${Font}"
    
    local essentialPackages=()
    
    # Debian/Ubuntu精简版常缺失的包
    if [[ "${release}" == "debian" ]] || [[ "${release}" == "ubuntu" ]]; then
        # 检查debconf-utils（用于debconf-set-selections）
        if ! dpkg -l 2>/dev/null | grep -q "^ii.*debconf-utils"; then
            essentialPackages+=("debconf-utils")
        fi
        
        # 检查apt-utils
        if ! dpkg -l 2>/dev/null | grep -q "^ii.*apt-utils"; then
            essentialPackages+=("apt-utils")
        fi
        
        # 检查ca-certificates（SSL证书）
        if ! dpkg -l 2>/dev/null | grep -q "^ii.*ca-certificates"; then
            essentialPackages+=("ca-certificates")
        fi
        
        # 检查gnupg（密钥管理）
        if ! dpkg -l 2>/dev/null | grep -q "^ii.*gnupg"; then
            essentialPackages+=("gnupg")
        fi
        
        # 检查locales包
        if ! dpkg -l 2>/dev/null | grep -q "^ii.*locales"; then
            essentialPackages+=("locales")
        fi
    fi
    
    # 如果有缺失的包，批量安装
    if [[ ${#essentialPackages[@]} -gt 0 ]]; then
        echo -e "${Yellow}检测到精简系统，安装必要组件: ${essentialPackages[*]}${Font}"
        for package in "${essentialPackages[@]}"; do
            echo -e "${Green} ---> 安装 ${package}${Font}"
            ${installType} "${package}" >/dev/null 2>&1
        done
    else
        echo -e "${Green}必要系统组件检查完成${Font}"
    fi
}

# 安装基础工具包
install_basic_tools() {
    echo -e "${Blue}正在安装基础工具包...${Font}"
    
    # 首先检查并配置locale（必须在其他操作之前）
    check_and_configure_locale
    
    # 检查精简系统必要组件
    check_essential_packages
    
    # 修复ubuntu个别系统问题
    if [[ "${release}" == "ubuntu" ]]; then
        dpkg --configure -a >/dev/null 2>&1
    fi
    
    # 杀死可能阻塞的包管理进程
    if [[ -n $(pgrep -f "apt") ]]; then
        pgrep -f apt | xargs kill -9 >/dev/null 2>&1
    fi
    
    echo -e "${Green} ---> 更新软件包列表${Font}"
    ${upgrade} >/dev/null 2>&1
    
    if [[ "${release}" == "centos" ]]; then
        rm -rf /var/run/yum.pid >/dev/null 2>&1
        ${installType} epel-release >/dev/null 2>&1
    fi
    
    # 检查并安装基础工具
    local tools=("wget" "curl" "unzip" "tar" "jq")
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo -e "${Green} ---> 安装 $tool${Font}"
            ${installType} "$tool" >/dev/null 2>&1
        fi
    done
    
    # 安装系统特定的工具
    if [[ "${release}" == "centos" ]]; then
        if ! command -v dig >/dev/null 2>&1; then
            echo -e "${Green} ---> 安装 bind-utils (dig)${Font}"
            ${installType} bind-utils >/dev/null 2>&1
        fi
    elif [[ "${release}" == "ubuntu" ]] || [[ "${release}" == "debian" ]]; then
        if ! command -v dig >/dev/null 2>&1; then
            echo -e "${Green} ---> 安装 dnsutils (dig)${Font}"
            ${installType} dnsutils >/dev/null 2>&1
        fi
        
        if ! command -v cron >/dev/null 2>&1; then
            echo -e "${Green} ---> 安装 cron${Font}"
            ${installType} cron >/dev/null 2>&1
        fi
    elif [[ "${release}" == "alpine" ]]; then
        if ! command -v dig >/dev/null 2>&1; then
            echo -e "${Green} ---> 安装 bind-tools (dig)${Font}"
            ${installType} bind-tools >/dev/null 2>&1
        fi
    fi
    
    echo -e "${Green}基础工具包安装完成${Font}"
}

# 检查网络连接
check_network_connectivity() {
    echo -e "${Blue}正在检查网络连接...${Font}"
    
    # 检查IPv4连接
    if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        echo -e "${Green}IPv4 网络连接正常${Font}"
    else
        echo -e "${Yellow}IPv4 网络连接异常${Font}"
    fi
    
    # 检查域名解析
    if ping -c 1 -W 3 github.com >/dev/null 2>&1; then
        echo -e "${Green}域名解析正常${Font}"
    else
        echo -e "${Yellow}域名解析可能存在问题${Font}"
    fi
    
    # 检查GitHub连接性
    if curl -s --connect-timeout 10 https://api.github.com >/dev/null 2>&1; then
        echo -e "${Green}GitHub 连接正常${Font}"
    else
        echo -e "${Yellow}GitHub 连接可能存在问题，建议检查网络环境${Font}"
    fi
}

# 检查SELinux状态（CentOS/RHEL）
check_selinux() {
    if [[ "${release}" == "centos" ]] && [[ -f "/etc/selinux/config" ]]; then
        if ! grep -q "SELINUX=disabled" "/etc/selinux/config"; then
            echo -e "${Yellow}检测到SELinux已启用${Font}"
            echo -e "${Yellow}建议关闭SELinux以避免潜在问题${Font}"
            echo -e "${Blue}您可以编辑 /etc/selinux/config 文件，将 SELINUX=enforcing 改为 SELINUX=disabled${Font}"
        fi
    fi
}

# 获取内存大小（MB）
get_memory_size() {
    local mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local mem_mb=$((mem_kb / 1024))
    echo $mem_mb
}

get_disk_available_mb() {
    local available_kb
    available_kb=$(df -k / | tail -1 | awk '{print $4}')
    echo $((available_kb / 1024))
}

ensure_zram_swap_dependencies() {
    if [[ "${release}" != "debian" && "${release}" != "ubuntu" ]]; then
        return 0
    fi

    local packages=()

    if ! command -v modprobe >/dev/null 2>&1; then
        packages+=("kmod")
    fi
    if ! command -v mkswap >/dev/null 2>&1 || ! command -v swapon >/dev/null 2>&1; then
        packages+=("util-linux")
    fi

    if [[ ${#packages[@]} -gt 0 ]]; then
        echo -e "${Yellow}检测到缺失依赖，正在安装: ${packages[*]}${Font}"
        ${installType} "${packages[@]}" >/dev/null 2>&1
    fi
}

systemd_available() {
    [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1
}

set_sysctl_value() {
    local key="$1"
    local value="$2"
    if grep -q "^${key}=" /etc/sysctl.conf 2>/dev/null; then
        sed -i "s/^${key}=.*/${key}=${value}/" /etc/sysctl.conf
    else
        echo "${key}=${value}" >> /etc/sysctl.conf
    fi
    sysctl "${key}=${value}" >/dev/null 2>&1
}

is_zram_active() {
    if [[ -f /proc/swaps ]]; then
        grep -q "/dev/zram0" /proc/swaps
        return $?
    fi
    return 1
}

is_disk_swap_active() {
    if command -v swapon >/dev/null 2>&1; then
        swapon --show --noheadings 2>/dev/null | awk '{print $1}' | grep -qv "/dev/zram0"
        return $?
    fi
    return 1
}

apply_memory_tuning() {
    local swappiness="$1"
    local vfs_cache_pressure="$2"

    set_sysctl_value "vm.swappiness" "${swappiness}"
    set_sysctl_value "vm.vfs_cache_pressure" "${vfs_cache_pressure}"
}

write_zram_runtime_files() {
    local zram_mb="$1"
    local zram_algo="$2"
    local zram_priority="$3"

    mkdir -p /etc/one-script
    cat >"${ZRAM_ENV_FILE}" <<EOF
ZRAM_SIZE_MB=${zram_mb}
ZRAM_ALGO=${zram_algo}
ZRAM_PRIORITY=${zram_priority}
EOF

    cat >"${ZRAM_SCRIPT_PATH}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ZRAM_ENV="/etc/one-script/zram.env"
if [[ -f "${ZRAM_ENV}" ]]; then
    # shellcheck disable=SC1090
    source "${ZRAM_ENV}"
fi

ZRAM_SIZE_MB="${ZRAM_SIZE_MB:-512}"
ZRAM_ALGO="${ZRAM_ALGO:-lz4}"
ZRAM_PRIORITY="${ZRAM_PRIORITY:-100}"

start_zram() {
    modprobe zram num_devices=1

    swapoff /dev/zram0 2>/dev/null || true

    if [[ -e /sys/block/zram0/reset ]]; then
        echo 1 > /sys/block/zram0/reset || true
    fi

    if [[ -n "${ZRAM_ALGO}" && -w /sys/block/zram0/comp_algorithm ]]; then
        echo "${ZRAM_ALGO}" > /sys/block/zram0/comp_algorithm || true
    fi

    echo "$((ZRAM_SIZE_MB * 1024 * 1024))" > /sys/block/zram0/disksize

    mkswap /dev/zram0 >/dev/null
    swapon -p "${ZRAM_PRIORITY}" /dev/zram0
}

stop_zram() {
    swapoff /dev/zram0 2>/dev/null || true
    if [[ -e /sys/block/zram0/reset ]]; then
        echo 1 > /sys/block/zram0/reset || true
    fi
}

case "${1:-start}" in
    start)
        start_zram
        ;;
    stop)
        stop_zram
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac
EOF

    chmod +x "${ZRAM_SCRIPT_PATH}"
}

enable_zram_service() {
    cat >"${ZRAM_SERVICE_FILE}" <<EOF
[Unit]
Description=One-Script ZRAM Swap
DefaultDependencies=no
After=local-fs.target
Before=swap.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${ZRAM_SCRIPT_PATH} start
ExecStop=${ZRAM_SCRIPT_PATH} stop

[Install]
WantedBy=swap.target
EOF

    if systemd_available; then
        systemctl daemon-reload
        systemctl enable --now "$(basename "${ZRAM_SERVICE_FILE}")" >/dev/null 2>&1
    fi
}

configure_zram_swap() {
    local zram_mb="$1"
    local zram_algo="${2:-lz4}"
    local zram_priority="${3:-100}"

    ensure_zram_swap_dependencies

    if systemd_available; then
        if systemctl list-unit-files 2>/dev/null | grep -q "^zramswap.service"; then
            systemctl disable --now zramswap.service >/dev/null 2>&1 || true
            echo -e "${Yellow}检测到 zramswap 服务，已禁用以避免冲突${Font}"
        fi
        systemctl stop "$(basename "${ZRAM_SERVICE_FILE}")" >/dev/null 2>&1 || true
    else
        swapoff /dev/zram0 2>/dev/null || true
    fi

    write_zram_runtime_files "${zram_mb}" "${zram_algo}" "${zram_priority}"
    enable_zram_service
    apply_memory_tuning "100" "50"

    if systemd_available; then
        if systemctl is-active --quiet "$(basename "${ZRAM_SERVICE_FILE}")"; then
            echo -e "${Green}ZRAM 已启用并设置开机自启${Font}"
        else
            echo -e "${Red}ZRAM 服务启动失败，请检查 systemd 日志${Font}"
        fi
    else
        "${ZRAM_SCRIPT_PATH}" start
        echo -e "${Yellow}未检测到 systemd，ZRAM 仅在当前会话生效${Font}"
    fi
}

recommend_hybrid_sizes() {
    local memory_mb="$1"
    local zram_mb=$((memory_mb / 2))

    if [[ $zram_mb -lt 256 ]]; then
        zram_mb=256
    elif [[ $zram_mb -gt 1024 ]]; then
        zram_mb=1024
    fi

    local swap_mb
    if [[ $memory_mb -le 512 ]]; then
        swap_mb=1024
    elif [[ $memory_mb -le 1024 ]]; then
        swap_mb=2048
    elif [[ $memory_mb -le 2048 ]]; then
        swap_mb=2048
    else
        swap_mb=1024
    fi

    echo "${zram_mb} ${swap_mb}"
}

prompt_custom_hybrid_sizes() {
    local memory_mb="$1"
    local max_swap_mb="$2"
    local max_zram_mb=$((memory_mb * 2))
    local zram_mb
    local swap_mb

    while true; do
        echo -e "${Green}请输入 zram 大小（单位：MB，输入 0 表示跳过）：${Font}"
        echo -e "${Yellow}建议范围：256MB - ${memory_mb}MB（最高可到 ${max_zram_mb}MB）${Font}"
        read -p "zram 大小: " zram_mb
        if [[ $zram_mb =~ ^[0-9]+$ ]]; then
            if [[ $zram_mb -eq 0 ]]; then
                break
            elif [[ $zram_mb -lt 128 ]]; then
                echo -e "${Red}zram 太小，建议至少 128MB${Font}"
            elif [[ $zram_mb -gt $max_zram_mb ]]; then
                echo -e "${Red}zram 过大，最大允许 ${max_zram_mb}MB${Font}"
            else
                break
            fi
        else
            echo -e "${Red}请输入有效数字${Font}"
        fi
    done

    if [[ $max_swap_mb -lt 128 ]]; then
        echo -e "${Yellow}磁盘空间不足，跳过 swap 文件创建${Font}"
        swap_mb=0
    else
        while true; do
            echo -e "${Green}请输入 swap 大小（单位：MB，输入 0 表示跳过）：${Font}"
            echo -e "${Yellow}可用范围：128MB - ${max_swap_mb}MB${Font}"
            read -p "swap 大小: " swap_mb
            if [[ $swap_mb =~ ^[0-9]+$ ]]; then
                if [[ $swap_mb -eq 0 ]]; then
                    break
                elif [[ $swap_mb -lt 128 ]]; then
                    echo -e "${Red}swap 太小，建议至少 128MB${Font}"
                elif [[ $swap_mb -gt $max_swap_mb ]]; then
                    echo -e "${Red}swap 超过可用磁盘空间限制，最大 ${max_swap_mb}MB${Font}"
                else
                    break
                fi
            else
                echo -e "${Red}请输入有效数字${Font}"
            fi
        done
    fi

    echo "${zram_mb} ${swap_mb}"
}

prompt_hybrid_memory_setup() {
    local mode="${1:-}"
    if [[ "${release}" != "debian" && "${release}" != "ubuntu" ]]; then
        echo -e "${Yellow}当前系统非 Debian/Ubuntu，跳过混合内存方案配置${Font}"
        return 0
    fi

    echo
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}混合虚拟内存方案（ZRAM + Swap）${Font}"
    echo -e "${Blue}============================================${Font}"
    echo -e "${Yellow}适合小内存 VPS：优先使用内存压缩 (zram)，再使用磁盘 swap${Font}"
    echo

    if [[ "${mode}" != "force" ]] && is_zram_active && is_disk_swap_active; then
        show_zram_swap_status
        echo -e "${Green}已检测到 ZRAM 与 Swap 均已配置，继续后续初始化...${Font}"
        return 0
    fi

    if [[ "${mode}" != "force" ]]; then
        read -r -p "是否配置混合方案？[Y/n]: " enable_choice
        enable_choice=${enable_choice:-Y}
        if [[ ! $enable_choice =~ ^[Yy]$ ]]; then
            echo -e "${Yellow}已跳过混合方案配置${Font}"
            return 0
        fi
    fi

    local memory_mb
    memory_mb=$(get_memory_size)
    local available_space_mb
    available_space_mb=$(get_disk_available_mb)
    local max_swap_mb=$((available_space_mb - 1024))
    if [[ $max_swap_mb -lt 0 ]]; then
        max_swap_mb=0
    fi

    echo -e "${Green}当前系统内存：${memory_mb}MB${Font}"
    echo -e "${Green}根分区可用空间：${available_space_mb}MB${Font}"

    local rec_zram rec_swap
    read -r rec_zram rec_swap < <(recommend_hybrid_sizes "${memory_mb}")

    if [[ $max_swap_mb -lt 128 ]]; then
        rec_swap=0
        echo -e "${Yellow}磁盘空间不足，将仅配置 zram${Font}"
    elif [[ $rec_swap -gt $max_swap_mb ]]; then
        rec_swap=$max_swap_mb
        echo -e "${Yellow}根据磁盘空间调整推荐 swap 大小为：${rec_swap}MB${Font}"
    fi

    local existing_swap=""
    if command -v swapon >/dev/null 2>&1; then
        existing_swap=$(swapon --show --noheadings 2>/dev/null | awk '{print $1}')
    fi
    if [[ -n "${existing_swap}" ]]; then
        echo -e "${Yellow}检测到已有 swap：${Font}"
        echo -e "${Yellow}${existing_swap}${Font}"
    fi

    echo
    echo -e "${Green}推荐方案：zram ${rec_zram}MB + swap ${rec_swap}MB${Font}"
    echo -e "${Yellow}1.${Font} 使用推荐方案"
    echo -e "${Yellow}2.${Font} 自定义大小"
    echo -e "${Yellow}3.${Font} 跳过配置"

    local choice
    while true; do
        read -p "请选择 [1-3]: " choice
        case $choice in
            1)
                if [[ -n "${existing_swap}" && $rec_swap -gt 0 ]]; then
                    read -r -p "检测到已有 swap，是否仍创建/替换 /swapfile？[y/N]: " replace_choice
                    replace_choice=${replace_choice:-N}
                    if [[ ! $replace_choice =~ ^[Yy]$ ]]; then
                        rec_swap=0
                    fi
                fi

                if [[ $rec_zram -gt 0 ]]; then
                    configure_zram_swap "${rec_zram}" "lz4" "100"
                fi

                if [[ $rec_swap -gt 0 ]]; then
                    ensure_zram_swap_dependencies
                    create_swap_file "${rec_swap}"
                else
                    echo -e "${Yellow}未创建新的 swap 文件${Font}"
                fi
                break
                ;;
            2)
                local custom_zram custom_swap
                read -r custom_zram custom_swap < <(prompt_custom_hybrid_sizes "${memory_mb}" "${max_swap_mb}")

                if [[ $custom_zram -gt 0 ]]; then
                    configure_zram_swap "${custom_zram}" "lz4" "100"
                else
                    echo -e "${Yellow}跳过 zram 配置${Font}"
                fi

                if [[ $custom_swap -gt 0 ]]; then
                    ensure_zram_swap_dependencies
                    create_swap_file "${custom_swap}"
                else
                    echo -e "${Yellow}未创建新的 swap 文件${Font}"
                fi
                break
                ;;
            3)
                echo -e "${Yellow}已跳过混合方案配置${Font}"
                return 0
                ;;
            *)
                echo -e "${Red}无效选择，请输入 1-3${Font}"
                ;;
        esac
    done
}

show_zram_swap_status() {
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}ZRAM / Swap 状态${Font}"
    echo -e "${Blue}============================================${Font}"
    echo

    if command -v swapon >/dev/null 2>&1; then
        echo -e "${Green}当前 Swap 设备：${Font}"
        swapon --show 2>/dev/null || echo "无"
    else
        echo -e "${Yellow}系统未提供 swapon 命令${Font}"
    fi
    echo

    if [[ -d /sys/block/zram0 ]]; then
        local zram_size_bytes
        local zram_size_mb
        zram_size_bytes=$(cat /sys/block/zram0/disksize 2>/dev/null || echo 0)
        zram_size_mb=$((zram_size_bytes / 1024 / 1024))
        local algo
        algo=$(cat /sys/block/zram0/comp_algorithm 2>/dev/null || echo "未知")

        echo -e "${Green}ZRAM 设备：/dev/zram0${Font}"
        echo -e "${Yellow}  容量：${zram_size_mb}MB${Font}"
        echo -e "${Yellow}  压缩算法：${algo}${Font}"

        if [[ -f /sys/block/zram0/orig_data_size ]]; then
            local orig_size
            local compr_size
            orig_size=$(cat /sys/block/zram0/orig_data_size 2>/dev/null || echo 0)
            compr_size=$(cat /sys/block/zram0/compr_data_size 2>/dev/null || echo 0)
            echo -e "${Yellow}  原始数据：$((orig_size / 1024 / 1024))MB${Font}"
            echo -e "${Yellow}  压缩数据：$((compr_size / 1024 / 1024))MB${Font}"
        fi
    else
        echo -e "${Yellow}未检测到 zram 设备${Font}"
    fi
    echo

    if [[ -f "${ZRAM_ENV_FILE}" ]]; then
        echo -e "${Green}当前配置文件：${Font}${ZRAM_ENV_FILE}"
        cat "${ZRAM_ENV_FILE}"
        echo
    else
        echo -e "${Yellow}未发现 ZRAM 配置文件${Font}"
        echo
    fi

    if systemd_available; then
        if [[ -f "${ZRAM_SERVICE_FILE}" ]]; then
            echo -e "${Green}服务状态：${Font}"
            systemctl is-enabled "$(basename "${ZRAM_SERVICE_FILE}")" >/dev/null 2>&1 && \
                echo -e "${Yellow}  开机自启：已启用${Font}" || \
                echo -e "${Yellow}  开机自启：未启用${Font}"
            systemctl is-active "$(basename "${ZRAM_SERVICE_FILE}")" >/dev/null 2>&1 && \
                echo -e "${Yellow}  运行状态：运行中${Font}" || \
                echo -e "${Yellow}  运行状态：未运行${Font}"
        else
            echo -e "${Yellow}未发现 ZRAM systemd 服务文件${Font}"
        fi
    else
        echo -e "${Yellow}系统未启用 systemd，ZRAM 可能仅当前会话生效${Font}"
    fi

    echo -e "${Blue}============================================${Font}"
}

prompt_zram_config() {
    local memory_mb
    memory_mb=$(get_memory_size)
    local max_zram_mb=$((memory_mb * 2))
    local zram_mb
    local zram_algo
    local zram_priority

    while true; do
        echo -e "${Green}请输入 zram 大小（单位：MB）：${Font}"
        echo -e "${Yellow}建议范围：256MB - ${memory_mb}MB（最高可到 ${max_zram_mb}MB）${Font}"
        read -p "zram 大小: " zram_mb
        if [[ $zram_mb =~ ^[0-9]+$ ]]; then
            if [[ $zram_mb -lt 128 ]]; then
                echo -e "${Red}zram 太小，建议至少 128MB${Font}"
            elif [[ $zram_mb -gt $max_zram_mb ]]; then
                echo -e "${Red}zram 过大，最大允许 ${max_zram_mb}MB${Font}"
            else
                break
            fi
        else
            echo -e "${Red}请输入有效数字${Font}"
        fi
    done

    read -r -p "压缩算法 (默认 lz4): " zram_algo
    zram_algo=${zram_algo:-lz4}

    read -r -p "zram 优先级 (1-32767, 默认 100): " zram_priority
    zram_priority=${zram_priority:-100}
    if [[ ! $zram_priority =~ ^[0-9]+$ ]] || [[ $zram_priority -lt 1 ]] || [[ $zram_priority -gt 32767 ]]; then
        zram_priority=100
    fi

    echo "${zram_mb} ${zram_algo} ${zram_priority}"
}

disable_zram_swap() {
    if systemd_available && [[ -f "${ZRAM_SERVICE_FILE}" ]]; then
        systemctl disable --now "$(basename "${ZRAM_SERVICE_FILE}")" >/dev/null 2>&1 || true
    fi
    swapoff /dev/zram0 2>/dev/null || true
    echo -e "${Green}已停止 ZRAM（配置保留，可随时重新启用）${Font}"
}

hybrid_memory_management() {
    local mode="${1:-menu}"
    if [[ "${release}" != "debian" && "${release}" != "ubuntu" ]]; then
        echo -e "${Yellow}当前系统非 Debian/Ubuntu，无法使用混合内存管理${Font}"
        read -p "按回车键返回..."
        if [[ "${mode}" == "menu" ]]; then
            system_tools_menu
        fi
        return
    fi

    while true; do
        clear
        show_zram_swap_status
        echo
        echo -e "${Green}混合内存管理选项：${Font}"
        echo -e "${Yellow}1.${Font} 重新运行混合方案向导"
        echo -e "${Yellow}2.${Font} 调整 ZRAM 大小/算法"
        echo -e "${Yellow}3.${Font} 停用 ZRAM"
        if [[ "${mode}" == "menu" ]]; then
            echo -e "${Yellow}4.${Font} 返回系统工具"
        else
            echo -e "${Yellow}4.${Font} 退出"
        fi

        local choice
        read -p "请选择操作 [1-4]: " choice
        case $choice in
            1)
                prompt_hybrid_memory_setup "force"
                ;;
            2)
                local zram_mb zram_algo zram_priority
                read -r zram_mb zram_algo zram_priority < <(prompt_zram_config)
                configure_zram_swap "${zram_mb}" "${zram_algo}" "${zram_priority}"
                ;;
            3)
                disable_zram_swap
                ;;
            4)
                if [[ "${mode}" == "menu" ]]; then
                    system_tools_menu
                fi
                return
                ;;
            *)
                echo -e "${Red}无效选择，请输入 1-4${Font}"
                ;;
        esac

        echo
        read -p "按回车键继续..."
    done
}

# 自动创建swap（优化版）
auto_create_swap() {
    echo -e "${Blue}正在检查系统内存和swap状态...${Font}"
    
    local memory_mb=$(get_memory_size)
    echo -e "${Green}当前系统内存：${memory_mb}MB${Font}"
    
    # 检查是否已存在swap文件
    if [[ -f "/swapfile" ]] || grep -q "swapfile" /etc/fstab 2>/dev/null; then
        echo -e "${Yellow}检测到已存在swap文件，跳过创建。${Font}"
        
        # 显示当前swap状态
        if [[ -f "/proc/swaps" ]]; then
            echo -e "${Green}当前swap状态：${Font}"
            cat /proc/swaps
        fi
        return 0
    fi
    
    # 检查是否有其他swap分区
    local existing_swap=$(swapon --show 2>/dev/null | wc -l)
    if [[ $existing_swap -gt 1 ]]; then
        echo -e "${Yellow}检测到已有其他swap分区，跳过创建swap文件${Font}"
        swapon --show 2>/dev/null
        return 0
    fi
    
    # 检查磁盘可用空间
    local available_space_kb=$(df / | tail -1 | awk '{print $4}')
    local available_space_mb=$((available_space_kb / 1024))
    echo -e "${Green}根分区可用空间：${available_space_mb}MB${Font}"
    
    # 根据内存大小决定推荐的swap大小
    local recommended_swap_size
    local max_swap_size=$((available_space_mb - 1024))  # 保留1GB空间
    
    if [[ $memory_mb -lt 512 ]]; then
        recommended_swap_size=1024  # 1GB
        echo -e "${Yellow}建议：内存小于512MB，推荐创建1GB的swap${Font}"
    elif [[ $memory_mb -lt 1024 ]]; then
        recommended_swap_size=2048  # 2GB
        echo -e "${Yellow}建议：内存小于1GB，推荐创建2GB的swap${Font}"
    elif [[ $memory_mb -lt 2048 ]]; then
        recommended_swap_size=2048  # 2GB
        echo -e "${Yellow}建议：内存小于2GB，推荐创建2GB的swap${Font}"
    else
        recommended_swap_size=1024  # 1GB
        echo -e "${Yellow}建议：内存充足，推荐创建1GB的swap${Font}"
    fi
    
    # 检查推荐大小是否超过可用空间
    if [[ $recommended_swap_size -gt $max_swap_size ]]; then
        if [[ $max_swap_size -gt 512 ]]; then
            recommended_swap_size=$max_swap_size
            echo -e "${Yellow}根据可用磁盘空间调整swap大小为：${recommended_swap_size}MB${Font}"
        else
            echo -e "${Red}磁盘空间不足，无法创建swap文件${Font}"
            return 1
        fi
    fi
    
    echo
    echo -e "${Green}Swap创建选项：${Font}"
    echo -e "${Yellow}1.${Font} 自动创建推荐大小的swap (${recommended_swap_size}MB)"
    echo -e "${Yellow}2.${Font} 手动指定swap大小"
    echo -e "${Yellow}3.${Font} 跳过swap创建"
    echo
    
    local choice
    while true; do
        read -p "请选择 [1-3]: " choice
        case $choice in
            1)
                # 自动创建推荐大小
                create_swap_file $recommended_swap_size
                break
                ;;
            2)
                # 手动指定大小
                manual_create_swap $max_swap_size
                break
                ;;
            3)
                echo -e "${Yellow}跳过swap创建。${Font}"
                return 0
                ;;
            *)
                echo -e "${Red}无效选择，请输入 1-3${Font}"
                ;;
        esac
    done
}

# 手动创建swap（优化版）
manual_create_swap() {
    local max_swap_size=${1:-10240}  # 默认最大10GB
    local swap_size
    
    while true; do
        echo -e "${Green}请输入需要创建的swap大小（单位：MB）：${Font}"
        echo -e "${Yellow}建议范围：512MB - ${max_swap_size}MB${Font}"
        echo -e "${Yellow}推荐：内存的1-2倍，但不超过可用磁盘空间${Font}"
        read -p "请输入swap大小: " swap_size
        
        # 验证输入是否为数字
        if [[ $swap_size =~ ^[0-9]+$ ]] && [[ $swap_size -gt 0 ]]; then
            # 检查是否超过最大允许大小
            if [[ $swap_size -gt $max_swap_size ]]; then
                echo -e "${Red}输入的大小超过可用磁盘空间，最大允许：${max_swap_size}MB${Font}"
                continue
            fi
            
            # 检查是否太小
            if [[ $swap_size -lt 128 ]]; then
                echo -e "${Red}swap大小太小，建议至少128MB${Font}"
                continue
            fi
            
            echo -e "${Green}将创建${swap_size}MB的swap文件${Font}"
            read -p "确认创建吗？[y/N]: " confirm
            if [[ $confirm =~ ^[Yy]$ ]]; then
                create_swap_file $swap_size
                break
            fi
        else
            echo -e "${Red}请输入有效的数字（大于0）${Font}"
        fi
    done
}

# 创建swap文件的通用函数（优化版）
create_swap_file() {
    local swap_size=$1
    echo -e "${Green}正在创建${swap_size}MB的swap文件...${Font}"
    
    # 检查是否有足够的磁盘空间
    local available_space_kb=$(df / | tail -1 | awk '{print $4}')
    local available_space_mb=$((available_space_kb / 1024))
    local required_space_mb=$((swap_size + 200))  # 额外200MB缓冲
    
    if [[ $available_space_mb -lt $required_space_mb ]]; then
        echo -e "${Red}磁盘空间不足！需要${required_space_mb}MB，可用${available_space_mb}MB${Font}"
        return 1
    fi
    
    # 删除可能存在的旧swap文件
    if [[ -f "/swapfile" ]]; then
        echo -e "${Yellow}检测到已存在的swap文件，正在删除...${Font}"
        swapoff /swapfile 2>/dev/null
        rm -f /swapfile
    fi
    
    # 创建swap文件
    echo -e "${Blue}正在创建swap文件...${Font}"
    if dd if=/dev/zero of=/swapfile bs=1M count=${swap_size} status=progress 2>/dev/null; then
        # 设置正确的权限
        chmod 600 /swapfile
        
        # 设置为swap文件
        echo -e "${Blue}正在格式化swap文件...${Font}"
        if mkswap /swapfile >/dev/null 2>&1; then
            # 启用swap
            echo -e "${Blue}正在启用swap...${Font}"
            if swapon /swapfile; then
                # 添加到fstab实现开机自动挂载
                if ! grep -q "/swapfile" /etc/fstab; then
                    echo '/swapfile none swap defaults 0 0' >> /etc/fstab
                fi
                
                # 优化swap使用策略
                echo -e "${Blue}正在优化swap参数...${Font}"

                local swappiness=10
                local vfs_cache_pressure=50
                if is_zram_active; then
                    swappiness=100
                    vfs_cache_pressure=50
                fi

                apply_memory_tuning "${swappiness}" "${vfs_cache_pressure}"
                
                echo -e "${Green}Swap创建成功！${Font}"
                echo -e "${Green}Swap信息：${Font}"
                cat /proc/swaps
                echo
                echo -e "${Green}系统内存信息：${Font}"
                free -h
                echo
                echo -e "${Blue}Swap优化参数：${Font}"
                echo -e "${Green}  swappiness: ${swappiness} (控制swap使用积极性，数值越小越不容易使用swap)${Font}"
                echo -e "${Green}  vfs_cache_pressure: ${vfs_cache_pressure} (控制内核回收用于目录和inode cache内存的倾向)${Font}"
                
            else
                echo -e "${Red}启用swap失败！${Font}"
                rm -f /swapfile
                return 1
            fi
        else
            echo -e "${Red}格式化swap文件失败！${Font}"
            rm -f /swapfile
            return 1
        fi
    else
        echo -e "${Red}创建swap文件失败！可能是磁盘空间不足或权限问题${Font}"
        return 1
    fi
}

# 显示脚本选择菜单
show_script_menu() {
    if [[ "${SKIP_CLEAR_ONCE}" == "true" ]]; then
        SKIP_CLEAR_ONCE="false"
    else
        clear
    fi
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}      One-Script 脚本管理工具${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    lang_echo "${Green}系统信息：${Font}"
    if command -v uname >/dev/null 2>&1; then
        lang_echo "${Yellow}  操作系统：$(uname -o) $(uname -m)${Font}"
        lang_echo "${Yellow}  内核版本：$(uname -r)${Font}"
    fi
    if [[ -f "/etc/os-release" ]]; then
        source /etc/os-release
        lang_echo "${Yellow}  发行版本：${NAME} ${VERSION}${Font}"
    fi
    lang_echo "${Yellow}  当前用户：$(whoami)${Font}"
    lang_echo "${Yellow}  系统时间：$(date '+%Y-%m-%d %H:%M:%S')${Font}"
    echo
    lang_echo "${Green}请选择要运行的脚本：${Font}"
    echo
    lang_echo "${Green}【代理工具】${Font}"
    lang_echo "${Yellow}1.${Font} V2Ray 安装脚本 ${Blue}${Font}"
    lang_echo "${Yellow}2.${Font} V2Ray 原版安装脚本 ${Blue}${Font}"
    lang_echo "${Yellow}3.${Font} 无交互版本 ${Blue}(quick-script)${Font}"
    echo
    lang_echo "${Green}【系统管理】${Font}"
    lang_echo "${Yellow}4.${Font} 混合内存管理 ${Blue}(ZRAM/Swap)${Font}"
    lang_echo "${Yellow}5.${Font} 系统工具 ${Blue}(系统优化和诊断)${Font}"
    lang_echo "${Yellow}6.${Font} 内核安装脚本 (BBR/BBR Plus)"
    echo
    lang_echo "${Green}【网络配置】${Font}"
    lang_echo "${Yellow}7.${Font} 快速切换节点IPv4/IPv6优先级"
    echo
    lang_echo "${Green}【工具查询】${Font}"
    lang_echo "${Yellow}8.${Font} 查询核心配置路径"
    echo
    lang_echo "${Green}【脚本维护】${Font}"
    lang_echo "${Yellow}9.${Font} 命令管理 ${Blue}(安装/卸载${REMOTE_COMMAND_NAME}快捷命令)${Font}"
    lang_echo "${Yellow}10.${Font} 更新 main.sh 脚本 ${Blue}(检查脚本更新)${Font}"
    lang_echo "${Yellow}11.${Font} 退出"
    echo
    echo -e "${Blue}============================================${Font}"
}

# 执行选择的脚本
execute_script() {
    local choice=$1

    case $choice in
        1)
            lang_echo "${Green}正在启动 V2Ray 安装脚本...${Font}"
            lang_echo "${Yellow}正在从远程仓库获取...${Font}"
            
            # 先尝试下载脚本到临时文件
            local temp_script="${TEMP_DIR}/v2ray_temp.sh"
            local download_success=false
            
            # 使用本仓库的修改版install.sh
            local v2ray_url="${BASE_URL}/install.sh"
            
            if download_file "$v2ray_url" "$temp_script"; then
                download_success=true
                lang_echo "${Green}脚本下载成功${Font}"
            fi
            
            if [[ "$download_success" == "true" && -s "$temp_script" ]]; then
                lang_echo "${Green}开始执行 V2Ray 安装脚本...${Font}"
                # 执行脚本，不管退出状态码
                bash "$temp_script"
                lang_echo "${Green}V2Ray 脚本执行完成${Font}"
                rm -f "$temp_script"
                # 添加定时重启任务
                add_crontab_reboot
            else
                lang_echo "${Red}错误：无法从远程仓库获取 V2Ray 安装脚本！${Font}"
                lang_echo "${Yellow}请检查网络连接或稍后重试${Font}"
                rm -f "$temp_script"
            fi
            ;;
        2)
            lang_echo "${Green}正在启动 V2Ray 原版安装脚本...${Font}"
            lang_echo "${Yellow}正在从 mack-a 仓库获取原版 install.sh...${Font}"
            
            # 先尝试下载脚本到临时文件
            local temp_script="${TEMP_DIR}/v2ray_original_temp.sh"
            local download_success=false
            
            # 使用mack-a的官方原版脚本
            local v2ray_original_url="${V2RAY_ORIGINAL_URL}"
            
            if download_file "$v2ray_original_url" "$temp_script"; then
                download_success=true
                lang_echo "${Green}脚本下载成功${Font}"
            fi
            
            if [[ "$download_success" == "true" && -s "$temp_script" ]]; then
                lang_echo "${Green}开始执行 V2Ray 原版安装脚本...${Font}"

                # 执行脚本，不管退出状态码
                bash "$temp_script"
                lang_echo "${Green}V2Ray 原版脚本执行完成${Font}"
                rm -f "$temp_script"
            else
                lang_echo "${Red}错误：无法从 mack-a 仓库获取原版安装脚本！${Font}"
                lang_echo "${Yellow}请检查网络连接或稍后重试${Font}"
                rm -f "$temp_script"
            fi
            ;;
        3)
            lang_echo "${Green}是否使用无交互版本？[Y/N]${Font}"
            read -r quick_choice
            if [[ -z "${quick_choice}" ]] || [[ "${quick_choice}" =~ ^[Yy]$ ]]; then
                lang_echo "${Yellow}正在从 quick-script 仓库获取脚本...${Font}"
                if run_remote_script "${QUICK_SCRIPT_URL}"; then
                    lang_echo "${Green}无交互脚本执行完成${Font}"
                else
                    lang_echo "${Red}错误：无法从 quick-script 仓库获取脚本！${Font}"
                    lang_echo "${Yellow}请检查网络连接或稍后重试${Font}"
                fi
            else
                lang_echo "${Yellow}已取消操作${Font}"
            fi
            ;;
        4)
            lang_echo "${Green}正在启动 混合内存管理...${Font}"
            lang_echo "${Yellow}正在从远程仓库获取...${Font}"
            if run_remote_script "${BASE_URL}/swap.sh"; then
                lang_echo "${Green}脚本执行完成${Font}"
            else
                lang_echo "${Red}错误：无法从远程仓库获取 swap.sh 脚本！${Font}"
                lang_echo "${Yellow}请检查网络连接或稍后重试${Font}"
            fi
            ;;
        5)
            lang_echo "${Green}进入系统工具...${Font}"
            system_tools_menu
            ;;
        6)
            lang_echo "${Green}正在启动内核安装脚本...${Font}"
            local script_dir="$(dirname "$(readlink -f "$0")")"
            local local_script="${script_dir}/install_kernel.sh"
            
            if [[ -f "$local_script" ]]; then
                bash "$local_script"
            else
                lang_echo "${Yellow}正在从远程仓库获取...${Font}"
                local temp_script="${TEMP_DIR}/install_kernel.sh"
                local kernel_url="${BASE_URL}/install_kernel.sh"
                
                if download_file "$kernel_url" "$temp_script"; then
                    bash "$temp_script"
                    rm -f "$temp_script"
                else
                    lang_echo "${Red}错误：无法从远程仓库获取 install_kernel.sh 脚本！${Font}"
                    lang_echo "${Yellow}请检查网络连接或稍后重试${Font}"
                fi
            fi
            ;;
        7)
            quick_switch_ip_priority
            ;;
        8)
            show_config_paths
            ;;
        9)
            lang_echo "${Green}进入命令管理...${Font}"
            command_management
            ;;
        10)
            lang_echo "${Green}正在更新 main.sh 脚本...${Font}"
            update_main_script
            ;;
        11)
            lang_echo "${Green}感谢使用，再见！${Font}"
            exit 0
            ;;
        *)
            lang_echo "${Red}无效选择，请输入 1-11${Font}"
            sleep 2
            main_menu
            ;;
    esac
}

# 添加定时重启任务（交互式询问）
add_crontab_reboot() {
    # 检查是否已存在重启任务
    if crontab -l 2>/dev/null | grep -q "0 21 \* \* \* /sbin/reboot"; then
        echo -e "${Yellow}检测到已存在定时重启任务，跳过询问。${Font}"
        return 0
    fi

    # 交互式询问用户是否设置定时重启
    echo -e "${Blue}============================================${Font}"
    echo -e "${Blue}  是否设置系统定时重启任务？${Font}"
    echo -e "${Blue}============================================${Font}"
    echo -e "${Yellow}  将在每天北京时间 05:00（UTC 21:00）自动重启系统${Font}"
    echo -e "${Yellow}  以保持系统性能和释放资源${Font}"
    echo
    echo -e "${Green}  1) 是 - 设置定时重启任务${Font}"
    echo -e "${Green}  2) 否 - 跳过（不推荐用于长期运行）${Font}"
    echo
    read -p "$(lang_text "请输入您的选择 [1-2]: ")" cron_choice

    case "$cron_choice" in
        1)
            setup_crontab_reboot
            ;;
        2|*)
            echo -e "${Yellow}已跳过定时重启任务设置${Font}"
            echo -e "${Yellow}注意：长期运行建议设置定时重启以保持系统性能${Font}"
            echo -e "${Blue}如需稍后设置，可重新运行本脚本${Font}"
            ;;
    esac
}

# 设置定时重启任务（UTC 21:00 = UTC+8 05:00）
setup_crontab_reboot() {
    echo -e "${Blue}正在配置系统定时重启任务...${Font}"

    # 备份当前的crontab
    crontab -l 2>/dev/null > /tmp/current_crontab || touch /tmp/current_crontab

    # 添加新的重启任务（UTC 21:00 = 北京时间 05:00）
    echo "0 21 * * * /sbin/reboot" >> /tmp/current_crontab

    # 应用新的crontab
    if crontab /tmp/current_crontab; then
        echo -e "${Green}定时重启任务添加成功！${Font}"
        echo -e "${Green}系统将在每日北京时间 05:00（UTC 21:00）自动重启${Font}"
        rm -f /tmp/current_crontab
    else
        echo -e "${Red}定时重启任务添加失败！${Font}"
        rm -f /tmp/current_crontab
    fi

    echo -e "${Blue}当前定时任务：${Font}"
    crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" || echo -e "${Yellow}暂无定时任务${Font}"
    echo
}

# 主菜单
main_menu() {
    while true; do
        show_script_menu
        read -p "$(lang_text "请输入您的选择 [1-11]: ")" choice
        execute_script "$choice"
        echo
        if [[ "$choice" != "10" ]]; then
            read -p "$(lang_text "脚本执行完毕，按回车键返回主菜单...")"
        fi
    done
}

# 显示核心配置路径
show_config_paths() {
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}           核心配置文件路径查询${Font}"
    echo -e "${Blue}============================================${Font}"
    echo

    # 1. 检查 Sing-box
    lang_echo "${Green}Sing-box 配置：${Font}"
    local sb_found=false
    
    # 检查 install.sh 安装路径
    if [[ -f "/etc/v2ray-agent/sing-box/conf/config.json" ]]; then
        lang_echo "${Yellow}  主配置文件 (install.sh): /etc/v2ray-agent/sing-box/conf/config.json${Font}"
        sb_found=true
    fi
    if [[ -f "/etc/v2ray-agent/sing-box/conf/config_warp_template.json" ]]; then
        lang_echo "${Yellow}  WARP 模板文件: /etc/v2ray-agent/sing-box/conf/config_warp_template.json${Font}"
        sb_found=true
    fi
    
    # 检查标准安装路径
    if [[ -f "/etc/sing-box/config.json" ]]; then
        lang_echo "${Yellow}  主配置文件 (标准): /etc/sing-box/config.json${Font}"
        sb_found=true
    fi
    
    if [[ "$sb_found" == "false" ]]; then
        lang_echo "${Red}  未检测到 Sing-box 配置文件${Font}"
    fi
    echo

    # 2. 检查 Xray (install.sh)
    lang_echo "${Green}Xray 配置：${Font}"
    if [[ -f "/etc/v2ray-agent/xray/conf/config.json" ]]; then
        lang_echo "${Yellow}  主配置文件: /etc/v2ray-agent/xray/conf/config.json${Font}"
    else
        lang_echo "${Red}  未检测到 Xray 配置文件${Font}"
    fi
    echo

    # 3. 检查 WARP
    lang_echo "${Green}Cloudflare WARP 配置：${Font}"
    if command -v warp-cli >/dev/null 2>&1; then
        lang_echo "${Yellow}  WARP 是 CLI 工具，无直接编辑的配置文件。${Font}"
        lang_echo "${Yellow}  查看设置: warp-cli settings${Font}"
        lang_echo "${Yellow}  检查连接: curl -x socks5://127.0.0.1:40000 https://ifconfig.me${Font}"
    else
        lang_echo "${Red}  未检测到 warp-cli${Font}"
    fi
    
    echo -e "${Blue}============================================${Font}"
}

# 初始化函数（优化版）
initialize() {
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}      One-Script 环境初始化${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    echo -e "${Green}当前渠道：${Font}${CHANNEL}"
    echo
    
    # 检查权限和环境
    check_root
    check_su_login
    check_ovz
    
    # 系统环境检测
    check_system_environment
    check_cpu_vendor
    check_selinux
    
    # 安装基础工具
    install_basic_tools

    # 混合虚拟内存方案（ZRAM + Swap）
    prompt_hybrid_memory_setup
    
    # 检查网络连接
    check_network_connectivity
    
    # 自动创建swap
    # auto_create_swap
    
    echo -e "${Green}环境初始化完成！${Font}"
    SKIP_CLEAR_ONCE="true"
    sleep 2
}

# 系统工具菜单
bbr_management() {
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}           BBR 管理${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    # 检查当前状态
    local current_algo=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    local current_qdisc=$(sysctl net.core.default_qdisc 2>/dev/null | awk '{print $3}')
    
    lang_echo "${Yellow}当前 TCP 拥塞控制算法：${current_algo:-未知}${Font}"
    lang_echo "${Yellow}当前队列调度算法：${current_qdisc:-未知}${Font}"
    echo
    
    lang_echo "${Green}请选择操作：${Font}"
    lang_echo "${Yellow}1.${Font} 开启 BBR"
    lang_echo "${Yellow}2.${Font} 关闭 BBR (恢复默认 cubic)"
    lang_echo "${Yellow}3.${Font} 返回上级菜单"
    echo
    
    read -p "$(lang_text "请输入选择 [1-3]: ")" bbr_choice
    case $bbr_choice in
        1)
            lang_echo "${Green}正在开启 BBR...${Font}"
            if ! grep -q "net.core.default_qdisc" /etc/sysctl.conf; then
                echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
            else
                sed -i 's/^net.core.default_qdisc.*/net.core.default_qdisc = fq/' /etc/sysctl.conf
            fi
            
            if ! grep -q "net.ipv4.tcp_congestion_control" /etc/sysctl.conf; then
                echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
            else
                sed -i 's/^net.ipv4.tcp_congestion_control.*/net.ipv4.tcp_congestion_control = bbr/' /etc/sysctl.conf
            fi
            
            sysctl -p >/dev/null 2>&1
            lang_echo "${Green}BBR 已开启！${Font}"
            ;;
        2)
            lang_echo "${Green}正在关闭 BBR...${Font}"
            sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
            sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
            
            # 恢复默认
            sysctl -w net.core.default_qdisc=fq_codel >/dev/null 2>&1
            sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null 2>&1
            
            lang_echo "${Green}BBR 已关闭，已恢复为 cubic。${Font}"
            ;;
        *)
            ;;
    esac
    read -p "$(lang_text "按回车键返回...")"
    system_tools_menu
}

system_tools_menu() {
    clear
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}           系统工具和诊断${Font}" "${Green}           System tools & diagnostics${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    lang_echo "${Green}系统工具选项：${Font}" "${Green}System tool options:${Font}"
    lang_echo "${Yellow}1.${Font} 系统信息查看" "${Yellow}1.${Font} System info"
    lang_echo "${Yellow}2.${Font} 网络诊断工具" "${Yellow}2.${Font} Network diagnostics"
    lang_echo "${Yellow}3.${Font} 性能监控和优化" "${Yellow}3.${Font} Performance monitor & tuning"
    lang_echo "${Yellow}4.${Font} 防火墙管理" "${Yellow}4.${Font} Firewall management"
    lang_echo "${Yellow}5.${Font} 服务管理" "${Yellow}5.${Font} Service management"
    lang_echo "${Yellow}6.${Font} 磁盘空间清理" "${Yellow}6.${Font} Disk cleanup"
    lang_echo "${Yellow}7.${Font} 系统日志查看" "${Yellow}7.${Font} System logs"
    lang_echo "${Yellow}8.${Font} 时间同步设置" "${Yellow}8.${Font} Time sync"
    lang_echo "${Yellow}9.${Font} 混合内存管理 (ZRAM/Swap)" "${Yellow}9.${Font} Hybrid memory (ZRAM/Swap)"
    lang_echo "${Yellow}10.${Font} BBR 管理" "${Yellow}10.${Font} BBR management"
    lang_echo "${Yellow}11.${Font} 返回主菜单" "${Yellow}11.${Font} Back to main menu"
    echo
    echo -e "${Blue}============================================${Font}"
    
    local choice
    while true; do
        read -p "$(lang_text "请选择操作 [1-11]: " "Choose an action [1-11]: ")" choice
        case $choice in
            1)
                show_system_info
                break
                ;;
            2)
                network_diagnostic_tools
                break
                ;;
            3)
                performance_monitoring
                break
                ;;
            4)
                firewall_management
                break
                ;;
            5)
                service_management
                break
                ;;
            6)
                disk_cleanup
                break
                ;;
            7)
                view_system_logs
                break
                ;;
            8)
                time_sync_setup
                break
                ;;
            9)
                hybrid_memory_management
                break
                ;;
            10)
                bbr_management
                break
                ;;
            11)
                echo -e "${Yellow}返回主菜单${Font}"
                return 0
                ;;
            *)
                echo -e "${Red}无效选择，请输入 1-11${Font}"
                ;;
        esac
    done
}

# 显示详细系统信息
show_system_info() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}           详细系统信息${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    # 基本系统信息
    echo -e "${Green}基本系统信息：${Font}"
    echo -e "${Yellow}  主机名：$(hostname)${Font}"
    echo -e "${Yellow}  系统：$(uname -o) $(uname -m)${Font}"
    echo -e "${Yellow}  内核：$(uname -r)${Font}"
    echo -e "${Yellow}  运行时间：$(uptime -p 2>/dev/null || uptime)${Font}"
    
    if [[ -f "/etc/os-release" ]]; then
        source /etc/os-release
        echo -e "${Yellow}  发行版：${NAME} ${VERSION}${Font}"
    fi
    echo
    
    # CPU信息
    echo -e "${Green}CPU信息：${Font}"
    if [[ -f "/proc/cpuinfo" ]]; then
        local cpu_model=$(grep "model name" /proc/cpuinfo | head -n1 | cut -d: -f2 | sed 's/^ *//')
        local cpu_cores=$(grep -c "^processor" /proc/cpuinfo)
        echo -e "${Yellow}  CPU型号：${cpu_model}${Font}"
        echo -e "${Yellow}  CPU核心数：${cpu_cores}${Font}"
    fi
    echo
    
    # 内存信息
    echo -e "${Green}内存信息：${Font}"
    if command -v free >/dev/null 2>&1; then
        free -h
    fi
    echo
    
    # 磁盘信息
    echo -e "${Green}磁盘使用情况：${Font}"
    if command -v df >/dev/null 2>&1; then
        df -h
    fi
    echo
    
    # 网络接口信息
    echo -e "${Green}网络接口：${Font}"
    if command -v ip >/dev/null 2>&1; then
        ip addr show | grep -E "(inet|inet6)" | grep -v "127.0.0.1" | grep -v "::1"
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig | grep -E "(inet|inet6)" | grep -v "127.0.0.1" | grep -v "::1"
    fi
    echo
    
    # 负载信息
    echo -e "${Green}系统负载：${Font}"
    if [[ -f "/proc/loadavg" ]]; then
        echo -e "${Yellow}  负载平均值：$(cat /proc/loadavg)${Font}"
    fi
    echo
    
    read -p "按回车键返回系统工具菜单..."
    system_tools_menu
}

# 网络诊断工具
network_diagnostic_tools() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}           网络诊断工具${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    echo -e "${Green}网络诊断选项：${Font}"
    echo -e "${Yellow}1.${Font} 网络连接测试"
    echo -e "${Yellow}2.${Font} DNS解析测试"
    echo -e "${Yellow}3.${Font} 端口连通性测试"
    echo -e "${Yellow}4.${Font} 网络速度测试"
    echo -e "${Yellow}5.${Font} 路由追踪"
    echo -e "${Yellow}6.${Font} 返回系统工具"
    echo
    
    local choice
    while true; do
        read -p "请选择诊断项目 [1-6]: " choice
        case $choice in
            1)
                echo -e "${Blue}正在测试网络连接...${Font}"
                echo -e "${Green}测试国内连接：${Font}"
                ping -c 4 baidu.com 2>/dev/null && echo -e "${Green}  百度连接正常${Font}" || echo -e "${Red}  百度连接失败${Font}"
                echo -e "${Green}测试国外连接：${Font}"
                ping -c 4 google.com 2>/dev/null && echo -e "${Green}  谷歌连接正常${Font}" || echo -e "${Red}  谷歌连接失败${Font}"
                ping -c 4 github.com 2>/dev/null && echo -e "${Green}  GitHub连接正常${Font}" || echo -e "${Red}  GitHub连接失败${Font}"
                break
                ;;
            2)
                echo -e "${Blue}正在测试DNS解析...${Font}"
                if command -v dig >/dev/null 2>&1; then
                    echo -e "${Green}使用dig测试DNS解析：${Font}"
                    dig @8.8.8.8 google.com +short
                    dig @1.1.1.1 cloudflare.com +short
                elif command -v nslookup >/dev/null 2>&1; then
                    echo -e "${Green}使用nslookup测试DNS解析：${Font}"
                    nslookup google.com 8.8.8.8
                fi
                break
                ;;
            3)
                echo -e "${Blue}端口连通性测试${Font}"
                read -p "请输入要测试的主机名或IP: " host
                read -p "请输入要测试的端口: " port
                if command -v nc >/dev/null 2>&1; then
                    nc -zv "$host" "$port" 2>&1
                elif command -v telnet >/dev/null 2>&1; then
                    timeout 5 telnet "$host" "$port"
                else
                    echo -e "${Red}未找到nc或telnet工具${Font}"
                fi
                break
                ;;
            4)
                echo -e "${Blue}网络速度测试（需要安装speedtest-cli）${Font}"
                if command -v speedtest-cli >/dev/null 2>&1; then
                    speedtest-cli
                else
                    echo -e "${Yellow}正在尝试安装speedtest-cli...${Font}"
                    if command -v apt >/dev/null 2>&1; then
                        apt update && apt install -y speedtest-cli
                    elif command -v yum >/dev/null 2>&1; then
                        yum install -y speedtest-cli
                    else
                        echo -e "${Red}无法自动安装speedtest-cli${Font}"
                    fi
                fi
                break
                ;;
            5)
                echo -e "${Blue}路由追踪${Font}"
                read -p "请输入要追踪的主机名或IP (默认: google.com): " target
                target=${target:-google.com}
                if command -v traceroute >/dev/null 2>&1; then
                    traceroute "$target"
                elif command -v tracepath >/dev/null 2>&1; then
                    tracepath "$target"
                else
                    echo -e "${Red}未找到traceroute或tracepath工具${Font}"
                fi
                break
                ;;
            6)
                system_tools_menu
                return
                ;;
            *)
                echo -e "${Red}无效选择，请输入 1-6${Font}"
                ;;
        esac
    done
    
    echo
    read -p "按回车键返回网络诊断菜单..."
    network_diagnostic_tools
}

# 性能监控
performance_monitoring() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}         性能监控和优化${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    echo -e "${Green}当前系统资源使用情况：${Font}"
    
    # CPU使用率
    if command -v top >/dev/null 2>&1; then
        echo -e "${Yellow}CPU使用率（实时）：${Font}"
        top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print "CPU使用率: " 100-$1 "%"}'
    fi
    
    # 内存使用
    echo -e "${Yellow}内存使用情况：${Font}"
    free -h
    echo
    
    # 磁盘I/O
    echo -e "${Yellow}磁盘使用情况：${Font}"
    df -h
    echo
    
    # 进程信息
    echo -e "${Yellow}占用资源最多的进程（CPU）：${Font}"
    ps aux --sort=-%cpu | head -6
    echo
    
    echo -e "${Yellow}占用资源最多的进程（内存）：${Font}"
    ps aux --sort=-%mem | head -6
    echo
    
    # 系统优化建议
    echo -e "${Green}系统优化选项：${Font}"
    echo -e "${Yellow}1.${Font} 清理系统缓存"
    echo -e "${Yellow}2.${Font} 优化Swap设置"
    echo -e "${Yellow}3.${Font} 返回系统工具"
    
    local choice
    read -p "请选择优化项目 [1-3]: " choice
    case $choice in
        1)
            echo -e "${Blue}正在清理系统缓存...${Font}"
            sync
            echo 3 > /proc/sys/vm/drop_caches
            echo -e "${Green}系统缓存清理完成${Font}"
            ;;
        2)
            echo -e "${Blue}当前Swap设置：${Font}"
            cat /proc/sys/vm/swappiness 2>/dev/null || echo "无法读取swappiness设置"
            read -p "请输入新的swappiness值 (1-100, 推荐10-60): " swappiness
            if [[ $swappiness =~ ^[0-9]+$ ]] && [[ $swappiness -ge 1 ]] && [[ $swappiness -le 100 ]]; then
                echo "vm.swappiness=$swappiness" >> /etc/sysctl.conf
                sysctl vm.swappiness=$swappiness
                echo -e "${Green}Swap设置已更新${Font}"
            else
                echo -e "${Red}无效的swappiness值${Font}"
            fi
            ;;
        3)
            system_tools_menu
            return
            ;;
    esac
    
    echo
    read -p "按回车键返回系统工具菜单..."
    system_tools_menu
}

# 防火墙管理（简化版）
firewall_management() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}           防火墙管理${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    # 检测防火墙类型
    local firewall_type=""
    if command -v ufw >/dev/null 2>&1; then
        firewall_type="ufw"
        echo -e "${Green}检测到 UFW 防火墙${Font}"
        ufw status
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall_type="firewalld"
        echo -e "${Green}检测到 Firewalld 防火墙${Font}"
        firewall-cmd --state 2>/dev/null && firewall-cmd --list-all 2>/dev/null
    elif command -v iptables >/dev/null 2>&1; then
        firewall_type="iptables"
        echo -e "${Green}检测到 IPTables${Font}"
        iptables -L INPUT -n --line-numbers | head -10
    else
        echo -e "${Yellow}未检测到常见的防火墙工具${Font}"
    fi
    
    echo
    echo -e "${Green}防火墙管理选项：${Font}"
    echo -e "${Yellow}1.${Font} 查看防火墙状态"
    echo -e "${Yellow}2.${Font} 开放端口"
    echo -e "${Yellow}3.${Font} 关闭端口"
    echo -e "${Yellow}4.${Font} 返回系统工具"
    
    local choice
    read -p "请选择操作 [1-4]: " choice
    case $choice in
        1)
            case $firewall_type in
                "ufw")
                    ufw status verbose
                    ;;
                "firewalld")
                    firewall-cmd --list-all
                    ;;
                "iptables")
                    iptables -L -n --line-numbers
                    ;;
                *)
                    echo -e "${Red}无法识别防火墙类型${Font}"
                    ;;
            esac
            ;;
        2)
            read -p "请输入要开放的端口: " port
            case $firewall_type in
                "ufw")
                    ufw allow "$port"
                    ;;
                "firewalld")
                    firewall-cmd --permanent --add-port="$port/tcp"
                    firewall-cmd --reload
                    ;;
                "iptables")
                    iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
                    # 自动保存iptables规则
                    if command -v netfilter-persistent >/dev/null 2>&1; then
                        netfilter-persistent save
                        echo -e "${Green}iptables规则已自动保存${Font}"
                    elif [[ -f /etc/iptables/rules.v4 ]] && command -v iptables-save >/dev/null 2>&1; then
                        iptables-save > /etc/iptables/rules.v4
                        echo -e "${Green}iptables规则已保存到 /etc/iptables/rules.v4${Font}"
                    else
                        echo -e "${Yellow}注意：iptables规则需要手动保存${Font}"
                    fi
                    ;;
                *)
                    echo -e "${Red}无法识别防火墙类型${Font}"
                    ;;
            esac
            ;;
        3)
            read -p "请输入要关闭的端口: " port
            case $firewall_type in
                "ufw")
                    ufw deny "$port"
                    ;;
                "firewalld")
                    firewall-cmd --permanent --remove-port="$port/tcp"
                    firewall-cmd --reload
                    ;;
                "iptables")
                    # 显示现有规则供用户参考
                    echo -e "${Blue}当前iptables INPUT规则：${Font}"
                    iptables -L INPUT -n --line-numbers | grep "$port"
                    echo
                    echo -e "${Yellow}请手动使用以下命令删除对应规则：${Font}"
                    echo -e "${Blue}iptables -D INPUT <规则编号>${Font}"
                    echo -e "${Yellow}或者使用：${Font}"
                    echo -e "${Blue}iptables -D INPUT -p tcp --dport $port -j ACCEPT${Font}"
                    echo
                    read -p "是否要自动尝试删除端口 $port 的ACCEPT规则？[y/N]: " auto_remove
                    if [[ $auto_remove =~ ^[Yy]$ ]]; then
                        iptables -D INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null
                        if command -v netfilter-persistent >/dev/null 2>&1; then
                            netfilter-persistent save
                            echo -e "${Green}iptables规则已自动保存${Font}"
                        elif [[ -f /etc/iptables/rules.v4 ]] && command -v iptables-save >/dev/null 2>&1; then
                            iptables-save > /etc/iptables/rules.v4
                            echo -e "${Green}iptables规则已保存到 /etc/iptables/rules.v4${Font}"
                        fi
                        echo -e "${Green}端口 $port 的规则已尝试删除${Font}"
                    fi
                    ;;
                *)
                    echo -e "${Red}无法识别防火墙类型${Font}"
                    ;;
            esac
            ;;
        4)
            system_tools_menu
            return
            ;;
    esac
    
    echo
    read -p "按回车键返回防火墙管理..."
    firewall_management
}

# 服务管理
service_management() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}           服务管理${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    echo -e "${Green}常见服务状态：${Font}"
    
    # 检查常见服务
    local services=("nginx" "apache2" "ssh" "sshd" "docker" "mysql" "mariadb")
    
    for service in "${services[@]}"; do
        if systemctl list-unit-files | grep -q "^$service.service"; then
            local status=$(systemctl is-active "$service" 2>/dev/null)
            if [[ "$status" == "active" ]]; then
                echo -e "${Green}  $service: 运行中${Font}"
            else
                echo -e "${Yellow}  $service: 未运行${Font}"
            fi
        fi
    done
    
    echo
    echo -e "${Green}服务管理选项：${Font}"
    echo -e "${Yellow}1.${Font} 查看所有服务状态"
    echo -e "${Yellow}2.${Font} 启动服务"
    echo -e "${Yellow}3.${Font} 停止服务"
    echo -e "${Yellow}4.${Font} 重启服务"
    echo -e "${Yellow}5.${Font} 查看服务日志"
    echo -e "${Yellow}6.${Font} 返回系统工具"
    
    local choice
    read -p "请选择操作 [1-6]: " choice
    case $choice in
        1)
            systemctl list-unit-files --type=service | grep enabled | head -20
            ;;
        2)
            read -p "请输入要启动的服务名: " service_name
            systemctl start "$service_name" && echo -e "${Green}服务启动成功${Font}" || echo -e "${Red}服务启动失败${Font}"
            ;;
        3)
            read -p "请输入要停止的服务名: " service_name
            systemctl stop "$service_name" && echo -e "${Green}服务停止成功${Font}" || echo -e "${Red}服务停止失败${Font}"
            ;;
        4)
            read -p "请输入要重启的服务名: " service_name
            systemctl restart "$service_name" && echo -e "${Green}服务重启成功${Font}" || echo -e "${Red}服务重启失败${Font}"
            ;;
        5)
            read -p "请输入要查看日志的服务名: " service_name
            journalctl -u "$service_name" -n 50 --no-pager
            ;;
        6)
            system_tools_menu
            return
            ;;
    esac
    
    echo
    read -p "按回车键返回服务管理..."
    service_management
}

# 磁盘空间清理
disk_cleanup() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}           磁盘空间清理${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    echo -e "${Green}当前磁盘使用情况：${Font}"
    df -h
    echo
    
    echo -e "${Green}清理选项：${Font}"
    echo -e "${Yellow}1.${Font} 清理APT缓存 (Debian/Ubuntu)"
    echo -e "${Yellow}2.${Font} 清理YUM缓存 (CentOS/RHEL)"
    echo -e "${Yellow}3.${Font} 清理临时文件"
    echo -e "${Yellow}4.${Font} 清理日志文件"
    echo -e "${Yellow}5.${Font} 查找大文件"
    echo -e "${Yellow}6.${Font} 返回系统工具"
    
    local choice
    read -p "请选择清理项目 [1-6]: " choice
    case $choice in
        1)
            if command -v apt >/dev/null 2>&1; then
                echo -e "${Blue}正在清理APT缓存...${Font}"
                apt clean && apt autoremove -y && apt autoclean
                echo -e "${Green}APT缓存清理完成${Font}"
            else
                echo -e "${Red}系统不支持APT包管理器${Font}"
            fi
            ;;
        2)
            if command -v yum >/dev/null 2>&1; then
                echo -e "${Blue}正在清理YUM缓存...${Font}"
                yum clean all
                echo -e "${Green}YUM缓存清理完成${Font}"
            else
                echo -e "${Red}系统不支持YUM包管理器${Font}"
            fi
            ;;
        3)
            echo -e "${Blue}正在清理临时文件...${Font}"
            rm -rf /tmp/* 2>/dev/null
            rm -rf /var/tmp/* 2>/dev/null
            echo -e "${Green}临时文件清理完成${Font}"
            ;;
        4)
            echo -e "${Blue}正在清理日志文件...${Font}"
            journalctl --vacuum-time=7d 2>/dev/null
            find /var/log -name "*.log" -type f -mtime +7 -delete 2>/dev/null
            echo -e "${Green}日志文件清理完成${Font}"
            ;;
        5)
            echo -e "${Blue}查找大于100MB的文件...${Font}"
            find / -type f -size +100M -exec ls -lh {} \; 2>/dev/null | head -10
            ;;
        6)
            system_tools_menu
            return
            ;;
    esac
    
    echo
    echo -e "${Green}清理后磁盘使用情况：${Font}"
    df -h
    echo
    read -p "按回车键返回磁盘清理..."
    disk_cleanup
}

# 查看系统日志
view_system_logs() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}           系统日志查看${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    echo -e "${Green}日志查看选项：${Font}"
    echo -e "${Yellow}1.${Font} 查看系统日志 (syslog)"
    echo -e "${Yellow}2.${Font} 查看内核日志 (dmesg)"
    echo -e "${Yellow}3.${Font} 查看认证日志 (auth.log)"
    echo -e "${Yellow}4.${Font} 查看启动日志 (boot.log)"
    echo -e "${Yellow}5.${Font} 查看journalctl日志"
    echo -e "${Yellow}6.${Font} 返回系统工具"
    
    local choice
    read -p "请选择要查看的日志 [1-6]: " choice
    case $choice in
        1)
            if [[ -f "/var/log/syslog" ]]; then
                echo -e "${Blue}最近50行系统日志：${Font}"
                tail -50 /var/log/syslog
            elif [[ -f "/var/log/messages" ]]; then
                echo -e "${Blue}最近50行系统日志：${Font}"
                tail -50 /var/log/messages
            else
                echo -e "${Red}未找到系统日志文件${Font}"
            fi
            ;;
        2)
            echo -e "${Blue}内核日志：${Font}"
            dmesg | tail -50
            ;;
        3)
            if [[ -f "/var/log/auth.log" ]]; then
                echo -e "${Blue}最近50行认证日志：${Font}"
                tail -50 /var/log/auth.log
            elif [[ -f "/var/log/secure" ]]; then
                echo -e "${Blue}最近50行认证日志：${Font}"
                tail -50 /var/log/secure
            else
                echo -e "${Red}未找到认证日志文件${Font}"
            fi
            ;;
        4)
            if [[ -f "/var/log/boot.log" ]]; then
                echo -e "${Blue}启动日志：${Font}"
                cat /var/log/boot.log
            else
                echo -e "${Red}未找到启动日志文件${Font}"
            fi
            ;;
        5)
            if command -v journalctl >/dev/null 2>&1; then
                echo -e "${Blue}最近50条journalctl日志：${Font}"
                journalctl -n 50 --no-pager
            else
                echo -e "${Red}系统不支持journalctl${Font}"
            fi
            ;;
        6)
            system_tools_menu
            return
            ;;
    esac
    
    echo
    read -p "按回车键返回日志查看..."
    view_system_logs
}

# 时间同步设置
time_sync_setup() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}           时间同步设置${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    echo -e "${Green}当前系统时间：${Font}"
    echo -e "${Yellow}  系统时间：$(date)${Font}"
    echo -e "${Yellow}  时区：$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "未知")${Font}"
    echo
    
    if command -v timedatectl >/dev/null 2>&1; then
        echo -e "${Green}时间同步状态：${Font}"
        timedatectl status
        echo
    fi
    
    echo -e "${Green}时间管理选项：${Font}"
    echo -e "${Yellow}1.${Font} 设置时区"
    echo -e "${Yellow}2.${Font} 启用NTP时间同步"
    echo -e "${Yellow}3.${Font} 手动同步时间"
    echo -e "${Yellow}4.${Font} 返回系统工具"
    
    local choice
    read -p "请选择操作 [1-4]: " choice
    case $choice in
        1)
            echo -e "${Blue}常用时区：${Font}"
            echo -e "${Yellow}  Asia/Shanghai (北京时间)${Font}"
            echo -e "${Yellow}  UTC (协调世界时)${Font}"
            echo -e "${Yellow}  America/New_York (纽约时间)${Font}"
            echo -e "${Yellow}  Europe/London (伦敦时间)${Font}"
            read -p "请输入时区 (例如: Asia/Shanghai): " timezone
            if command -v timedatectl >/dev/null 2>&1; then
                timedatectl set-timezone "$timezone" && echo -e "${Green}时区设置成功${Font}" || echo -e "${Red}时区设置失败${Font}"
            else
                echo "$timezone" > /etc/timezone && echo -e "${Green}时区设置成功${Font}" || echo -e "${Red}时区设置失败${Font}"
            fi
            ;;
        2)
            if command -v timedatectl >/dev/null 2>&1; then
                timedatectl set-ntp true && echo -e "${Green}NTP时间同步已启用${Font}" || echo -e "${Red}NTP时间同步启用失败${Font}"
            elif command -v ntpdate >/dev/null 2>&1; then
                ntpdate -s pool.ntp.org && echo -e "${Green}时间同步完成${Font}" || echo -e "${Red}时间同步失败${Font}"
            else
                echo -e "${Red}系统不支持NTP时间同步${Font}"
            fi
            ;;
        3)
            if command -v ntpdate >/dev/null 2>&1; then
                echo -e "${Blue}正在手动同步时间...${Font}"
                ntpdate pool.ntp.org && echo -e "${Green}时间同步完成${Font}" || echo -e "${Red}时间同步失败${Font}"
            elif command -v chrony >/dev/null 2>&1; then
                chrony sources -v
            else
                echo -e "${Red}未找到时间同步工具${Font}"
            fi
            ;;
        4)
            system_tools_menu
            return
            ;;
    esac
    
    echo
    read -p "按回车键返回时间同步设置..."
    time_sync_setup
}

# 主函数
main() {
    parse_channel_args "$@"
    set -- "${REMAINING_ARGS[@]}"

    # 处理命令行参数
    case "${1:-}" in
        "--hybrid-memory")
            check_root
            check_su_login
            check_ovz
            check_system_environment
            install_basic_tools
            hybrid_memory_management "standalone"
            exit 0
            ;;
        "--zram-status")
            check_root
            check_su_login
            check_ovz
            check_system_environment
            show_zram_swap_status
            exit 0
            ;;
        "--zram-disable")
            check_root
            check_su_login
            check_ovz
            check_system_environment
            disable_zram_swap
            exit 0
            ;;
        "--zram-config")
            check_root
            check_su_login
            check_ovz
            check_system_environment
            install_basic_tools
            read -r zram_mb zram_algo zram_priority < <(prompt_zram_config)
            configure_zram_swap "${zram_mb}" "${zram_algo}" "${zram_priority}"
            exit 0
            ;;
        "--install-command")
            check_root
            install_quick_command
            exit 0
            ;;
        "--uninstall-command")
            check_root
            uninstall_quick_command
            exit 0
            ;;
        "--help"|"-h")
            show_help
            exit 0
            ;;
        "--version"|"-v")
            show_version_info
            exit 0
            ;;
    esac
    
    # 初始化环境
    initialize
    
    # 进入主菜单
    main_menu
}

# 显示帮助信息
show_help() {
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}      One-Script 脚本帮助信息${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    echo -e "${Green}用法：${Font}"
    echo -e "  $(basename "$0") [选项]"
    echo
    echo -e "${Green}选项：${Font}"
    echo -e "  ${Yellow}--channel dev|main${Font}      选择运行渠道（默认 main）"
    echo -e "  ${Yellow}--help, -h${Font}              显示此帮助信息"
    echo -e "  ${Yellow}--version, -v${Font}           显示版本信息"
    echo -e "  ${Yellow}--install-command${Font}       安装简易命令 (${REMOTE_COMMAND_NAME})"
    echo -e "  ${Yellow}--uninstall-command${Font}     卸载简易命令"
    echo
    echo -e "${Green}简易命令：${Font}"
    echo -e "  安装后可通过 '${Yellow}${REMOTE_COMMAND_NAME}${Font}' 命令启动脚本"
    echo -e "  使用方法：${Yellow}sudo ${REMOTE_COMMAND_NAME}${Font}"
    echo -e "  模式：${Yellow}远程运行（始终获取最新版本）${Font}"
    echo
    echo -e "${Green}功能特性：${Font}"
    echo -e "  • 智能 Swap 内存管理"
    echo -e "  • 远程脚本获取执行"
    echo -e "  • V2Ray 定时重启配置"
    echo -e "  • 脚本自动更新功能"
    echo -e "  • 远程运行命令安装"
    echo -e "  • 智能 iptables 规则管理"
    echo -e "  • 始终运行最新版本"
    echo
    echo -e "${Green}GitHub仓库：${Font}https://github.com/charleslkx/one-script"
    echo -e "${Blue}============================================${Font}"
}

# 更新 main.sh 脚本
update_main_script() {
    echo -e "${Blue}正在检查 main.sh 脚本更新...${Font}"
    
    local script_path="$0"
    
    # 获取当前脚本版本信息
    echo -e "${Green}当前脚本路径：${script_path}${Font}"
    echo
    
    # 显示更新选项
    echo -e "${Green}更新选项：${Font}"
    echo -e "${Yellow}1.${Font} 检查并更新到最新版本"
    echo -e "${Yellow}2.${Font} 强制重新下载脚本"
    echo -e "${Yellow}3.${Font} 查看当前版本信息"
    echo -e "${Yellow}4.${Font} 返回主菜单"
    echo
    
    local choice
    while true; do
        read -p "请选择更新选项 [1-4]: " choice
        case $choice in
            1)
                check_and_update
                break
                ;;
            2)
                force_update
                break
                ;;
            3)
                show_version_info
                break
                ;;
            4)
                echo -e "${Yellow}返回主菜单${Font}"
                return 0
                ;;
            *)
                echo -e "${Red}无效选择，请输入 1-4${Font}"
                ;;
        esac
    done
}

# 检查并更新脚本
check_and_update() {
    echo -e "${Blue}正在检查远程版本...${Font}"
    
    local script_path="$0"
    local temp_script="${TEMP_DIR}/main_new.sh"
    
    # 下载最新版本
    if download_file "${BASE_URL}/main.sh" "$temp_script"; then
        echo -e "${Green}最新版本下载成功${Font}"
        
        # 比较文件
        if ! diff -q "$script_path" "$temp_script" >/dev/null 2>&1; then
            echo -e "${Yellow}检测到新版本，准备更新...${Font}"
            perform_update "$script_path" "$temp_script"
        else
            echo -e "${Green}当前已是最新版本，无需更新${Font}"
            rm -f "$temp_script"
        fi
    else
        echo -e "${Red}无法下载最新版本，请检查网络连接${Font}"
    fi
}

# 强制更新脚本
force_update() {
    echo -e "${Yellow}正在强制更新脚本...${Font}"
    
    local script_path="$0"
    local temp_script="${TEMP_DIR}/main_new.sh"
    
    # 下载最新版本
    if download_file "${BASE_URL}/main.sh" "$temp_script"; then
        echo -e "${Green}最新版本下载成功${Font}"
        perform_update "$script_path" "$temp_script"
    else
        echo -e "${Red}无法下载最新版本，请检查网络连接${Font}"
    fi
}

# 执行更新操作
perform_update() {
    local script_path="$1"
    local temp_script="$2"
    
    # 直接更新脚本
    echo -e "${Blue}正在更新脚本...${Font}"
    if cp "$temp_script" "$script_path" && chmod +x "$script_path"; then
        echo -e "${Green}脚本更新成功！${Font}"
        rm -f "$temp_script"
        
        echo -e "${Yellow}更新完成，建议重新启动脚本以使用新版本${Font}"
        echo -e "${Blue}是否现在重新启动脚本？[y/N]:${Font}"
        read -p "" restart_choice
        if [[ $restart_choice =~ ^[Yy]$ ]]; then
            echo -e "${Green}正在重新启动脚本...${Font}"
            exec "$script_path"
        fi
    else
        echo -e "${Red}脚本更新失败！${Font}"
        rm -f "$temp_script"
    fi
}

# 显示版本信息
show_version_info() {
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}       One-Script 脚本信息${Font}"
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}脚本名称：${Font}One-Script 统一管理脚本"
    echo -e "${Green}脚本路径：${Font}$0"
    echo -e "${Green}修改时间：${Font}$(stat -c %y "$0" 2>/dev/null || echo "未知")"
    echo -e "${Green}文件大小：${Font}$(stat -c %s "$0" 2>/dev/null || echo "未知") 字节"
    echo -e "${Green}GitHub仓库：${Font}https://github.com/charleslkx/one-script"
    echo
    echo -e "${Green}功能特性：${Font}"
    echo -e "  • 智能 Swap 内存管理"
    echo -e "  • 远程脚本获取执行"  
    echo -e "  • V2Ray 定时重启配置"
    echo -e "  • 脚本自动更新功能"
    echo -e "  • 简易命令安装管理"
    echo -e "  • 智能 iptables 规则管理"
    echo -e "  • 优化的工具安装流程"
    echo -e "${Blue}============================================${Font}"
    echo
}

# 命令管理菜单
command_management() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}           命令管理${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    local command_name="${REMOTE_COMMAND_NAME}"
    local found=false
    
    # 检查命令状态
    echo -e "${Green}简易命令状态检查：${Font}"
    
    if [[ -f "/usr/bin/${command_name}" ]]; then
        echo -e "${Green}  /usr/bin/${command_name} ✓${Font}"
        found=true
    fi
    
    if [[ -f "/usr/sbin/${command_name}" ]]; then
        echo -e "${Green}  /usr/sbin/${command_name} ✓${Font}"
        found=true
    fi
    
    if [[ -f "/usr/local/bin/${command_name}" ]]; then
        echo -e "${Green}  /usr/local/bin/${command_name} ✓${Font}"
        found=true
    fi
    
    if [[ "$found" == "true" ]]; then
        echo -e "${Green}总体状态：${Font}已安装（远程运行模式）"
        echo -e "${Green}使用方法：${Font}${command_name} 或 sudo ${command_name}"
        echo -e "${Yellow}特性：始终运行最新版本，无需本地文件${Font}"
    else
        echo -e "${Yellow}总体状态：${Font}未安装"
    fi
    
    echo
    echo -e "${Green}命令管理选项：${Font}"
    echo -e "${Yellow}1.${Font} 安装远程运行命令 (${command_name})"
    echo -e "${Yellow}2.${Font} 卸载远程运行命令"
    echo -e "${Yellow}3.${Font} 查看详细状态"
    echo -e "${Yellow}4.${Font} 返回主菜单"
    echo
    echo -e "${Blue}============================================${Font}"
    
    local choice
    while true; do
        read -p "请选择操作 [1-4]: " choice
        case $choice in
            1)
                install_quick_command
                break
                ;;
            2)
                uninstall_quick_command
                break
                ;;
            3)
                show_command_status
                break
                ;;
            4)
                echo -e "${Yellow}返回主菜单${Font}"
                return 0
                ;;
            *)
                echo -e "${Red}无效选择，请输入 1-4${Font}"
                ;;
        esac
    done
}

# 显示命令状态
show_command_status() {
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}         简易命令状态信息${Font}"
    echo -e "${Blue}============================================${Font}"
    
    local command_name="${REMOTE_COMMAND_NAME}"
    local script_path="$(readlink -f "$0")"
    local found=false
    
    echo -e "${Green}当前脚本路径：${Font}${script_path}"
    echo -e "${Green}简易命令名称：${Font}${command_name}"
    echo
    
    # 检查各个位置的命令
    echo -e "${Green}命令安装状态：${Font}"
    
    if [[ -f "/usr/bin/${command_name}" ]]; then
        echo -e "${Green}  /usr/bin/${command_name} ✓${Font}"
        echo -e "${Green}  链接目标：$(readlink "/usr/bin/${command_name}" 2>/dev/null || echo "无法读取")${Font}"
        found=true
    else
        echo -e "${Yellow}  /usr/bin/${command_name} ✗${Font}"
    fi
    
    if [[ -f "/usr/sbin/${command_name}" ]]; then
        echo -e "${Green}  /usr/sbin/${command_name} ✓${Font}"
        echo -e "${Green}  链接目标：$(readlink "/usr/sbin/${command_name}" 2>/dev/null || echo "无法读取")${Font}"
        found=true
    else
        echo -e "${Yellow}  /usr/sbin/${command_name} ✗${Font}"
    fi
    
    if [[ -f "/usr/local/bin/${command_name}" ]]; then
        echo -e "${Green}  /usr/local/bin/${command_name} ✓${Font}"
        echo -e "${Green}  链接目标：$(readlink "/usr/local/bin/${command_name}" 2>/dev/null || echo "无法读取")${Font}"
        found=true
    else
        echo -e "${Yellow}  /usr/local/bin/${command_name} ✗${Font}"
    fi
    
    echo
    if [[ "$found" == "true" ]]; then
        echo -e "${Green}总体状态：${Font}已安装 ✓（远程运行模式）"
        echo
        echo -e "${Green}使用方法：${Font}"
        echo -e "  ${Blue}${command_name}${Font}                # 从远程启动最新版本脚本"
        echo -e "  ${Blue}sudo ${command_name}${Font}           # 以root权限从远程启动脚本"
        echo -e "  ${Blue}${command_name} --help${Font}         # 查看帮助信息"
        echo -e "  ${Blue}${command_name} --version${Font}      # 查看版本信息"
        echo
        echo -e "${Green}特性：${Font}"
        echo -e "  • 始终运行最新版本"
        echo -e "  • 无需本地存储脚本"
        echo -e "  • 自动检查网络连接"
    else
        echo -e "${Yellow}总体状态：${Font}未安装"
        echo
        echo -e "${Yellow}安装后可使用：${Font}"
        echo -e "  ${Blue}sudo ${command_name}${Font}           # 从远程启动脚本"
    fi
    
    echo
    echo -e "${Yellow}PATH 环境变量：${Font}"
    echo -e "${Blue}$(echo $PATH | tr ':' '\n' | grep -E '(usr/bin|usr/sbin|usr/local/bin)' || echo "未找到相关路径")${Font}"
    
    echo -e "${Blue}============================================${Font}"
    echo
}

# 启动脚本
main "$@"
