#!/usr/bin/env bash
# One-Script main entry script - manage swap and provide script menu.

# 颜色定义
Green="\033[32m"
Font="\033[0m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[34m"

LANGUAGE_CHOICE="en"

lang_text() {
    local _zh="$1"
    local en="$2"
    printf "%b" "${en}"
}

lang_echo() {
    local _zh="$1"
    local en="$2"
    echo -e "${en}"
}

select_language() {
    LANGUAGE_CHOICE="en"
    export ONE_SCRIPT_LANG="${LANGUAGE_CHOICE}"
}

select_language

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
    lang_echo "${Green}    快速切换服务器 IPv4/IPv6 优先级${Font}" "${Green}    Quick switch IPv4/IPv6 priority${Font}"
    echo -e "${Blue}============================================${Font}"
    echo

    local current_pref
    current_pref=$(detect_global_ip_preference)
    if [[ "${current_pref}" == "ipv4" ]]; then
        lang_echo "${Yellow}当前状态：IPv4 优先（通过 /etc/gai.conf 配置）${Font}" "${Yellow}Current: IPv4 preferred (via /etc/gai.conf)${Font}"
    else
        lang_echo "${Yellow}当前状态：IPv6 优先（系统默认）${Font}" "${Yellow}Current: IPv6 preferred (system default)${Font}"
    fi
    echo
    lang_echo "${Green}请选择目标优先级：${Font}" "${Green}Choose target preference:${Font}"
    lang_echo "${Yellow}1.${Font} 设置为 IPv4 优先（解析域名时优先使用 IPv4）" "${Yellow}1.${Font} Prefer IPv4 for DNS resolution"
    lang_echo "${Yellow}2.${Font} 设置为 IPv6 优先（恢复系统默认策略）" "${Yellow}2.${Font} Prefer IPv6 (system default)"
    lang_echo "${Yellow}3.${Font} 取消操作" "${Yellow}3.${Font} Cancel"
    echo
    read -p "$(lang_text "请输入选择 [1-3]: " "Choose [1-3]: ")" ip_choice

    case "${ip_choice}" in
    1)
        set_global_ip_preference "ipv4"
        lang_echo "${Green}已设置为 IPv4 优先。对新发起的域名解析立即生效。${Font}" "${Green}IPv4 preference applied for new DNS lookups.${Font}"
        ;;
    2)
        set_global_ip_preference "ipv6"
        lang_echo "${Green}已恢复为 IPv6 优先。对新发起的域名解析立即生效。${Font}" "${Green}Restored IPv6 preference for new DNS lookups.${Font}"
        ;;
    *)
        lang_echo "${Yellow}已取消操作。${Font}" "${Yellow}Cancelled.${Font}"
        ;;
    esac
}

# 安装简易命令（远程运行版本）
install_quick_command() {
    echo -e "${Blue}        ...${Font}"
    
    local command_name="v2ray"
    local base_url="https://raw.githubusercontent.com/charleslkx/one-script/master"
    local vasmaType=false
    
    # 显示当前环境信息
    echo -e "${Green}     $(whoami)${Font}"
    echo -e "${Green}         ${Font}"
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
BASE_URL="https://raw.githubusercontent.com/charleslkx/one-script/master"

# 检查网络连接
check_network() {
    lang_echo "${Blue}正在检查网络连接...${Font}" "${Blue}Checking network connection...${Font}"
    if ping -c 1 raw.githubusercontent.com >/dev/null 2>&1; then
        lang_echo "${Green}网络连接正常${Font}" "${Green}Network is accessible${Font}"
        return 0
    else
        lang_echo "${Red}无法连接到远程仓库，请检查网络连接${Font}" "${Red}Cannot reach remote repository, check network${Font}"
        return 1
    fi
}

# 运行远程脚本
run_remote_script() {
    lang_echo "${Blue}正在从远程仓库获取脚本...${Font}" "${Blue}Fetching script from remote repository...${Font}"
    lang_echo "${Green}源地址: ${BASE_URL}/main.sh${Font}" "${Green}Source: ${BASE_URL}/main.sh${Font}"
    echo
    
    # 尝试使用 wget 或 curl 运行远程脚本
    if command -v wget >/dev/null 2>&1; then
        lang_echo "${Blue}使用 wget 下载中...${Font}" "${Blue}Using wget to download...${Font}"
        bash <(wget -qO- "${BASE_URL}/main.sh" 2>/dev/null) "$@"
    elif command -v curl >/dev/null 2>&1; then
        lang_echo "${Blue}使用 curl 下载中...${Font}" "${Blue}Using curl to download...${Font}"
        bash <(curl -fsSL "${BASE_URL}/main.sh" 2>/dev/null) "$@"
    else
        lang_echo "${Red}错误: 系统未安装 wget 或 curl 工具${Font}" "${Red}Error: wget or curl not found${Font}"
        lang_echo "${Yellow}请先安装 wget 或 curl 后重试${Font}" "${Yellow}Please install wget or curl first${Font}"
        exit 1
    fi
}

# 显示帮助信息
show_help() {
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}      One-Script 快捷命令${Font}" "${Green}      One-Script Quick Command${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    lang_echo "${Green}说明${Font}" "${Green}Description${Font}"
    lang_echo "  v2ray [快捷命令]" "  v2ray [quick command]"
    echo
    lang_echo "${Green}可用选项${Font}" "${Green}Available Options${Font}"
    lang_echo "  ${Yellow}--help, -h${Font}                显示帮助信息" "  ${Yellow}--help, -h${Font}                Show help information"
    lang_echo "  ${Yellow}--version, -v${Font}             显示版本信息" "  ${Yellow}--version, -v${Font}             Show version information"
    lang_echo "  ${Yellow}--install-command${Font}         安装快捷命令" "  ${Yellow}--install-command${Font}         Install quick command"
    lang_echo "  ${Yellow}--uninstall-command${Font}       卸载快捷命令" "  ${Yellow}--uninstall-command${Font}       Uninstall quick command"
    echo
    lang_echo "${Green}使用说明${Font}" "${Green}Usage${Font}"
    lang_echo "直接运行脚本会进入交互式菜单。" "Please follow the on-screen instructions."
    lang_echo "使用快捷命令可更方便地管理服务。" "Use quick commands for easier service management."
    lang_echo "需要 root 权限才能执行某些操作。" "Root privileges required for some operations."
    echo
    lang_echo "${Green}GitHub 仓库${Font}https://github.com/charleslkx/one-script" "${Green}GitHub Repository${Font}https://github.com/charleslkx/one-script"
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
            lang_echo "${Green}One-Script 快捷命令版本 v1.0${Font}" "${Green}One-Script Quick Command v1.0${Font}"
            echo -e "${Green}GitHub: https://github.com/charleslkx/one-script${Font}"
            exit 0
            ;;
        "--install-command")
            lang_echo "${Yellow}开始安装快捷命令...${Font}" "${Yellow}Installing quick command...${Font}"
            exit 0
            ;;
        "--uninstall-command")
            lang_echo "${Yellow}开始卸载快捷命令...${Font}" "${Yellow}Uninstalling quick command...${Font}"
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
        lang_echo "${Green}正在尝试创建快捷命令: ${bin_path}${Font}" "${Green}Attempting to create quick command: ${bin_path}${Font}"
        
        if [[ ! -f "$bin_path" ]]; then
            if echo "$remote_script_content" > "$bin_path" 2>/dev/null && chmod 755 "$bin_path" 2>/dev/null; then
                vasmaType=true
                lang_echo "${Green}成功安装到 /usr/bin 目录${Font}" "${Green}Successfully installed to /usr/bin${Font}"
            else
                lang_echo "${Yellow}无法写入 /usr/bin 目录${Font}" "${Yellow}Cannot write to /usr/bin${Font}"
            fi
        else
            lang_echo "${Yellow}命令已存在: ${bin_path}${Font}" "${Yellow}Command already exists: ${bin_path}${Font}"
            lang_echo "${Yellow}是否覆盖安装? [y/N]:${Font}" "${Yellow}Overwrite installation? [y/N]:${Font}"
            read -p "" reinstall_choice
            if [[ $reinstall_choice =~ ^[Yy]$ ]]; then
                rm -f "$bin_path"
                if echo "$remote_script_content" > "$bin_path" 2>/dev/null && chmod 755 "$bin_path" 2>/dev/null; then
                    vasmaType=true
                    lang_echo "${Green}命令已更新安装${Font}" "${Green}Command reinstalled successfully${Font}"
                fi
            fi
        fi
    fi
    
    # 如果 /usr/bin 失败，尝试 /usr/sbin
    if [[ "$vasmaType" == "false" && -d "/usr/sbin/" ]]; then
        local sbin_path="/usr/sbin/${command_name}"
        lang_echo "${Green}尝试使用备用目录: /usr/sbin${Font}" "${Green}Trying alternative directory: /usr/sbin${Font}"
        
        if [[ ! -f "$sbin_path" ]]; then
            if echo "$remote_script_content" > "$sbin_path" 2>/dev/null && chmod 755 "$sbin_path" 2>/dev/null; then
                vasmaType=true
                lang_echo "${Green}成功安装到 /usr/sbin 目录${Font}" "${Green}Successfully installed to /usr/sbin${Font}"
            else
                lang_echo "${Yellow}无法写入 /usr/sbin 目录${Font}" "${Yellow}Cannot write to /usr/sbin${Font}"
            fi
        fi
    fi
    
    # 如果以上都失败，尝试 /usr/local/bin
    if [[ "$vasmaType" == "false" ]]; then
        local local_bin_path="/usr/local/bin/${command_name}"
        lang_echo "${Green}尝试最后一个目录: /usr/local/bin${Font}" "${Green}Trying last option: /usr/local/bin${Font}"
        
        # 确保目录存在
        if [[ ! -d "/usr/local/bin" ]]; then
            lang_echo "${Yellow}/usr/local/bin 目录不存在，正在创建...${Font}" "${Yellow}/usr/local/bin doesn't exist, creating...${Font}"
            mkdir -p /usr/local/bin
        fi
        
        if [[ ! -f "$local_bin_path" ]]; then
            if echo "$remote_script_content" > "$local_bin_path" 2>/dev/null && chmod 755 "$local_bin_path" 2>/dev/null; then
                vasmaType=true
                lang_echo "${Green}成功安装到 /usr/local/bin 目录${Font}" "${Green}Successfully installed to /usr/local/bin${Font}"
            else
                lang_echo "${Red}无法写入 /usr/local/bin 目录${Font}" "${Red}Cannot write to /usr/local/bin${Font}"
            fi
        fi
    fi
    
    # 显示安装结果
    if [[ "$vasmaType" == "true" ]]; then
        echo
        lang_echo "${Green}快捷命令安装成功！${Font}" "${Green}Quick command installed successfully!${Font}"
        lang_echo "${Yellow}现在您可以使用以下命令：${Font}" "${Yellow}You can now use the following commands:${Font}"
        lang_echo "${Blue}  ${command_name}${Font}                # 运行主菜单" "${Blue}  ${command_name}${Font}                # Run main menu"
        lang_echo "${Blue}  sudo ${command_name}${Font}           # 以 root 身份运行" "${Blue}  sudo ${command_name}${Font}           # Run as root"
        lang_echo "${Blue}  ${command_name} --help${Font}         # 显示帮助" "${Blue}  ${command_name} --help${Font}         # Show help"
        lang_echo "${Blue}  ${command_name} --version${Font}      # 显示版本" "${Blue}  ${command_name} --version${Font}      # Show version"
        echo
        lang_echo "${Green}提示：${Font}" "${Green}Tips:${Font}"
        lang_echo "${Green}快捷命令会自动从 GitHub 获取最新版本${Font}" "${Green}Quick command automatically fetches latest version from GitHub${Font}"
        lang_echo "${Green}无需手动更新本地脚本${Font}" "${Green}No manual local script updates needed${Font}"
        lang_echo "${Green}您的配置文件和服务不受影响${Font}" "${Green}Your config files and services are unaffected${Font}"
        echo
        lang_echo "${Yellow}有任何问题请访问 GitHub 仓库${Font}" "${Yellow}For any issues, visit our GitHub repository${Font}"
    else
        lang_echo "${Red}快捷命令安装失败${Font}" "${Red}Quick command installation failed${Font}"
        lang_echo "${Yellow}请检查是否有 root 权限${Font}" "${Yellow}Please check if you have root privileges${Font}"
    fi
}

# 卸载简易命令
uninstall_quick_command() {
    local command_name="v2ray"
    local removed=false
    
    lang_echo "${Yellow}正在搜索并删除快捷命令...${Font}" "${Yellow}Searching and removing quick command...${Font}"
    
    # 检查并删除 /usr/bin 中的命令
    if [[ -f "/usr/bin/${command_name}" ]]; then
        if rm -f "/usr/bin/${command_name}"; then
            lang_echo "${Green}已从 /usr/bin 删除 '${command_name}'${Font}" "${Green}Removed '${command_name}' from /usr/bin${Font}"
            removed=true
        else
            lang_echo "${Red}无法从 /usr/bin 删除 '${command_name}'${Font}" "${Red}Cannot remove '${command_name}' from /usr/bin${Font}"
        fi
    fi
    
    # 检查并删除 /usr/sbin 中的命令
    if [[ -f "/usr/sbin/${command_name}" ]]; then
        if rm -f "/usr/sbin/${command_name}"; then
            lang_echo "${Green}已从 /usr/sbin 删除 '${command_name}'${Font}" "${Green}Removed '${command_name}' from /usr/sbin${Font}"
            removed=true
        else
            lang_echo "${Red}无法从 /usr/sbin 删除 '${command_name}'${Font}" "${Red}Cannot remove '${command_name}' from /usr/sbin${Font}"
        fi
    fi
    
    # 检查并删除 /usr/local/bin 中的命令
    if [[ -f "/usr/local/bin/${command_name}" ]]; then
        if rm -f "/usr/local/bin/${command_name}"; then
            lang_echo "${Green}已从 /usr/local/bin 删除 '${command_name}'${Font}" "${Green}Removed '${command_name}' from /usr/local/bin${Font}"
            removed=true
        else
            lang_echo "${Red}无法从 /usr/local/bin 删除 '${command_name}'${Font}" "${Red}Cannot remove '${command_name}' from /usr/local/bin${Font}"
        fi
    fi
    
    if [[ "$removed" == "true" ]]; then
        lang_echo "${Green}快捷命令 '${command_name}' 已成功卸载${Font}" "${Green}Quick command '${command_name}' successfully uninstalled${Font}"
    else
        lang_echo "${Yellow}未找到快捷命令 '${command_name}' 或已被卸载${Font}" "${Yellow}Quick command '${command_name}' not found or already uninstalled${Font}"
    fi
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        lang_echo "${Red}错误: 此脚本需要 root 权限运行${Font}" "${Red}Error: This script must be run as root${Font}"
        exit 1
    fi
}

# 检查OpenVZ
check_ovz() {
    if [[ -d "/proc/vz" ]]; then
        lang_echo "${Red}您的 VPS 基于 OpenVZ，不支持 swap 操作${Font}" "${Red}Your VPS is based on OpenVZ, swap not supported${Font}"
        exit 1
    fi
}

# 系统检测和环境初始化
check_system_environment() {
    lang_echo "${Blue}正在检查系统环境...${Font}" "${Blue}Checking system environment...${Font}"
    
    # 设置语言环境
    export LANG=en_US.UTF-8
    
    # 检测系统发行版
    local release=""
    local installType=""
    local upgrade=""
    local removeType=""
    local updateReleaseInfoChange=""
    
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
        
    elif { [[ -f "/etc/issue" ]] && grep -qi "ubuntu" /etc/issue; } || { [[ -f "/proc/version" ]] && grep -qi "ubuntu" /proc/version; }; then
        release="ubuntu"
        installType='apt -y install'
        upgrade="apt update"
        updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
        removeType='apt -y autoremove'
        
        if grep </etc/issue -q -i "16."; then
            echo -e "${Red}Ubuntu 16                 ${Font}"
            exit 0
        fi
    fi
    
    if [[ -z ${release} ]]; then
        echo -e "${Red}                      ${Font}"
        echo -e "${Yellow}$(cat /etc/issue)${Font}"
        echo -e "${Yellow}$(cat /proc/version)${Font}"
        exit 0
    fi
    
    echo -e "${Green}      ${release}${Font}"
    echo -e "${Green}     ${installType}${Font}"
}

# 检查CPU架构
check_cpu_vendor() {
    echo -e "${Blue}    CPU  ...${Font}"
    
    if [[ -n $(which uname) ]]; then
        if [[ "$(uname)" == "Linux" ]]; then
            case "$(uname -m)" in
            'amd64' | 'x86_64')
                cpuVendor="amd64"
                echo -e "${Green}CPU   x86_64/amd64${Font}"
                ;;
            'armv8' | 'aarch64')
                cpuVendor="arm64"
                echo -e "${Green}CPU   arm64${Font}"
                ;;
            'armv7' | 'armv7l')
                cpuVendor="arm"
                echo -e "${Green}CPU   arm${Font}"
                ;;
            *)
                cpuVendor="amd64"
                echo -e "${Yellow}          amd64${Font}"
                ;;
            esac
        fi
    else
        cpuVendor="amd64"
        echo -e "${Yellow}            amd64${Font}"
    fi
}

# 安装基础工具包
install_basic_tools() {
    echo -e "${Blue}         ...${Font}"
    
    # 修复ubuntu个别系统问题
    if [[ "${release}" == "ubuntu" ]]; then
        dpkg --configure -a >/dev/null 2>&1
    fi
    
    # 杀死可能阻塞的包管理进程
    if [[ -n $(pgrep -f "apt") ]]; then
        pgrep -f apt | xargs kill -9 >/dev/null 2>&1
    fi
    
    echo -e "${Green} --->        ${Font}"
    ${upgrade} >/dev/null 2>&1
    
    if [[ "${release}" == "centos" ]]; then
        rm -rf /var/run/yum.pid >/dev/null 2>&1
        ${installType} epel-release >/dev/null 2>&1
    fi
    
    # 检查并安装基础工具
    local tools=("wget" "curl" "unzip" "tar" "jq")
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo -e "${Green} --->    $tool${Font}"
            ${installType} "$tool" >/dev/null 2>&1
        fi
    done
    
    # 安装系统特定的工具
    if [[ "${release}" == "centos" ]]; then
        if ! command -v dig >/dev/null 2>&1; then
            echo -e "${Green} --->    bind-utils (dig)${Font}"
            ${installType} bind-utils >/dev/null 2>&1
        fi
    elif [[ "${release}" == "ubuntu" ]] || [[ "${release}" == "debian" ]]; then
        if ! command -v dig >/dev/null 2>&1; then
            echo -e "${Green} --->    dnsutils (dig)${Font}"
            ${installType} dnsutils >/dev/null 2>&1
        fi
        
        if ! command -v cron >/dev/null 2>&1; then
            echo -e "${Green} --->    cron${Font}"
            ${installType} cron >/dev/null 2>&1
        fi
    elif [[ "${release}" == "alpine" ]]; then
        if ! command -v dig >/dev/null 2>&1; then
            echo -e "${Green} --->    bind-tools (dig)${Font}"
            ${installType} bind-tools >/dev/null 2>&1
        fi
    fi
    
    echo -e "${Green}         ${Font}"
}

# 检查网络连接
check_network_connectivity() {
    echo -e "${Blue}        ...${Font}"
    
    # 检查IPv4连接
    if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        echo -e "${Green}IPv4       ${Font}"
    else
        echo -e "${Yellow}IPv4       ${Font}"
    fi
    
    # 检查域名解析
    if ping -c 1 -W 3 github.com >/dev/null 2>&1; then
        echo -e "${Green}      ${Font}"
    else
        echo -e "${Yellow}          ${Font}"
    fi
    
    # 检查GitHub连接性
    if curl -s --connect-timeout 10 https://api.github.com >/dev/null 2>&1; then
        echo -e "${Green}GitHub     ${Font}"
    else
        echo -e "${Yellow}GitHub                  ${Font}"
    fi
}

# 检查SELinux状态（CentOS/RHEL）
check_selinux() {
    if [[ "${release}" == "centos" ]] && [[ -f "/etc/selinux/config" ]]; then
        if ! grep -q "SELINUX=disabled" "/etc/selinux/config"; then
            echo -e "${Yellow}   SELinux   ${Font}"
            echo -e "${Yellow}    SELinux       ${Font}"
            echo -e "${Blue}      /etc/selinux/config      SELINUX=enforcing    SELINUX=disabled${Font}"
        fi
    fi
}

# 获取内存大小（MB）
get_memory_size() {
    local mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local mem_mb=$((mem_kb / 1024))
    echo $mem_mb
}

# 自动创建swap（优化版）
auto_create_swap() {
    echo -e "${Blue}         swap  ...${Font}"
    
    local memory_mb=$(get_memory_size)
    echo -e "${Green}       ${memory_mb}MB${Font}"
    
    # 检查是否已存在swap文件
    if [[ -f "/swapfile" ]] || grep -q "swapfile" /etc/fstab 2>/dev/null; then
        echo -e "${Yellow}      swap        ${Font}"
        
        # 显示当前swap状态
        if [[ -f "/proc/swaps" ]]; then
            echo -e "${Green}  swap   ${Font}"
            cat /proc/swaps
        fi
        return 0
    fi
    
    # 检查是否有其他swap分区
    local existing_swap=$(swapon --show 2>/dev/null | wc -l)
    if [[ $existing_swap -gt 1 ]]; then
        echo -e "${Yellow}       swap       swap  ${Font}"
        swapon --show 2>/dev/null
        return 0
    fi
    
    # 检查磁盘可用空间
    local available_space_kb=$(df / | tail -1 | awk '{print $4}')
    local available_space_mb=$((available_space_kb / 1024))
    echo -e "${Green}        ${available_space_mb}MB${Font}"
    
    # 根据内存大小决定推荐的swap大小
    local recommended_swap_size
    local max_swap_size=$((available_space_mb - 1024))  # 保留1GB空间
    
    if [[ $memory_mb -lt 512 ]]; then
        recommended_swap_size=1024  # 1GB
        echo -e "${Yellow}       512MB     1GB swap${Font}"
    elif [[ $memory_mb -lt 1024 ]]; then
        recommended_swap_size=2048  # 2GB
        echo -e "${Yellow}       1GB     2GB swap${Font}"
    elif [[ $memory_mb -lt 2048 ]]; then
        recommended_swap_size=2048  # 2GB
        echo -e "${Yellow}       2GB     2GB swap${Font}"
    else
        recommended_swap_size=1024  # 1GB
        echo -e "${Yellow}            1GB swap${Font}"
    fi
    
    # 检查推荐大小是否超过可用空间
    if [[ $recommended_swap_size -gt $max_swap_size ]]; then
        if [[ $max_swap_size -gt 512 ]]; then
            recommended_swap_size=$max_swap_size
            echo -e "${Yellow}          swap    ${recommended_swap_size}MB${Font}"
        else
            echo -e "${Red}           swap  ${Font}"
            return 1
        fi
    fi
    
    echo
    echo -e "${Green}Swap     ${Font}"
    echo -e "${Yellow}1.${Font}          swap (${recommended_swap_size}MB)"
    echo -e "${Yellow}2.${Font}     swap  "
    echo -e "${Yellow}3.${Font}   swap  "
    echo
    
    local choice
    while true; do
        read -p "    [1-3]: " choice
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
                echo -e "${Yellow}  swap   ${Font}"
                return 0
                ;;
            *)
                echo -e "${Red}         1-3${Font}"
                ;;
        esac
    done
}

# 手动创建swap（优化版）
manual_create_swap() {
    local max_swap_size=${1:-10240}  # 默认最大10GB
    local swap_size
    
    while true; do
        echo -e "${Green}        swap      MB  ${Font}"
        echo -e "${Yellow}     512MB - ${max_swap_size}MB${Font}"
        echo -e "${Yellow}      1-2            ${Font}"
        read -p "   swap  : " swap_size
        
        # 验证输入是否为数字
        if [[ $swap_size =~ ^[0-9]+$ ]] && [[ $swap_size -gt 0 ]]; then
            # 检查是否超过最大允许大小
            if [[ $swap_size -gt $max_swap_size ]]; then
                echo -e "${Red}                   ${max_swap_size}MB${Font}"
                continue
            fi
            
            # 检查是否太小
            if [[ $swap_size -lt 128 ]]; then
                echo -e "${Red}swap         128MB${Font}"
                continue
            fi
            
            echo -e "${Green}   ${swap_size}MB swap  ${Font}"
            read -p "      [y/N]: " confirm
            if [[ $confirm =~ ^[Yy]$ ]]; then
                create_swap_file $swap_size
                break
            fi
        else
            echo -e "${Red}           0 ${Font}"
        fi
    done
}

# 创建swap文件的通用函数（优化版）
create_swap_file() {
    local swap_size=$1
    echo -e "${Green}    ${swap_size}MB swap  ...${Font}"
    
    # 检查是否有足够的磁盘空间
    local available_space_kb=$(df / | tail -1 | awk '{print $4}')
    local available_space_mb=$((available_space_kb / 1024))
    local required_space_mb=$((swap_size + 200))  # 额外200MB缓冲
    
    if [[ $available_space_mb -lt $required_space_mb ]]; then
        echo -e "${Red}         ${required_space_mb}MB   ${available_space_mb}MB${Font}"
        return 1
    fi
    
    # 删除可能存在的旧swap文件
    if [[ -f "/swapfile" ]]; then
        echo -e "${Yellow}       swap       ...${Font}"
        swapoff /swapfile 2>/dev/null
        rm -f /swapfile
    fi
    
    # 创建swap文件
    echo -e "${Blue}    swap  ...${Font}"
    if dd if=/dev/zero of=/swapfile bs=1M count=${swap_size} status=progress 2>/dev/null; then
        # 设置正确的权限
        chmod 600 /swapfile
        
        # 设置为swap文件
        echo -e "${Blue}     swap  ...${Font}"
        if mkswap /swapfile >/dev/null 2>&1; then
            # 启用swap
            echo -e "${Blue}    swap...${Font}"
            if swapon /swapfile; then
                # 添加到fstab实现开机自动挂载
                if ! grep -q "/swapfile" /etc/fstab; then
                    echo '/swapfile none swap defaults 0 0' >> /etc/fstab
                fi
                
                # 优化swap使用策略
                echo -e "${Blue}    swap  ...${Font}"
                
                # 设置swappiness（建议值10-60，默认60）
                local swappiness=10
                echo "vm.swappiness=${swappiness}" >> /etc/sysctl.conf
                sysctl vm.swappiness=${swappiness} >/dev/null 2>&1
                
                # 设置vfs_cache_pressure（建议值50-100，默认100）
                local vfs_cache_pressure=50
                echo "vm.vfs_cache_pressure=${vfs_cache_pressure}" >> /etc/sysctl.conf
                sysctl vm.vfs_cache_pressure=${vfs_cache_pressure} >/dev/null 2>&1
                
                echo -e "${Green}Swap     ${Font}"
                echo -e "${Green}Swap   ${Font}"
                cat /proc/swaps
                echo
                echo -e "${Green}       ${Font}"
                free -h
                echo
                echo -e "${Blue}Swap     ${Font}"
                echo -e "${Green}  swappiness: ${swappiness} (  swap                swap)${Font}"
                echo -e "${Green}  vfs_cache_pressure: ${vfs_cache_pressure} (           inode cache     )${Font}"
                
            else
                echo -e "${Red}  swap   ${Font}"
                rm -f /swapfile
                return 1
            fi
        else
            echo -e "${Red}   swap     ${Font}"
            rm -f /swapfile
            return 1
        fi
    else
        echo -e "${Red}  swap                   ${Font}"
        return 1
    fi
}

# 显示脚本选择菜单
show_script_menu() {
    clear
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}      One-Script 脚本管理工具${Font}" "${Green}      One-Script Script Manager${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    lang_echo "${Green}系统信息：${Font}" "${Green}System info:${Font}"
    if command -v uname >/dev/null 2>&1; then
        lang_echo "${Yellow}  操作系统：$(uname -o) $(uname -m)${Font}" "${Yellow}  OS: $(uname -o) $(uname -m)${Font}"
        lang_echo "${Yellow}  内核版本：$(uname -r)${Font}" "${Yellow}  Kernel: $(uname -r)${Font}"
    fi
    if [[ -f "/etc/os-release" ]]; then
        source /etc/os-release
        lang_echo "${Yellow}  发行版本：${NAME} ${VERSION}${Font}" "${Yellow}  Release: ${NAME} ${VERSION}${Font}"
    fi
    lang_echo "${Yellow}  当前用户：$(whoami)${Font}" "${Yellow}  User: $(whoami)${Font}"
    lang_echo "${Yellow}  系统时间：$(date '+%Y-%m-%d %H:%M:%S')${Font}" "${Yellow}  Time: $(date '+%Y-%m-%d %H:%M:%S')${Font}"
    echo
    lang_echo "${Green}请选择要运行的脚本：${Font}" "${Green}Select the script to run:${Font}"
    echo
    lang_echo "${Yellow}1.${Font} V2Ray 安装脚本 ${Blue}(本仓库修改版install.sh)${Font}" "${Yellow}1.${Font} V2Ray installer ${Blue}(modified install.sh in this repo)${Font}"
    lang_echo "${Yellow}2.${Font} V2Ray 原版安装脚本 ${Blue}(mack-a官方原版)${Font}" "${Yellow}2.${Font} V2Ray original installer ${Blue}(mack-a official)${Font}"
    lang_echo "${Yellow}3.${Font} Swap 管理脚本 ${Blue}(虚拟内存管理)${Font}" "${Yellow}3.${Font} Swap manager ${Blue}(virtual memory)${Font}"
    lang_echo "${Yellow}4.${Font} 更新 main.sh 脚本 ${Blue}(检查脚本更新)${Font}" "${Yellow}4.${Font} Update main.sh ${Blue}(check for updates)${Font}"
    lang_echo "${Yellow}5.${Font} 命令管理 ${Blue}(安装/卸载v2ray快捷命令)${Font}" "${Yellow}5.${Font} Command manager ${Blue}(install/uninstall quick command)${Font}"
    lang_echo "${Yellow}6.${Font} 系统工具 ${Blue}(系统优化和诊断)${Font}" "${Yellow}6.${Font} System tools ${Blue}(tuning & diagnostics)${Font}"
    lang_echo "${Yellow}7.${Font} 快速切换节点IPv4/IPv6优先级" "${Yellow}7.${Font} Quick IPv4/IPv6 preference switch"
    lang_echo "${Yellow}8.${Font} 内核安装脚本 (BBR/BBR Plus)" "${Yellow}8.${Font} Kernel installer (BBR/BBR Plus)"
    lang_echo "${Yellow}9.${Font} 查询核心配置路径" "${Yellow}9.${Font} Show core config paths"
    lang_echo "${Yellow}10.${Font} 管理定时重启 ${Blue}(添加/删除cron任务)${Font}" "${Yellow}10.${Font} Manage auto-reboot ${Blue}(add/remove cron job)${Font}"
    lang_echo "${Yellow}11.${Font} VLESS 蓝绿部署 ${Blue}(高可用监控切流)${Font}" "${Yellow}11.${Font} VLESS Blue-Green ${Blue}(HA monitoring & failover)${Font}"
    lang_echo "${Yellow}12.${Font} 退出" "${Yellow}12.${Font} Exit"
    echo
    echo -e "${Blue}============================================${Font}"
}

# 执行选择的脚本
execute_script() {
    local choice=$1
    local base_url="https://raw.githubusercontent.com/charleslkx/one-script/master"
    
    case $choice in
        1)
            lang_echo "${Green}正在启动 V2Ray 安装脚本...${Font}" "${Green}Launching V2Ray installer...${Font}"
            lang_echo "${Yellow}正在从远程仓库获取 install.sh (修改版本)...${Font}" "${Yellow}Fetching install.sh (modified) from repository...${Font}"
            
            # 先尝试下载脚本到临时文件
            local temp_script="/tmp/v2ray_temp.sh"
            local download_success=false
            
            # 使用本仓库的修改版install.sh
            local install_script_name="install.sh"
            if [[ "${LANGUAGE_CHOICE}" == "en" ]]; then
                install_script_name="install.sh"
            fi
            local v2ray_url="${base_url}/${install_script_name}"
            
            if wget -qO "$temp_script" "$v2ray_url" 2>/dev/null; then
                download_success=true
                lang_echo "${Green}使用 wget 下载成功${Font}" "${Green}Downloaded with wget${Font}"
            elif curl -fsSL "$v2ray_url" -o "$temp_script" 2>/dev/null; then
                download_success=true
                lang_echo "${Green}使用 curl 下载成功${Font}" "${Green}Downloaded with curl${Font}"
            fi
            
            if [[ "$download_success" == "true" && -s "$temp_script" ]]; then
                lang_echo "${Green}开始执行 V2Ray 安装脚本...${Font}" "${Green}Starting installer...${Font}"
                # 执行脚本，不管退出状态码
                bash "$temp_script"
                lang_echo "${Green}V2Ray 脚本执行完成${Font}" "${Green}V2Ray install script finished${Font}"
                rm -f "$temp_script"
                # 询问用户是否添加定时重启任务
                ask_crontab_reboot
            else
                lang_echo "${Red}错误：无法从远程仓库获取 V2Ray 安装脚本！${Font}" "${Red}Error: unable to download V2Ray installer!${Font}"
                lang_echo "${Yellow}请检查网络连接或稍后重试${Font}" "${Yellow}Check your network connection or try again later${Font}"
                rm -f "$temp_script"
            fi
            ;;
        2)
            lang_echo "${Green}正在启动 V2Ray 原版安装脚本...${Font}" "${Green}Launching original V2Ray installer...${Font}"
            lang_echo "${Yellow}正在从 mack-a 官方仓库获取原版 install.sh...${Font}" "${Yellow}Fetching official install.sh from mack-a...${Font}"
            
            # 先尝试下载脚本到临时文件
            local temp_script="/tmp/v2ray_original_temp.sh"
            local download_success=false
            
            # 使用mack-a的官方原版脚本
            local v2ray_original_url="https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh"
            
            if wget -qO "$temp_script" "$v2ray_original_url" 2>/dev/null; then
                download_success=true
                lang_echo "${Green}使用 wget 下载成功${Font}" "${Green}Downloaded with wget${Font}"
            elif curl -fsSL "$v2ray_original_url" -o "$temp_script" 2>/dev/null; then
                download_success=true
                lang_echo "${Green}使用 curl 下载成功${Font}" "${Green}Downloaded with curl${Font}"
            fi
            
            if [[ "$download_success" == "true" && -s "$temp_script" ]]; then
                lang_echo "${Green}开始执行 V2Ray 原版安装脚本...${Font}" "${Green}Starting official installer...${Font}"
                lang_echo "${Yellow}注意：这是 mack-a 的官方原版，不包含本仓库的改进${Font}" "${Yellow}Note: this is the official version without this repo's tweaks${Font}"
                # 执行脚本，不管退出状态码
                bash "$temp_script"
                lang_echo "${Green}V2Ray 原版脚本执行完成${Font}" "${Green}Official V2Ray script finished${Font}"
                rm -f "$temp_script"
            else
                lang_echo "${Red}错误：无法从 mack-a 官方仓库获取原版安装脚本！${Font}" "${Red}Error: unable to download installer from mack-a!${Font}"
                lang_echo "${Yellow}请检查网络连接或稍后重试${Font}" "${Yellow}Check your network connection or try again later${Font}"
                rm -f "$temp_script"
            fi
            ;;
        3)
            lang_echo "${Green}正在启动 Swap 管理脚本...${Font}" "${Green}Launching swap manager...${Font}"
            lang_echo "${Yellow}正在从远程仓库获取 swap.sh...${Font}" "${Yellow}Fetching swap.sh from repository...${Font}"
            local swap_script_name="swap.sh"
            if [[ "${LANGUAGE_CHOICE}" == "en" ]]; then
                swap_script_name="swap.sh"
            fi
            if bash <(wget -qO- "${base_url}/${swap_script_name}" 2>/dev/null || curl -fsSL "${base_url}/${swap_script_name}" 2>/dev/null); then
                lang_echo "${Green}脚本执行完成${Font}" "${Green}Script finished${Font}"
            else
                lang_echo "${Red}错误：无法从远程仓库获取 swap.sh 脚本！${Font}" "${Red}Error: unable to download swap.sh!${Font}"
                lang_echo "${Yellow}请检查网络连接或稍后重试${Font}" "${Yellow}Check your network connection or try again later${Font}"
            fi
            ;;
        4)
            lang_echo "${Green}正在更新 main.sh 脚本...${Font}" "${Green}Updating main.sh...${Font}"
            update_main_script
            ;;
        5)
            lang_echo "${Green}进入命令管理...${Font}" "${Green}Opening command manager...${Font}"
            command_management
            ;;
        6)
            lang_echo "${Green}进入系统工具...${Font}" "${Green}Opening system tools...${Font}"
            system_tools_menu
            ;;
        7)
            quick_switch_ip_priority
            ;;
        8)
            lang_echo "${Green}正在启动内核安装脚本...${Font}" "${Green}Launching kernel installation script...${Font}"
            local script_dir="$(dirname "$(readlink -f "$0")")"
            local local_script="${script_dir}/install_kernel.sh"
            
            if [[ -f "$local_script" ]]; then
                bash "$local_script"
            else
                lang_echo "${Yellow}正在从远程仓库获取 install_kernel.sh...${Font}" "${Yellow}Fetching install_kernel.sh from repository...${Font}"
                local temp_script="/tmp/install_kernel.sh"
                local kernel_script_name="install_kernel.sh"
                if [[ "${LANGUAGE_CHOICE}" == "en" ]]; then
                    kernel_script_name="install_kernel.sh"
                fi
                local kernel_url="${base_url}/${kernel_script_name}"
                
                if wget -qO "$temp_script" "$kernel_url" 2>/dev/null || curl -fsSL "$kernel_url" -o "$temp_script" 2>/dev/null; then
                    bash "$temp_script"
                    rm -f "$temp_script"
                else
                    lang_echo "${Red}错误：无法从远程仓库获取 install_kernel.sh 脚本！${Font}" "${Red}Error: unable to download install_kernel.sh!${Font}"
                    lang_echo "${Yellow}请检查网络连接或稍后重试${Font}" "${Yellow}Check your network connection or try again later${Font}"
                fi
            fi
            ;;
        9)
            show_config_paths
            ;;
        10)
            manage_crontab_menu
            ;;
        11)
            lang_echo "${Green}进入 VLESS 蓝绿部署管理...${Font}" "${Green}Opening VLESS Blue-Green management...${Font}"
            vless_bluegreen_menu
            ;;
        12)
            lang_echo "${Green}感谢使用，再见！${Font}" "${Green}Thanks for using, bye!${Font}"
            exit 0
            ;;
        *)
            lang_echo "${Red}无效选择，请输入 1-12${Font}" "${Red}Invalid choice, please enter 1-12${Font}"
            sleep 2
            main_menu
            ;;
    esac
}

# 询问用户是否添加定时重启任务
ask_crontab_reboot() {
    echo
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}是否需要添加每日定时重启任务？${Font}" "${Green}Add daily auto-reboot schedule?${Font}"
    echo -e "${Blue}============================================${Font}"
    
    # 检查是否已存在重启任务
    if crontab -l 2>/dev/null | grep -q "0 5 \* \* \* /sbin/reboot"; then
        lang_echo "${Yellow}注意：系统已存在定时重启任务${Font}" "${Yellow}Note: Auto-reboot task already exists${Font}"
        echo
        lang_echo "${Green}1. 保持现有设置${Font}" "${Green}1. Keep current setting${Font}"
        lang_echo "${Green}2. 移除定时重启${Font}" "${Green}2. Remove auto-reboot${Font}"
        echo
        read -p "$(lang_text '请选择 [1-2，默认1]: ' 'Choose [1-2, default 1]: ')" reboot_choice
        reboot_choice=${reboot_choice:-1}
        
        if [[ "$reboot_choice" == "2" ]]; then
            remove_crontab_reboot
        else
            lang_echo "${Green}保持现有定时重启设置${Font}" "${Green}Keeping existing auto-reboot setting${Font}"
        fi
    else
        lang_echo "${Yellow}定时重启可以帮助保持系统稳定性（每天凌晨5点）${Font}" "${Yellow}Auto-reboot helps maintain system stability (5:00 AM daily)${Font}"
        echo
        lang_echo "${Green}1. 添加定时重启（推荐）${Font}" "${Green}1. Add auto-reboot (recommended)${Font}"
        lang_echo "${Green}2. 暂不添加${Font}" "${Green}2. Skip for now${Font}"
        echo
        read -p "$(lang_text '请选择 [1-2，默认2]: ' 'Choose [1-2, default 2]: ')" reboot_choice
        reboot_choice=${reboot_choice:-2}
        
        if [[ "$reboot_choice" == "1" ]]; then
            add_crontab_reboot
        else
            lang_echo "${Green}已跳过定时重启设置${Font}" "${Green}Skipped auto-reboot setup${Font}"
        fi
    fi
    echo
}

# 添加定时重启任务
add_crontab_reboot() {
    # 备份当前的crontab
    crontab -l 2>/dev/null > /tmp/current_crontab || touch /tmp/current_crontab
    
    # 添加新的重启任务
    echo "0 5 * * * /sbin/reboot" >> /tmp/current_crontab
    
    # 应用新的crontab
    if crontab /tmp/current_crontab; then
        lang_echo "${Green}✓ 已成功添加定时重启任务${Font}" "${Green}✓ Auto-reboot task added successfully${Font}"
        lang_echo "${Green}  计划时间：每天凌晨 5:00${Font}" "${Green}  Scheduled time: 5:00 AM daily${Font}"
        rm -f /tmp/current_crontab
    else
        lang_echo "${Red}✗ 添加定时重启失败${Font}" "${Red}✗ Failed to add auto-reboot${Font}"
        rm -f /tmp/current_crontab
    fi
}

# 移除定时重启任务
remove_crontab_reboot() {
    # 备份当前的crontab
    crontab -l 2>/dev/null > /tmp/current_crontab || touch /tmp/current_crontab
    
    # 移除重启任务
    sed -i '/\/sbin\/reboot/d' /tmp/current_crontab
    
    # 应用新的crontab
    if crontab /tmp/current_crontab; then
        lang_echo "${Green}✓ 已成功移除定时重启任务${Font}" "${Green}✓ Auto-reboot task removed successfully${Font}"
        rm -f /tmp/current_crontab
    else
        lang_echo "${Red}✗ 移除定时重启失败${Font}" "${Red}✗ Failed to remove auto-reboot${Font}"
        rm -f /tmp/current_crontab
    fi
}

# Cron定时重启管理菜单
manage_crontab_menu() {
    while true; do
        echo
        echo -e "${Blue}============================================${Font}"
        lang_echo "${Green}     定时重启管理${Font}" "${Green}     Auto-Reboot Management${Font}"
        echo -e "${Blue}============================================${Font}"
        echo
        
        # 检查当前状态
        if crontab -l 2>/dev/null | grep -q "0 5 \* \* \* /sbin/reboot"; then
            lang_echo "${Green}当前状态：${Font}${Yellow}已启用定时重启${Font}" "${Green}Status:${Font} ${Yellow}Auto-reboot enabled${Font}"
            lang_echo "${Yellow}  计划时间：每天凌晨 5:00${Font}" "${Yellow}  Schedule: 5:00 AM daily${Font}"
        else
            lang_echo "${Green}当前状态：${Font}${Red}未启用定时重启${Font}" "${Green}Status:${Font} ${Red}Auto-reboot disabled${Font}"
        fi
        
        echo
        lang_echo "${Green}可用操作：${Font}" "${Green}Available actions:${Font}"
        echo
        lang_echo "${Yellow}1.${Font} 添加定时重启任务" "${Yellow}1.${Font} Add auto-reboot task"
        lang_echo "${Yellow}2.${Font} 移除定时重启任务" "${Yellow}2.${Font} Remove auto-reboot task"
        lang_echo "${Yellow}3.${Font} 查看所有cron任务" "${Yellow}3.${Font} View all cron tasks"
        lang_echo "${Yellow}4.${Font} 返回主菜单" "${Yellow}4.${Font} Back to main menu"
        echo
        echo -e "${Blue}============================================${Font}"
        
        read -p "$(lang_text '请选择 [1-4]: ' 'Choose [1-4]: ')" cron_choice
        
        case "$cron_choice" in
            1)
                echo
                if crontab -l 2>/dev/null | grep -q "0 5 \* \* \* /sbin/reboot"; then
                    lang_echo "${Yellow}定时重启任务已存在，无需重复添加${Font}" "${Yellow}Auto-reboot task already exists${Font}"
                else
                    add_crontab_reboot
                fi
                sleep 2
                ;;
            2)
                echo
                if crontab -l 2>/dev/null | grep -q "0 5 \* \* \* /sbin/reboot"; then
                    remove_crontab_reboot
                else
                    lang_echo "${Yellow}未找到定时重启任务${Font}" "${Yellow}Auto-reboot task not found${Font}"
                fi
                sleep 2
                ;;
            3)
                echo
                echo -e "${Blue}============================================${Font}"
                lang_echo "${Green}当前所有cron任务：${Font}" "${Green}All current cron tasks:${Font}"
                echo -e "${Blue}============================================${Font}"
                if crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$"; then
                    lang_echo "${Green}任务列表如上${Font}" "${Green}Tasks listed above${Font}"
                else
                    lang_echo "${Yellow}未设置任何cron任务${Font}" "${Yellow}No cron tasks configured${Font}"
                fi
                echo
                read -p "$(lang_text '按回车键继续...' 'Press Enter to continue...')"
                ;;
            4)
                return
                ;;
            *)
                lang_echo "${Red}无效选择，请输入 1-4${Font}" "${Red}Invalid choice, please enter 1-4${Font}"
                sleep 2
                ;;
        esac
    done
}

# 主菜单
main_menu() {
    while true; do
        show_script_menu
        read -p "$(lang_text "请输入您的选择 [1-12]: " "Choose an option [1-12]: ")" choice
        execute_script "$choice"
        echo
        if [[ "$choice" != "11" ]]; then
            read -p "$(lang_text "脚本执行完毕，按回车键返回主菜单..." "Script finished. Press Enter to return to the main menu...")"
        fi
    done
}

# 显示核心配置路径
show_config_paths() {
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}           核心配置文件路径查询${Font}" "${Green}           Core config path lookup${Font}"
    echo -e "${Blue}============================================${Font}"
    echo

    # 1. 检查 Sing-box
    lang_echo "${Green}Sing-box 配置：${Font}" "${Green}Sing-box config:${Font}"
    local sb_found=false
    
    # 检查 install.sh 安装路径
    if [[ -f "/etc/v2ray-agent/sing-box/conf/config.json" ]]; then
        lang_echo "${Yellow}  主配置文件 (install.sh): /etc/v2ray-agent/sing-box/conf/config.json${Font}" "${Yellow}  Main config (install.sh): /etc/v2ray-agent/sing-box/conf/config.json${Font}"
        sb_found=true
    fi
    if [[ -f "/etc/v2ray-agent/sing-box/conf/config_warp_template.json" ]]; then
        lang_echo "${Yellow}  WARP 模板文件: /etc/v2ray-agent/sing-box/conf/config_warp_template.json${Font}" "${Yellow}  WARP template: /etc/v2ray-agent/sing-box/conf/config_warp_template.json${Font}"
        sb_found=true
    fi
    
    # 检查标准安装路径
    if [[ -f "/etc/sing-box/config.json" ]]; then
        lang_echo "${Yellow}  主配置文件 (标准): /etc/sing-box/config.json${Font}" "${Yellow}  Main config (standard): /etc/sing-box/config.json${Font}"
        sb_found=true
    fi
    
    if [[ "$sb_found" == "false" ]]; then
        lang_echo "${Red}  未检测到 Sing-box 配置文件${Font}" "${Red}  No Sing-box config found${Font}"
    fi
    echo

    # 2. 检查 Xray (install.sh)
    lang_echo "${Green}Xray 配置：${Font}" "${Green}Xray config:${Font}"
    if [[ -f "/etc/v2ray-agent/xray/conf/config.json" ]]; then
        lang_echo "${Yellow}  主配置文件: /etc/v2ray-agent/xray/conf/config.json${Font}" "${Yellow}  Main config: /etc/v2ray-agent/xray/conf/config.json${Font}"
    else
        lang_echo "${Red}  未检测到 Xray 配置文件${Font}" "${Red}  No Xray config found${Font}"
    fi
    echo

    # 3. 检查 WARP
    lang_echo "${Green}Cloudflare WARP 配置：${Font}" "${Green}Cloudflare WARP:${Font}"
    if command -v warp-cli >/dev/null 2>&1; then
        lang_echo "${Yellow}  WARP 是 CLI 工具，无直接编辑的配置文件。${Font}" "${Yellow}  WARP is CLI-only; no editable config file.${Font}"
        lang_echo "${Yellow}  查看设置: warp-cli settings${Font}" "${Yellow}  View settings: warp-cli settings${Font}"
        lang_echo "${Yellow}  检查连接: curl -x socks5://127.0.0.1:40000 https://ifconfig.me${Font}" "${Yellow}  Check connection: curl -x socks5://127.0.0.1:40000 https://ifconfig.me${Font}"
    else
        lang_echo "${Red}  未检测到 warp-cli${Font}" "${Red}  warp-cli not found${Font}"
    fi
    
    echo -e "${Blue}============================================${Font}"
}

# 初始化函数（优化版）
initialize() {
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}      One-Script      ${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    # 检查权限和环境
    check_root
    check_ovz
    
    # 系统环境检测
    check_system_environment
    check_cpu_vendor
    check_selinux
    
    # 安装基础工具
    install_basic_tools
    
    # 检查网络连接
    check_network_connectivity
    
    # 自动创建swap
    auto_create_swap
    
    echo -e "${Green}        ${Font}"
    sleep 2
}

# 系统工具菜单
bbr_management() {
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}           BBR 管理${Font}" "${Green}           BBR Management${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    # 检查当前状态
    local current_algo=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    local current_qdisc=$(sysctl net.core.default_qdisc 2>/dev/null | awk '{print $3}')
    
    lang_echo "${Yellow}当前 TCP 拥塞控制算法：${current_algo:-未知}${Font}" "${Yellow}Current TCP congestion control: ${current_algo:-unknown}${Font}"
    lang_echo "${Yellow}当前队列调度算法：${current_qdisc:-未知}${Font}" "${Yellow}Current queue discipline: ${current_qdisc:-unknown}${Font}"
    echo
    
    lang_echo "${Green}请选择操作：${Font}" "${Green}Choose an action:${Font}"
    lang_echo "${Yellow}1.${Font} 开启 BBR" "${Yellow}1.${Font} Enable BBR"
    lang_echo "${Yellow}2.${Font} 关闭 BBR (恢复默认 cubic)" "${Yellow}2.${Font} Disable BBR (restore cubic)"
    lang_echo "${Yellow}3.${Font} 返回上级菜单" "${Yellow}3.${Font} Back"
    echo
    
    read -p "$(lang_text "请输入选择 [1-3]: " "Choose [1-3]: ")" bbr_choice
    case $bbr_choice in
        1)
            lang_echo "${Green}正在开启 BBR...${Font}" "${Green}Enabling BBR...${Font}"
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
            lang_echo "${Green}BBR 已开启！${Font}" "${Green}BBR enabled!${Font}"
            ;;
        2)
            lang_echo "${Green}正在关闭 BBR...${Font}" "${Green}Disabling BBR...${Font}"
            sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
            sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
            
            # 恢复默认
            sysctl -w net.core.default_qdisc=fq_codel >/dev/null 2>&1
            sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null 2>&1
            
            lang_echo "${Green}BBR 已关闭，已恢复为 cubic。${Font}" "${Green}BBR disabled; restored to cubic.${Font}"
            ;;
        *)
            ;;
    esac
    read -p "$(lang_text "按回车键返回..." "Press Enter to return...")"
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
    lang_echo "${Yellow}9.${Font} BBR 管理" "${Yellow}9.${Font} BBR management"
    lang_echo "${Yellow}10.${Font} 返回主菜单" "${Yellow}10.${Font} Back to main menu"
    echo
    echo -e "${Blue}============================================${Font}"
    
    local choice
    while true; do
        read -p "$(lang_text "请选择操作 [1-10]: " "Choose an action [1-10]: ")" choice
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
                bbr_management
                break
                ;;
            10)
                echo -e "${Yellow}     ${Font}"
                return 0
                ;;
            *)
                echo -e "${Red}         1-10${Font}"
                ;;
        esac
    done
}

# 显示详细系统信息
show_system_info() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}                 ${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    # 基本系统信息
    echo -e "${Green}       ${Font}"
    echo -e "${Yellow}      $(hostname)${Font}"
    echo -e "${Yellow}     $(uname -o) $(uname -m)${Font}"
    echo -e "${Yellow}     $(uname -r)${Font}"
    echo -e "${Yellow}       $(uptime -p 2>/dev/null || uptime)${Font}"
    
    if [[ -f "/etc/os-release" ]]; then
        source /etc/os-release
        echo -e "${Yellow}      ${NAME} ${VERSION}${Font}"
    fi
    echo
    
    # CPU信息
    echo -e "${Green}CPU   ${Font}"
    if [[ -f "/proc/cpuinfo" ]]; then
        local cpu_model=$(grep "model name" /proc/cpuinfo | head -n1 | cut -d: -f2 | sed 's/^ *//')
        local cpu_cores=$(grep -c "^processor" /proc/cpuinfo)
        echo -e "${Yellow}  CPU   ${cpu_model}${Font}"
        echo -e "${Yellow}  CPU    ${cpu_cores}${Font}"
    fi
    echo
    
    # 内存信息
    echo -e "${Green}     ${Font}"
    if command -v free >/dev/null 2>&1; then
        free -h
    fi
    echo
    
    # 磁盘信息
    echo -e "${Green}       ${Font}"
    if command -v df >/dev/null 2>&1; then
        df -h
    fi
    echo
    
    # 网络接口信息
    echo -e "${Green}     ${Font}"
    if command -v ip >/dev/null 2>&1; then
        ip addr show | grep -E "(inet|inet6)" | grep -v "127.0.0.1" | grep -v "::1"
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig | grep -E "(inet|inet6)" | grep -v "127.0.0.1" | grep -v "::1"
    fi
    echo
    
    # 负载信息
    echo -e "${Green}     ${Font}"
    if [[ -f "/proc/loadavg" ]]; then
        echo -e "${Yellow}        $(cat /proc/loadavg)${Font}"
    fi
    echo
    
    read -p "            ..."
    system_tools_menu
}

# 网络诊断工具
network_diagnostic_tools() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}                 ${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    echo -e "${Green}       ${Font}"
    echo -e "${Yellow}1.${Font}       "
    echo -e "${Yellow}2.${Font} DNS    "
    echo -e "${Yellow}3.${Font}        "
    echo -e "${Yellow}4.${Font}       "
    echo -e "${Yellow}5.${Font}     "
    echo -e "${Yellow}6.${Font}       "
    echo
    
    local choice
    while true; do
        read -p "        [1-6]: " choice
        case $choice in
            1)
                echo -e "${Blue}        ...${Font}"
                echo -e "${Green}       ${Font}"
                ping -c 4 baidu.com 2>/dev/null && echo -e "${Green}        ${Font}" || echo -e "${Red}        ${Font}"
                echo -e "${Green}       ${Font}"
                ping -c 4 google.com 2>/dev/null && echo -e "${Green}        ${Font}" || echo -e "${Red}        ${Font}"
                ping -c 4 github.com 2>/dev/null && echo -e "${Green}  GitHub    ${Font}" || echo -e "${Red}  GitHub    ${Font}"
                break
                ;;
            2)
                echo -e "${Blue}    DNS  ...${Font}"
                if command -v dig >/dev/null 2>&1; then
                    echo -e "${Green}  dig  DNS   ${Font}"
                    dig @8.8.8.8 google.com +short
                    dig @1.1.1.1 cloudflare.com +short
                elif command -v nslookup >/dev/null 2>&1; then
                    echo -e "${Green}  nslookup  DNS   ${Font}"
                    nslookup google.com 8.8.8.8
                fi
                break
                ;;
            3)
                echo -e "${Blue}       ${Font}"
                read -p "           IP: " host
                read -p "         : " port
                if command -v nc >/dev/null 2>&1; then
                    nc -zv "$host" "$port" 2>&1
                elif command -v telnet >/dev/null 2>&1; then
                    timeout 5 telnet "$host" "$port"
                else
                    echo -e "${Red}   nc telnet  ${Font}"
                fi
                break
                ;;
            4)
                echo -e "${Blue}           speedtest-cli ${Font}"
                if command -v speedtest-cli >/dev/null 2>&1; then
                    speedtest-cli
                else
                    echo -e "${Yellow}      speedtest-cli...${Font}"
                    if command -v apt >/dev/null 2>&1; then
                        apt update && apt install -y speedtest-cli
                    elif command -v yum >/dev/null 2>&1; then
                        yum install -y speedtest-cli
                    else
                        echo -e "${Red}      speedtest-cli${Font}"
                    fi
                fi
                break
                ;;
            5)
                echo -e "${Blue}    ${Font}"
                read -p "           IP (  : google.com): " target
                target=${target:-google.com}
                if command -v traceroute >/dev/null 2>&1; then
                    traceroute "$target"
                elif command -v tracepath >/dev/null 2>&1; then
                    tracepath "$target"
                else
                    echo -e "${Red}   traceroute tracepath  ${Font}"
                fi
                break
                ;;
            6)
                system_tools_menu
                return
                ;;
            *)
                echo -e "${Red}         1-6${Font}"
                ;;
        esac
    done
    
    echo
    read -p "            ..."
    network_diagnostic_tools
}

# 性能监控
performance_monitoring() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}                ${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    echo -e "${Green}           ${Font}"
    
    # CPU使用率
    if command -v top >/dev/null 2>&1; then
        echo -e "${Yellow}CPU        ${Font}"
        top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print "CPU使用率: " 100-$1 "%"}'
    fi
    
    # 内存使用
    echo -e "${Yellow}       ${Font}"
    free -h
    echo
    
    # 磁盘I/O
    echo -e "${Yellow}       ${Font}"
    df -h
    echo
    
    # 进程信息
    echo -e "${Yellow}          CPU  ${Font}"
    ps aux --sort=-%cpu | head -6
    echo
    
    echo -e "${Yellow}              ${Font}"
    ps aux --sort=-%mem | head -6
    echo
    
    # 系统优化建议
    echo -e "${Green}       ${Font}"
    echo -e "${Yellow}1.${Font}       "
    echo -e "${Yellow}2.${Font}   Swap  "
    echo -e "${Yellow}3.${Font}       "
    
    local choice
    read -p "        [1-3]: " choice
    case $choice in
        1)
            echo -e "${Blue}        ...${Font}"
            sync
            echo 3 > /proc/sys/vm/drop_caches
            echo -e "${Green}        ${Font}"
            ;;
        2)
            echo -e "${Blue}  Swap   ${Font}"
            cat /proc/sys/vm/swappiness 2>/dev/null || echo "    swappiness  "
            read -p "     swappiness  (1-100,   10-60): " swappiness
            if [[ $swappiness =~ ^[0-9]+$ ]] && [[ $swappiness -ge 1 ]] && [[ $swappiness -le 100 ]]; then
                echo "vm.swappiness=$swappiness" >> /etc/sysctl.conf
                sysctl vm.swappiness=$swappiness
                echo -e "${Green}Swap     ${Font}"
            else
                echo -e "${Red}   swappiness ${Font}"
            fi
            ;;
        3)
            system_tools_menu
            return
            ;;
    esac
    
    echo
    read -p "            ..."
    system_tools_menu
}

# 防火墙管理（简化版）
firewall_management() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}                ${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    # 检测防火墙类型
    local firewall_type=""
    if command -v ufw >/dev/null 2>&1; then
        firewall_type="ufw"
        echo -e "${Green}    UFW    ${Font}"
        ufw status
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall_type="firewalld"
        echo -e "${Green}    Firewalld    ${Font}"
        firewall-cmd --state 2>/dev/null && firewall-cmd --list-all 2>/dev/null
    elif command -v iptables >/dev/null 2>&1; then
        firewall_type="iptables"
        echo -e "${Green}    IPTables${Font}"
        iptables -L INPUT -n --line-numbers | head -10
    else
        echo -e "${Yellow}            ${Font}"
    fi
    
    echo
    echo -e "${Green}        ${Font}"
    echo -e "${Yellow}1.${Font}        "
    echo -e "${Yellow}2.${Font}     "
    echo -e "${Yellow}3.${Font}     "
    echo -e "${Yellow}4.${Font}       "
    
    local choice
    read -p "      [1-4]: " choice
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
                    echo -e "${Red}         ${Font}"
                    ;;
            esac
            ;;
        2)
            read -p "         : " port
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
                        echo -e "${Green}iptables       ${Font}"
                    elif [[ -f /etc/iptables/rules.v4 ]] && command -v iptables-save >/dev/null 2>&1; then
                        iptables-save > /etc/iptables/rules.v4
                        echo -e "${Green}iptables       /etc/iptables/rules.v4${Font}"
                    else
                        echo -e "${Yellow}   iptables        ${Font}"
                    fi
                    ;;
                *)
                    echo -e "${Red}         ${Font}"
                    ;;
            esac
            ;;
        3)
            read -p "         : " port
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
                    echo -e "${Blue}  iptables INPUT   ${Font}"
                    iptables -L INPUT -n --line-numbers | grep "$port"
                    echo
                    echo -e "${Yellow}                ${Font}"
                    echo -e "${Blue}iptables -D INPUT <    >${Font}"
                    echo -e "${Yellow}     ${Font}"
                    echo -e "${Blue}iptables -D INPUT -p tcp --dport $port -j ACCEPT${Font}"
                    echo
                    read -p "            $port  ACCEPT   [y/N]: " auto_remove
                    if [[ $auto_remove =~ ^[Yy]$ ]]; then
                        iptables -D INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null
                        if command -v netfilter-persistent >/dev/null 2>&1; then
                            netfilter-persistent save
                            echo -e "${Green}iptables       ${Font}"
                        elif [[ -f /etc/iptables/rules.v4 ]] && command -v iptables-save >/dev/null 2>&1; then
                            iptables-save > /etc/iptables/rules.v4
                            echo -e "${Green}iptables       /etc/iptables/rules.v4${Font}"
                        fi
                        echo -e "${Green}   $port         ${Font}"
                    fi
                    ;;
                *)
                    echo -e "${Red}         ${Font}"
                    ;;
            esac
            ;;
        4)
            system_tools_menu
            return
            ;;
    esac
    
    echo
    read -p "           ..."
    firewall_management
}

# 服务管理
service_management() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}               ${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    echo -e "${Green}       ${Font}"
    
    # 检查常见服务
    local services=("nginx" "apache2" "ssh" "sshd" "docker" "mysql" "mariadb")
    
    for service in "${services[@]}"; do
        if systemctl list-unit-files | grep -q "^$service.service"; then
            local status=$(systemctl is-active "$service" 2>/dev/null)
            if [[ "$status" == "active" ]]; then
                echo -e "${Green}  $service:    ${Font}"
            else
                echo -e "${Yellow}  $service:    ${Font}"
            fi
        fi
    done
    
    echo
    echo -e "${Green}       ${Font}"
    echo -e "${Yellow}1.${Font}         "
    echo -e "${Yellow}2.${Font}     "
    echo -e "${Yellow}3.${Font}     "
    echo -e "${Yellow}4.${Font}     "
    echo -e "${Yellow}5.${Font}       "
    echo -e "${Yellow}6.${Font}       "
    
    local choice
    read -p "      [1-6]: " choice
    case $choice in
        1)
            systemctl list-unit-files --type=service | grep enabled | head -20
            ;;
        2)
            read -p "          : " service_name
            systemctl start "$service_name" && echo -e "${Green}      ${Font}" || echo -e "${Red}      ${Font}"
            ;;
        3)
            read -p "          : " service_name
            systemctl stop "$service_name" && echo -e "${Green}      ${Font}" || echo -e "${Red}      ${Font}"
            ;;
        4)
            read -p "          : " service_name
            systemctl restart "$service_name" && echo -e "${Green}      ${Font}" || echo -e "${Red}      ${Font}"
            ;;
        5)
            read -p "            : " service_name
            journalctl -u "$service_name" -n 50 --no-pager
            ;;
        6)
            system_tools_menu
            return
            ;;
    esac
    
    echo
    read -p "          ..."
    service_management
}

# 磁盘空间清理
disk_cleanup() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}                 ${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    echo -e "${Green}         ${Font}"
    df -h
    echo
    
    echo -e "${Green}     ${Font}"
    echo -e "${Yellow}1.${Font}   APT   (Debian/Ubuntu)"
    echo -e "${Yellow}2.${Font}   YUM   (CentOS/RHEL)"
    echo -e "${Yellow}3.${Font}       "
    echo -e "${Yellow}4.${Font}       "
    echo -e "${Yellow}5.${Font}      "
    echo -e "${Yellow}6.${Font}       "
    
    local choice
    read -p "        [1-6]: " choice
    case $choice in
        1)
            if command -v apt >/dev/null 2>&1; then
                echo -e "${Blue}    APT  ...${Font}"
                apt clean && apt autoremove -y && apt autoclean
                echo -e "${Green}APT      ${Font}"
            else
                echo -e "${Red}     APT    ${Font}"
            fi
            ;;
        2)
            if command -v yum >/dev/null 2>&1; then
                echo -e "${Blue}    YUM  ...${Font}"
                yum clean all
                echo -e "${Green}YUM      ${Font}"
            else
                echo -e "${Red}     YUM    ${Font}"
            fi
            ;;
        3)
            echo -e "${Blue}        ...${Font}"
            rm -rf /tmp/* 2>/dev/null
            rm -rf /var/tmp/* 2>/dev/null
            echo -e "${Green}        ${Font}"
            ;;
        4)
            echo -e "${Blue}        ...${Font}"
            journalctl --vacuum-time=7d 2>/dev/null
            find /var/log -name "*.log" -type f -mtime +7 -delete 2>/dev/null
            echo -e "${Green}        ${Font}"
            ;;
        5)
            echo -e "${Blue}    100MB   ...${Font}"
            find / -type f -size +100M -exec ls -lh {} \; 2>/dev/null | head -10
            ;;
        6)
            system_tools_menu
            return
            ;;
    esac
    
    echo
    echo -e "${Green}          ${Font}"
    df -h
    echo
    read -p "          ..."
    disk_cleanup
}

# 查看系统日志
view_system_logs() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}                 ${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    echo -e "${Green}       ${Font}"
    echo -e "${Yellow}1.${Font}        (syslog)"
    echo -e "${Yellow}2.${Font}        (dmesg)"
    echo -e "${Yellow}3.${Font}        (auth.log)"
    echo -e "${Yellow}4.${Font}        (boot.log)"
    echo -e "${Yellow}5.${Font}   journalctl  "
    echo -e "${Yellow}6.${Font}       "
    
    local choice
    read -p "          [1-6]: " choice
    case $choice in
        1)
            if [[ -f "/var/log/syslog" ]]; then
                echo -e "${Blue}  50      ${Font}"
                tail -50 /var/log/syslog
            elif [[ -f "/var/log/messages" ]]; then
                echo -e "${Blue}  50      ${Font}"
                tail -50 /var/log/messages
            else
                echo -e "${Red}         ${Font}"
            fi
            ;;
        2)
            echo -e "${Blue}     ${Font}"
            dmesg | tail -50
            ;;
        3)
            if [[ -f "/var/log/auth.log" ]]; then
                echo -e "${Blue}  50      ${Font}"
                tail -50 /var/log/auth.log
            elif [[ -f "/var/log/secure" ]]; then
                echo -e "${Blue}  50      ${Font}"
                tail -50 /var/log/secure
            else
                echo -e "${Red}         ${Font}"
            fi
            ;;
        4)
            if [[ -f "/var/log/boot.log" ]]; then
                echo -e "${Blue}     ${Font}"
                cat /var/log/boot.log
            else
                echo -e "${Red}         ${Font}"
            fi
            ;;
        5)
            if command -v journalctl >/dev/null 2>&1; then
                echo -e "${Blue}  50 journalctl   ${Font}"
                journalctl -n 50 --no-pager
            else
                echo -e "${Red}     journalctl${Font}"
            fi
            ;;
        6)
            system_tools_menu
            return
            ;;
    esac
    
    echo
    read -p "          ..."
    view_system_logs
}

# 时间同步设置
time_sync_setup() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}                 ${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    echo -e "${Green}       ${Font}"
    echo -e "${Yellow}       $(date)${Font}"
    echo -e "${Yellow}     $(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "unknown")${Font}"
    echo
    
    if command -v timedatectl >/dev/null 2>&1; then
        echo -e "${Green}       ${Font}"
        timedatectl status
        echo
    fi
    
    echo -e "${Green}       ${Font}"
    echo -e "${Yellow}1.${Font}     "
    echo -e "${Yellow}2.${Font}   NTP    "
    echo -e "${Yellow}3.${Font}       "
    echo -e "${Yellow}4.${Font}       "
    
    local choice
    read -p "      [1-4]: " choice
    case $choice in
        1)
            echo -e "${Blue}     ${Font}"
            echo -e "${Yellow}  Asia/Shanghai (    )${Font}"
            echo -e "${Yellow}  UTC (     )${Font}"
            echo -e "${Yellow}  America/New_York (    )${Font}"
            echo -e "${Yellow}  Europe/London (    )${Font}"
            read -p "      (  : Asia/Shanghai): " timezone
            if command -v timedatectl >/dev/null 2>&1; then
                timedatectl set-timezone "$timezone" && echo -e "${Green}      ${Font}" || echo -e "${Red}      ${Font}"
            else
                echo "$timezone" > /etc/timezone && echo -e "${Green}      ${Font}" || echo -e "${Red}      ${Font}"
            fi
            ;;
        2)
            if command -v timedatectl >/dev/null 2>&1; then
                timedatectl set-ntp true && echo -e "${Green}NTP       ${Font}" || echo -e "${Red}NTP        ${Font}"
            elif command -v ntpdate >/dev/null 2>&1; then
                ntpdate -s pool.ntp.org && echo -e "${Green}      ${Font}" || echo -e "${Red}      ${Font}"
            else
                echo -e "${Red}     NTP    ${Font}"
            fi
            ;;
        3)
            if command -v ntpdate >/dev/null 2>&1; then
                echo -e "${Blue}        ...${Font}"
                ntpdate pool.ntp.org && echo -e "${Green}      ${Font}" || echo -e "${Red}      ${Font}"
            elif command -v chrony >/dev/null 2>&1; then
                chrony sources -v
            else
                echo -e "${Red}         ${Font}"
            fi
            ;;
        4)
            system_tools_menu
            return
            ;;
    esac
    
    echo
    read -p "            ..."
    time_sync_setup
}

# 主函数
main() {
    # 处理命令行参数
    case "${1:-}" in
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
    echo -e "${Green}      One-Script       ${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    echo -e "${Green}   ${Font}"
    echo -e "  $(basename "$0") [  ]"
    echo
    echo -e "${Green}   ${Font}"
    echo -e "  ${Yellow}--help, -h${Font}                     "
    echo -e "  ${Yellow}--version, -v${Font}                 "
    echo -e "  ${Yellow}--install-command${Font}              (v2ray)"
    echo -e "  ${Yellow}--uninstall-command${Font}           "
    echo
    echo -e "${Green}     ${Font}"
    echo -e "         '${Yellow}v2ray${Font}'       "
    echo -e "       ${Yellow}sudo v2ray${Font}"
    echo -e "     ${Yellow}              ${Font}"
    echo
    echo -e "${Green}     ${Font}"
    echo -e "       Swap     "
    echo -e "Please follow the on-screen instructions."
    echo -e "    V2Ray       "
    echo -e "Please follow the on-screen instructions."
    echo -e "Please follow the on-screen instructions."
    echo -e "       iptables     "
    echo -e "Please follow the on-screen instructions."
    echo
    echo -e "${Green}GitHub   ${Font}https://github.com/charleslkx/one-script"
    echo -e "${Blue}============================================${Font}"
}

# 更新 main.sh 脚本
update_main_script() {
    lang_echo "${Blue}正在检查 main.sh 更新...${Font}" "${Blue}Checking for main.sh updates...${Font}"
    
    local base_url="https://raw.githubusercontent.com/charleslkx/one-script/master"
    local script_path="$0"
    local temp_script="/tmp/main_new.sh"
    
    # 获取当前脚本版本信息
    lang_echo "${Green}当前脚本路径: ${script_path}${Font}" "${Green}Current script: ${script_path}${Font}"
    echo
    
    # 显示更新选项
    lang_echo "${Green}更新选项:${Font}" "${Green}Update options:${Font}"
    lang_echo "${Yellow}1.${Font} 检查并更新（推荐）" "${Yellow}1.${Font} Check and update (recommended)"
    lang_echo "${Yellow}2.${Font} 强制更新" "${Yellow}2.${Font} Force update"
    lang_echo "${Yellow}3.${Font} 查看版本信息" "${Yellow}3.${Font} Show version info"
    lang_echo "${Yellow}4.${Font} 取消" "${Yellow}4.${Font} Cancel"
    echo
    
    local choice
    while true; do
        read -p "$(lang_text "请选择 [1-4]: " "Choose [1-4]: ")" choice
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
                lang_echo "${Yellow}已取消更新${Font}" "${Yellow}Update cancelled${Font}"
                return 0
                ;;
            *)
                lang_echo "${Red}无效选择，请输入 1-4${Font}" "${Red}Invalid choice, enter 1-4${Font}"
                ;;
        esac
    done
}

# 检查并更新脚本
check_and_update() {
    lang_echo "${Blue}正在检查更新...${Font}" "${Blue}Checking for updates...${Font}"
    
    local base_url="https://raw.githubusercontent.com/charleslkx/one-script/master"
    local script_path="$0"
    local temp_script="/tmp/main_new.sh"
    
    # 下载最新版本
    if wget -qO "$temp_script" "${base_url}/main.sh" 2>/dev/null || curl -fsSL "${base_url}/main.sh" -o "$temp_script" 2>/dev/null; then
        lang_echo "${Green}下载成功${Font}" "${Green}Download successful${Font}"
        
        # 比较文件
        if ! diff -q "$script_path" "$temp_script" >/dev/null 2>&1; then
            lang_echo "${Yellow}发现新版本，正在更新...${Font}" "${Yellow}New version found, updating...${Font}"
            perform_update "$script_path" "$temp_script"
        else
            lang_echo "${Green}已经是最新版本${Font}" "${Green}Already up to date${Font}"
            rm -f "$temp_script"
        fi
    else
        lang_echo "${Red}下载失败，请检查网络连接${Font}" "${Red}Download failed, check network${Font}"
    fi
}

# 强制更新脚本
force_update() {
    lang_echo "${Yellow}正在强制更新...${Font}" "${Yellow}Forcing update...${Font}"
    
    local base_url="https://raw.githubusercontent.com/charleslkx/one-script/master"
    local script_path="$0"
    local temp_script="/tmp/main_new.sh"
    
    # 下载最新版本
    if wget -qO "$temp_script" "${base_url}/main.sh" 2>/dev/null || curl -fsSL "${base_url}/main.sh" -o "$temp_script" 2>/dev/null; then
        lang_echo "${Green}下载成功${Font}" "${Green}Download successful${Font}"
        perform_update "$script_path" "$temp_script"
    else
        lang_echo "${Red}下载失败，请检查网络连接${Font}" "${Red}Download failed, check network${Font}"
    fi
}

# 执行更新操作
perform_update() {
    local script_path="$1"
    local temp_script="$2"
    
    # 直接更新脚本
    echo -e "${Blue}      ...${Font}"
    if cp "$temp_script" "$script_path" && chmod +x "$script_path"; then
        echo -e "${Green}       ${Font}"
        rm -f "$temp_script"
        
        echo -e "${Yellow}                   ${Font}"
        echo -e "${Blue}           [y/N]:${Font}"
        read -p "" restart_choice
        if [[ $restart_choice =~ ^[Yy]$ ]]; then
            echo -e "${Green}        ...${Font}"
            exec "$script_path"
        fi
    else
        echo -e "${Red}       ${Font}"
        rm -f "$temp_script"
    fi
}

# 显示版本信息
show_version_info() {
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}       One-Script     ${Font}"
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}     ${Font}One-Script       "
    echo -e "${Green}     ${Font}$0"
    echo -e "${Green}     ${Font}$(stat -c %y "$0" 2>/dev/null || echo "unknown")"
    echo -e "${Green}     ${Font}$(stat -c %s "$0" 2>/dev/null || echo "unknown")   "
    echo -e "${Green}GitHub   ${Font}https://github.com/charleslkx/one-script"
    echo
    echo -e "${Green}     ${Font}"
    echo -e "       Swap     "
    echo -e "Please follow the on-screen instructions."  
    echo -e "    V2Ray       "
    echo -e "Please follow the on-screen instructions."
    echo -e "Please follow the on-screen instructions."
    echo -e "       iptables     "
    echo -e "Please follow the on-screen instructions."
    echo -e "${Blue}============================================${Font}"
    echo
}

# 命令管理菜单
command_management() {
    clear
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}               ${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    local command_name="v2ray"
    local found=false
    
    # 检查命令状态
    echo -e "${Green}         ${Font}"
    
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
        echo -e "${Green}     ${Font}           "
        echo -e "${Green}     ${Font}${command_name}   sudo ${command_name}"
        echo -e "${Yellow}                  ${Font}"
    else
        echo -e "${Yellow}     ${Font}   "
    fi
    
    echo
    echo -e "${Green}       ${Font}"
    echo -e "${Yellow}1.${Font}          (${command_name})"
    echo -e "${Yellow}2.${Font}         "
    echo -e "${Yellow}3.${Font}       "
    echo -e "${Yellow}4.${Font}      "
    echo
    echo -e "${Blue}============================================${Font}"
    
    local choice
    while true; do
        read -p "      [1-4]: " choice
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
                echo -e "${Yellow}     ${Font}"
                return 0
                ;;
            *)
                echo -e "${Red}         1-4${Font}"
                ;;
        esac
    done
}

# 显示命令状态
show_command_status() {
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}                 ${Font}"
    echo -e "${Blue}============================================${Font}"
    
    local command_name="v2ray"
    local script_path="$(readlink -f "$0")"
    local found=false
    
    echo -e "${Green}       ${Font}${script_path}"
    echo -e "${Green}       ${Font}${command_name}"
    echo
    
    # 检查各个位置的命令
    echo -e "${Green}       ${Font}"
    
    if [[ -f "/usr/bin/${command_name}" ]]; then
        echo -e "${Green}  /usr/bin/${command_name} ✓${Font}"
        echo -e "${Green}       $(readlink "/usr/bin/${command_name}" 2>/dev/null || echo "unreadable")${Font}"
        found=true
    else
        echo -e "${Yellow}  /usr/bin/${command_name} ✗${Font}"
    fi
    
    if [[ -f "/usr/sbin/${command_name}" ]]; then
        echo -e "${Green}  /usr/sbin/${command_name} ✓${Font}"
        echo -e "${Green}       $(readlink "/usr/sbin/${command_name}" 2>/dev/null || echo "unreadable")${Font}"
        found=true
    else
        echo -e "${Yellow}  /usr/sbin/${command_name} ✗${Font}"
    fi
    
    if [[ -f "/usr/local/bin/${command_name}" ]]; then
        echo -e "${Green}  /usr/local/bin/${command_name} ✓${Font}"
        echo -e "${Green}       $(readlink "/usr/local/bin/${command_name}" 2>/dev/null || echo "unreadable")${Font}"
        found=true
    else
        echo -e "${Yellow}  /usr/local/bin/${command_name} ✗${Font}"
    fi
    
    echo
    if [[ "$found" == "true" ]]; then
        echo -e "${Green}     ${Font}             "
        echo
        echo -e "${Green}     ${Font}"
        echo -e "  ${Blue}${command_name}${Font}                #            "
        echo -e "  ${Blue}sudo ${command_name}${Font}           #  root         "
        echo -e "  ${Blue}${command_name} --help${Font}         #       "
        echo -e "  ${Blue}${command_name} --version${Font}      #       "
        echo
        echo -e "${Green}   ${Font}"
        echo -e "Please follow the on-screen instructions."
        echo -e "Please follow the on-screen instructions."
        echo -e "Please follow the on-screen instructions."
    else
        echo -e "${Yellow}     ${Font}   "
        echo
        echo -e "${Yellow}       ${Font}"
        echo -e "  ${Blue}sudo ${command_name}${Font}           #        "
    fi
    
    echo
    echo -e "${Yellow}PATH      ${Font}"
    echo -e "${Blue}$(echo $PATH | tr ':' '\n' | grep -E '(usr/bin|usr/sbin|usr/local/bin)' || echo "no matching paths found")${Font}"
    
    echo -e "${Blue}============================================${Font}"
    echo
}

# ============================================
# VLESS Blue-Green Deployment Functions
# ============================================

# Check if VLESS blue-green is installed
check_vless_installed() {
    [[ -f "/etc/systemd/system/vless-instance-a.service" ]] && \
    [[ -f "/etc/systemd/system/vless-instance-b.service" ]] && \
    [[ -f "/usr/local/bin/switch-traffic.sh" ]]
}

# Install VLESS Blue-Green system
install_vless_bluegreen() {
    clear
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}    VLESS Blue-Green Deployment Installation${Font}" "${Green}    VLESS Blue-Green Deployment Installation${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    if check_vless_installed; then
        lang_echo "${Yellow}VLESS Blue-Green system is already installed!${Font}" "${Yellow}VLESS Blue-Green system is already installed!${Font}"
        echo
        lang_echo "${Yellow}Current status:${Font}" "${Yellow}Current status:${Font}"
        systemctl is-active vless-instance-a.service &>/dev/null && \
            echo -e "  Instance A: ${Green}active${Font}" || echo -e "  Instance A: ${Red}inactive${Font}"
        systemctl is-active vless-instance-b.service &>/dev/null && \
            echo -e "  Instance B: ${Green}active${Font}" || echo -e "  Instance B: ${Red}inactive${Font}"
        systemctl is-active vless-monitor.service &>/dev/null && \
            echo -e "  Monitor: ${Green}active${Font}" || echo -e "  Monitor: ${Red}inactive${Font}"
        echo
        read -p "$(lang_text "按回车键继续..." "Press Enter to continue...")"
        return
    fi
    
    lang_echo "${Green}Starting VLESS Blue-Green installation...${Font}" "${Green}Starting VLESS Blue-Green installation...${Font}"
    echo
    
    # Step 1: Install dependencies
    lang_echo "${Yellow}[1/9]${Font} Installing system dependencies..." "${Yellow}[1/9]${Font} Installing system dependencies..."
    apt-get update -qq
    apt-get install -y curl wget unzip netcat-openbsd jq systemd >/dev/null 2>&1
    lang_echo "${Green}✓ Dependencies installed${Font}" "${Green}✓ Dependencies installed${Font}"
    
    # Step 2: Install Xray-core
    lang_echo "${Yellow}[2/9]${Font} Installing Xray-core..." "${Yellow}[2/9]${Font} Installing Xray-core..."
    if [ ! -f /usr/local/bin/xray ]; then
        LATEST_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) XRAY_ARCH="linux-64" ;;
            aarch64) XRAY_ARCH="linux-arm64-v8a" ;;
            armv7l) XRAY_ARCH="linux-arm32-v7a" ;;
            *) lang_echo "${Red}Unsupported architecture: $ARCH${Font}" "${Red}Unsupported architecture: $ARCH${Font}"; return 1 ;;
        esac
        
        DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/download/${LATEST_VERSION}/Xray-${XRAY_ARCH}.zip"
        cd /tmp
        wget -q --show-progress "$DOWNLOAD_URL" -O xray.zip
        unzip -q xray.zip
        mv xray /usr/local/bin/
        chmod +x /usr/local/bin/xray
        mkdir -p /usr/local/share/xray
        mv geoip.dat geosite.dat /usr/local/share/xray/ 2>/dev/null || true
        rm -f xray.zip
        lang_echo "${Green}✓ Xray-core $LATEST_VERSION installed${Font}" "${Green}✓ Xray-core $LATEST_VERSION installed${Font}"
    else
        lang_echo "${Green}✓ Xray-core already installed${Font}" "${Green}✓ Xray-core already installed${Font}"
    fi
    
    # Step 3: Create vless user
    lang_echo "${Yellow}[3/9]${Font} Creating vless system user..." "${Yellow}[3/9]${Font} Creating vless system user..."
    if ! id "vless" &>/dev/null; then
        useradd -r -s /bin/false vless
        lang_echo "${Green}✓ User 'vless' created${Font}" "${Green}✓ User 'vless' created${Font}"
    else
        lang_echo "${Green}✓ User 'vless' already exists${Font}" "${Green}✓ User 'vless' already exists${Font}"
    fi
    
    # Step 4: Create directories
    lang_echo "${Yellow}[4/9]${Font} Creating directory structure..." "${Yellow}[4/9]${Font} Creating directory structure..."
    mkdir -p /etc/vless /var/log/vless /usr/local/bin
    chown vless:vless /var/log/vless
    chmod 755 /var/log/vless
    lang_echo "${Green}✓ Directories created${Font}" "${Green}✓ Directories created${Font}"
    
    # Step 5: Create config files
    lang_echo "${Yellow}[5/9]${Font} Creating configuration files..." "${Yellow}[5/9]${Font} Creating configuration files..."
    local script_dir="$(dirname "$(readlink -f "$0")")"
    
    # Generate UUID and keys
    local uuid=$(/usr/local/bin/xray uuid)
    local keypair=$(/usr/local/bin/xray x25519)
    local private_key=$(echo "$keypair" | grep "Private key:" | awk '{print $3}')
    
    # Create config-a.json
    cat > /etc/vless/config-a.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 10080,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.microsoft.com:443",
          "serverNames": ["www.microsoft.com"],
          "privateKey": "$private_key",
          "shortIds": [""]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
EOF
    
    # Create config-b.json (same but port 10081)
    cat > /etc/vless/config-b.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 10081,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.microsoft.com:443",
          "serverNames": ["www.microsoft.com"],
          "privateKey": "$private_key",
          "shortIds": [""]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
EOF
    
    chown -R vless:vless /etc/vless
    chmod 600 /etc/vless/*.json
    lang_echo "${Green}✓ Configuration files created (UUID: $uuid)${Font}" "${Green}✓ Configuration files created (UUID: $uuid)${Font}"
    
    # Step 6: Install systemd service files
    lang_echo "${Yellow}[6/9]${Font} Installing systemd services..." "${Yellow}[6/9]${Font} Installing systemd services..."
    for service in vless-instance-a.service vless-instance-b.service vless-monitor.service; do
        if [[ -f "$script_dir/$service" ]]; then
            cp "$script_dir/$service" /etc/systemd/system/
            chmod 644 /etc/systemd/system/$service
        fi
    done
    lang_echo "${Green}✓ Systemd services installed${Font}" "${Green}✓ Systemd services installed${Font}"
    
    # Step 7: Install scripts
    lang_echo "${Yellow}[7/9]${Font} Installing management scripts..." "${Yellow}[7/9]${Font} Installing management scripts..."
    for script in switch-traffic.sh monitor-vless.sh; do
        if [[ -f "$script_dir/$script" ]]; then
            cp "$script_dir/$script" /usr/local/bin/
            chmod 755 /usr/local/bin/$script
        fi
    done
    lang_echo "${Green}✓ Management scripts installed${Font}" "${Green}✓ Management scripts installed${Font}"
    
    # Step 8: Setup firewall
    lang_echo "${Yellow}[8/9]${Font} Setting up port forwarding..." "${Yellow}[8/9]${Font} Setting up port forwarding..."
    if command -v nft &> /dev/null; then
        if [[ -f "$script_dir/setup-nftables.sh" ]]; then
            bash "$script_dir/setup-nftables.sh" >/dev/null 2>&1
            lang_echo "${Green}✓ nftables configured${Font}" "${Green}✓ nftables configured${Font}"
        fi
    elif command -v iptables &> /dev/null; then
        if [[ -f "$script_dir/iptables-vless.sh" ]]; then
            bash "$script_dir/iptables-vless.sh" install >/dev/null 2>&1
            lang_echo "${Green}✓ iptables configured${Font}" "${Green}✓ iptables configured${Font}"
        fi
    fi
    
    # Step 9: Enable and start services
    lang_echo "${Yellow}[9/9]${Font} Enabling and starting services..." "${Yellow}[9/9]${Font} Enabling and starting services..."
    systemctl daemon-reload
    systemctl enable vless-instance-a.service vless-instance-b.service vless-monitor.service >/dev/null 2>&1
    systemctl start vless-instance-a.service vless-instance-b.service
    sleep 2
    systemctl start vless-monitor.service
    lang_echo "${Green}✓ Services enabled and started (will auto-start on reboot)${Font}" "${Green}✓ Services enabled and started (will auto-start on reboot)${Font}"
    
    echo
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}Installation Complete!${Font}" "${Green}Installation Complete!${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    lang_echo "${Yellow}Important Information:${Font}" "${Yellow}Important Information:${Font}"
    echo -e "  UUID: ${Green}$uuid${Font}"
    echo -e "  Config A: ${Blue}/etc/vless/config-a.json${Font} (Port 10080)"
    echo -e "  Config B: ${Blue}/etc/vless/config-b.json${Font} (Port 10081)"
    echo -e "  Active: ${Green}Instance A${Font} (443 -> 10080)"
    echo
    lang_echo "${Yellow}Services are now running and will auto-start on reboot${Font}" "${Yellow}Services are now running and will auto-start on reboot${Font}"
    echo
    read -p "$(lang_text "按回车键继续..." "Press Enter to continue...")"
}

# Uninstall VLESS Blue-Green system
uninstall_vless_bluegreen() {
    clear
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Red}    VLESS Blue-Green Uninstallation${Font}" "${Red}    VLESS Blue-Green Uninstallation${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    if ! check_vless_installed; then
        lang_echo "${Yellow}VLESS Blue-Green system is not installed.${Font}" "${Yellow}VLESS Blue-Green system is not installed.${Font}"
        read -p "$(lang_text "按回车键继续..." "Press Enter to continue...")"
        return
    fi
    
    lang_echo "${Yellow}This will completely remove VLESS Blue-Green deployment.${Font}" "${Yellow}This will completely remove VLESS Blue-Green deployment.${Font}"
    lang_echo "${Red}WARNING: All configuration and data will be deleted!${Font}" "${Red}WARNING: All configuration and data will be deleted!${Font}"
    echo
    read -p "$(lang_text "确认删除? (y/N): " "Confirm uninstall? (y/N): ")" confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        lang_echo "${Green}Uninstall cancelled${Font}" "${Green}Uninstall cancelled${Font}"
        read -p "$(lang_text "按回车键继续..." "Press Enter to continue...")"
        return
    fi
    
    echo
    lang_echo "${Yellow}Stopping and disabling services...${Font}" "${Yellow}Stopping and disabling services...${Font}"
    systemctl stop vless-instance-a.service vless-instance-b.service vless-monitor.service 2>/dev/null || true
    systemctl disable vless-instance-a.service vless-instance-b.service vless-monitor.service 2>/dev/null || true
    lang_echo "${Green}✓ Services stopped and disabled${Font}" "${Green}✓ Services stopped and disabled${Font}"
    
    lang_echo "${Yellow}Removing systemd service files...${Font}" "${Yellow}Removing systemd service files...${Font}"
    rm -f /etc/systemd/system/vless-instance-a.service
    rm -f /etc/systemd/system/vless-instance-b.service
    rm -f /etc/systemd/system/vless-monitor.service
    systemctl daemon-reload
    lang_echo "${Green}✓ Service files removed${Font}" "${Green}✓ Service files removed${Font}"
    
    lang_echo "${Yellow}Removing management scripts...${Font}" "${Yellow}Removing management scripts...${Font}"
    rm -f /usr/local/bin/switch-traffic.sh
    rm -f /usr/local/bin/monitor-vless.sh
    lang_echo "${Green}✓ Scripts removed${Font}" "${Green}✓ Scripts removed${Font}"
    
    lang_echo "${Yellow}Removing configuration files...${Font}" "${Yellow}Removing configuration files...${Font}"
    rm -rf /etc/vless
    rm -rf /var/log/vless
    rm -rf /var/run/vless-monitor
    lang_echo "${Green}✓ Configuration removed${Font}" "${Green}✓ Configuration removed${Font}"
    
    lang_echo "${Yellow}Cleaning firewall rules...${Font}" "${Yellow}Cleaning firewall rules...${Font}"
    if command -v nft &> /dev/null; then
        nft delete table nat 2>/dev/null || true
    fi
    if command -v iptables &> /dev/null; then
        iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 10080 2>/dev/null || true
        iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 10081 2>/dev/null || true
        if command -v netfilter-persistent &> /dev/null; then
            netfilter-persistent save 2>/dev/null || true
        fi
    fi
    lang_echo "${Green}✓ Firewall rules cleaned${Font}" "${Green}✓ Firewall rules cleaned${Font}"
    
    lang_echo "${Yellow}Note: Xray-core binary and vless user are kept (may be used by other services)${Font}" "${Yellow}Note: Xray-core binary and vless user are kept (may be used by other services)${Font}"
    
    echo
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}Uninstallation Complete!${Font}" "${Green}Uninstallation Complete!${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    read -p "$(lang_text "按回车键继续..." "Press Enter to continue...")"
}

# VLESS Blue-Green management menu
vless_bluegreen_menu() {
    while true; do
        clear
        echo -e "${Blue}============================================${Font}"
        lang_echo "${Green}    VLESS 蓝绿部署管理${Font}" "${Green}    VLESS Blue-Green Management${Font}"
        echo -e "${Blue}============================================${Font}"
        echo
        
        # Show current status
        if check_vless_installed; then
            lang_echo "${Green}系统状态:${Font}" "${Green}System Status:${Font}"
            
            # Check active instance
            if command -v nft &> /dev/null && nft list ruleset 2>/dev/null | grep -q "dnat to :10080"; then
                echo -e "  ${Yellow}活动实例:${Font} ${Green}Instance A (10080)${Font}" 
            elif command -v nft &> /dev/null && nft list ruleset 2>/dev/null | grep -q "dnat to :10081"; then
                echo -e "  ${Yellow}活动实例:${Font} ${Green}Instance B (10081)${Font}"
            elif command -v iptables &> /dev/null && iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "redir ports 10080"; then
                echo -e "  ${Yellow}活动实例:${Font} ${Green}Instance A (10080)${Font}"
            elif command -v iptables &> /dev/null && iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "redir ports 10081"; then
                echo -e "  ${Yellow}活动实例:${Font} ${Green}Instance B (10081)${Font}"
            else
                echo -e "  ${Yellow}活动实例:${Font} ${Red}Unknown${Font}"
            fi
            
            # Service status
            systemctl is-active vless-instance-a.service &>/dev/null && \
                echo -e "  ${Yellow}Instance A:${Font} ${Green}running${Font}" || echo -e "  ${Yellow}Instance A:${Font} ${Red}stopped${Font}"
            systemctl is-active vless-instance-b.service &>/dev/null && \
                echo -e "  ${Yellow}Instance B:${Font} ${Green}running${Font}" || echo -e "  ${Yellow}Instance B:${Font} ${Red}stopped${Font}"
            systemctl is-active vless-monitor.service &>/dev/null && \
                echo -e "  ${Yellow}Monitor:${Font} ${Green}running${Font}" || echo -e "  ${Yellow}Monitor:${Font} ${Red}stopped${Font}"
            echo
        else
            lang_echo "${Red}系统未安装${Font}" "${Red}System not installed${Font}"
            echo
        fi
        
        lang_echo "${Green}请选择操作:${Font}" "${Green}Select operation:${Font}"
        echo
        
        if check_vless_installed; then
            lang_echo "${Yellow}1.${Font}  切换到 Instance A (10080)" "${Yellow}1.${Font}  Switch to Instance A (10080)"
            lang_echo "${Yellow}2.${Font}  切换到 Instance B (10081)" "${Yellow}2.${Font}  Switch to Instance B (10081)"
            lang_echo "${Yellow}3.${Font}  查看详细状态" "${Yellow}3.${Font}  View detailed status"
            lang_echo "${Yellow}4.${Font}  查看监控日志" "${Yellow}4.${Font}  View monitor logs"
            lang_echo "${Yellow}5.${Font}  启动所有服务" "${Yellow}5.${Font}  Start all services"
            lang_echo "${Yellow}6.${Font}  停止所有服务" "${Yellow}6.${Font}  Stop all services"
            lang_echo "${Yellow}7.${Font}  重启所有服务" "${Yellow}7.${Font}  Restart all services"
            lang_echo "${Yellow}8.${Font}  查看配置信息" "${Yellow}8.${Font}  View configuration"
            lang_echo "${Yellow}9.${Font}  ${Red}卸载系统${Font}" "${Yellow}9.${Font}  ${Red}Uninstall system${Font}"
            lang_echo "${Yellow}10.${Font} 返回主菜单" "${Yellow}10.${Font} Back to main menu"
        else
            lang_echo "${Yellow}1.${Font}  安装蓝绿部署系统" "${Yellow}1.${Font}  Install Blue-Green system"
            lang_echo "${Yellow}2.${Font}  返回主菜单" "${Yellow}2.${Font}  Back to main menu"
        fi
        
        echo
        echo -e "${Blue}============================================${Font}"
        
        if check_vless_installed; then
            read -p "$(lang_text "请输入选项 [1-10]: " "Enter option [1-10]: ")" vless_choice
        else
            read -p "$(lang_text "请输入选项 [1-2]: " "Enter option [1-2]: ")" vless_choice
        fi
        
        if check_vless_installed; then
            case $vless_choice in
                1)
                    lang_echo "${Green}正在切换到 Instance A...${Font}" "${Green}Switching to Instance A...${Font}"
                    if /usr/local/bin/switch-traffic.sh a; then
                        lang_echo "${Green}✓ 已切换到 Instance A${Font}" "${Green}✓ Switched to Instance A${Font}"
                    else
                        lang_echo "${Red}切换失败${Font}" "${Red}Switch failed${Font}"
                    fi
                    sleep 2
                    ;;
                2)
                    lang_echo "${Green}正在切换到 Instance B...${Font}" "${Green}Switching to Instance B...${Font}"
                    if /usr/local/bin/switch-traffic.sh b; then
                        lang_echo "${Green}✓ 已切换到 Instance B${Font}" "${Green}✓ Switched to Instance B${Font}"
                    else
                        lang_echo "${Red}切换失败${Font}" "${Red}Switch failed${Font}"
                    fi
                    sleep 2
                    ;;
                3)
                    /usr/local/bin/switch-traffic.sh status
                    echo
                    read -p "$(lang_text "按回车键继续..." "Press Enter to continue...")"
                    ;;
                4)
                    lang_echo "${Green}显示监控日志 (Ctrl+C 退出)...${Font}" "${Green}Showing monitor logs (Ctrl+C to exit)...${Font}"
                    journalctl -u vless-monitor.service -f
                    ;;
                5)
                    lang_echo "${Green}正在启动所有服务...${Font}" "${Green}Starting all services...${Font}"
                    systemctl start vless-instance-a.service vless-instance-b.service vless-monitor.service
                    lang_echo "${Green}✓ 服务已启动${Font}" "${Green}✓ Services started${Font}"
                    sleep 2
                    ;;
                6)
                    lang_echo "${Yellow}正在停止所有服务...${Font}" "${Yellow}Stopping all services...${Font}"
                    systemctl stop vless-instance-a.service vless-instance-b.service vless-monitor.service
                    lang_echo "${Green}✓ 服务已停止${Font}" "${Green}✓ Services stopped${Font}"
                    sleep 2
                    ;;
                7)
                    lang_echo "${Green}正在重启所有服务...${Font}" "${Green}Restarting all services...${Font}"
                    systemctl restart vless-instance-a.service vless-instance-b.service vless-monitor.service
                    lang_echo "${Green}✓ 服务已重启${Font}" "${Green}✓ Services restarted${Font}"
                    sleep 2
                    ;;
                8)
                    clear
                    echo -e "${Blue}============================================${Font}"
                    lang_echo "${Green}    配置信息${Font}" "${Green}    Configuration Info${Font}"
                    echo -e "${Blue}============================================${Font}"
                    echo
                    if [[ -f /etc/vless/config-a.json ]]; then
                        local uuid=$(grep '"id"' /etc/vless/config-a.json | head -1 | awk -F'"' '{print $4}')
                        echo -e "${Yellow}UUID:${Font} ${Green}$uuid${Font}"
                        echo -e "${Yellow}Config A:${Font} ${Blue}/etc/vless/config-a.json${Font} (Port 10080)"
                        echo -e "${Yellow}Config B:${Font} ${Blue}/etc/vless/config-b.json${Font} (Port 10081)"
                        echo -e "${Yellow}External Port:${Font} ${Blue}443${Font}"
                        echo
                        lang_echo "${Yellow}编辑配置:${Font} sudo nano /etc/vless/config-a.json" "${Yellow}Edit config:${Font} sudo nano /etc/vless/config-a.json"
                    fi
                    echo
                    read -p "$(lang_text "按回车键继续..." "Press Enter to continue...")"
                    ;;
                9)
                    uninstall_vless_bluegreen
                    ;;
                10)
                    return
                    ;;
                *)
                    lang_echo "${Red}无效选项${Font}" "${Red}Invalid option${Font}"
                    sleep 1
                    ;;
            esac
        else
            case $vless_choice in
                1)
                    install_vless_bluegreen
                    ;;
                2)
                    return
                    ;;
                *)
                    lang_echo "${Red}无效选项${Font}" "${Red}Invalid option${Font}"
                    sleep 1
                    ;;
            esac
        fi
    done
}

# ============================================
# End of VLESS Blue-Green Functions
# ============================================

# 启动脚本
main "$@"
