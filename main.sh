#!/usr/bin/env bash
#One-Script 主启动脚本 - 自动管理虚拟内存并提供脚本选择

# 颜色定义
Green="\033[32m"
Font="\033[0m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[34m"

lang_text() {
    local zh="$1"
    printf "%b" "${zh}"
}

lang_echo() {
    local zh="$1"
    echo -e "${zh}"
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
    echo -e "${Blue}正在安装简易命令...${Font}"
    
    local command_name="v2ray"
    local base_url="https://raw.githubusercontent.com/charleslkx/one-script/master"
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
BASE_URL="https://raw.githubusercontent.com/charleslkx/one-script/master"

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
    local command_name="v2ray"
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

# 安装基础工具包
install_basic_tools() {
    echo -e "${Blue}正在安装基础工具包...${Font}"
    
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
                
                # 设置swappiness（建议值10-60，默认60）
                local swappiness=10
                echo "vm.swappiness=${swappiness}" >> /etc/sysctl.conf
                sysctl vm.swappiness=${swappiness} >/dev/null 2>&1
                
                # 设置vfs_cache_pressure（建议值50-100，默认100）
                local vfs_cache_pressure=50
                echo "vm.vfs_cache_pressure=${vfs_cache_pressure}" >> /etc/sysctl.conf
                sysctl vm.vfs_cache_pressure=${vfs_cache_pressure} >/dev/null 2>&1
                
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
    lang_echo "${Yellow}10.${Font} 蓝绿部署管理 ${Blue}(零中断重启方案)${Font}" "${Yellow}10.${Font} Blue-Green deployment ${Blue}(zero-downtime restart)${Font}"
    lang_echo "${Yellow}11.${Font} BBR 管理 ${Blue}(快速开关)${Font}" "${Yellow}11.${Font} BBR management ${Blue}(quick toggle)${Font}"
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
            local v2ray_url="${base_url}/install.sh"
            
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
                
                # 询问是否配置蓝绿部署
                echo
                lang_echo "${Blue}============================================${Font}" "${Blue}============================================${Font}"
                lang_echo "${Green}V2Ray 安装完成！${Font}" "${Green}V2Ray installation completed!${Font}"
                lang_echo "${Blue}============================================${Font}" "${Blue}============================================${Font}"
                echo
                lang_echo "${Yellow}推荐配置蓝绿部署实现零中断重启：${Font}" "${Yellow}Recommend Blue-Green deployment for zero-downtime restart:${Font}"
                lang_echo "${Green}  • 双实例热备 (A/B 实例)${Font}" "${Green}  • Dual-instance hot standby${Font}"
                lang_echo "${Green}  • 极短中断切换 (毫秒级)${Font}" "${Green}  • Near-zero interruption switching${Font}"
                lang_echo "${Green}  • 资源隔离保护${Font}" "${Green}  • Resource isolation${Font}"
                lang_echo "${Green}  • 自动故障恢复${Font}" "${Green}  • Auto failure recovery${Font}"
                echo
                read -p "$(lang_text "是否立即配置蓝绿部署? (推荐) (y/n): " "Configure Blue-Green deployment now? (Recommended) (y/n): ")" setup_bg
                
                if [[ "$setup_bg" == "y" || "$setup_bg" == "Y" ]]; then
                    echo
                    setup_blue_green_deployment
                else
                    lang_echo "${Yellow}已跳过蓝绿部署配置${Font}" "${Yellow}Blue-Green deployment skipped${Font}"
                    lang_echo "${Yellow}可稍后在主菜单选项 10 中配置${Font}" "${Yellow}You can configure it later in main menu option 10${Font}"
                fi
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
            if bash <(wget -qO- "${base_url}/swap.sh" 2>/dev/null || curl -fsSL "${base_url}/swap.sh" 2>/dev/null); then
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
                local kernel_url="${base_url}/install_kernel.sh"
                
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
            lang_echo "${Green}进入蓝绿部署管理...${Font}" "${Green}Opening Blue-Green deployment manager...${Font}"
            blue_green_menu
            ;;
        11)
            lang_echo "${Green}进入 BBR 管理...${Font}" "${Green}Opening BBR management...${Font}"
            bbr_management
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

# ============================================
# 蓝绿部署相关函数
# ============================================

# 检查端口是否可用
is_port_available() {
    local port=$1
    if ss -tln 2>/dev/null | grep -q ":${port} " || netstat -tln 2>/dev/null | grep -q ":${port} "; then
        return 1
    fi
    return 0
}

is_valid_port() {
    local port=$1
    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    if ((port < 1 || port > 65535)); then
        return 1
    fi
    return 0
}

resolve_proxy_binary() {
    local proxy_type=$1
    local bin_path=$2
    local candidates=()

    if [[ -n "$bin_path" && -x "$bin_path" ]]; then
        echo "$bin_path"
        return 0
    fi

    case "$proxy_type" in
        xray)
            candidates=(/usr/local/bin/xray /usr/bin/xray /usr/sbin/xray /etc/v2ray-agent/xray/xray)
            ;;
        sing-box)
            candidates=(/etc/v2ray-agent/sing-box/sing-box /usr/local/bin/sing-box /usr/bin/sing-box /usr/sbin/sing-box)
            ;;
        v2ray)
            candidates=(/usr/local/bin/v2ray /usr/bin/v2ray /usr/sbin/v2ray /etc/v2ray-agent/v2ray/v2ray)
            ;;
        *)
            candidates=()
            ;;
    esac

    for c in "${candidates[@]}"; do
        if [[ -x "$c" ]]; then
            echo "$c"
            return 0
        fi
    done

    echo ""
}

# 检测代理软件类型和配置路径
detect_proxy_software() {
    local proxy_type=""
    local config_dir=""
    local bin_path=""
    local detected_bin=""

    detect_bin() {
        local name=$1
        local path=""
        path=$(command -v "$name" 2>/dev/null || true)
        if [[ -z "$path" ]]; then
            if [[ -x "/usr/local/bin/${name}" ]]; then
                path="/usr/local/bin/${name}"
            elif [[ -x "/usr/bin/${name}" ]]; then
                path="/usr/bin/${name}"
            elif [[ -x "/usr/sbin/${name}" ]]; then
                path="/usr/sbin/${name}"
            fi
        fi
        echo "$path"
    }
    
    # 检测 Xray
    detected_bin=$(detect_bin "xray")
    if [[ -n "$detected_bin" || -f "/etc/v2ray-agent/xray/conf/config.json" ]]; then
        proxy_type="xray"
        bin_path="$detected_bin"
        config_dir="/etc/v2ray-agent/xray/conf"
    # 检测 sing-box
    elif [[ -n "$(detect_bin "sing-box")" || -f "/etc/v2ray-agent/sing-box/conf/config.json" ]]; then
        proxy_type="sing-box"
        bin_path=$(detect_bin "sing-box")
        config_dir="/etc/v2ray-agent/sing-box/conf"
    # 检测 v2ray
    elif [[ -n "$(detect_bin "v2ray")" || -f "/etc/v2ray-agent/v2ray/conf/config.json" ]]; then
        proxy_type="v2ray"
        bin_path=$(detect_bin "v2ray")
        config_dir="/etc/v2ray-agent/v2ray/conf"
    fi
    
    echo "${proxy_type}|${config_dir}|${bin_path}"
}

# 检查蓝绿部署是否已安装
check_blue_green_installed() {
    if [[ -f "/etc/systemd/system/proxy-a.service" ]] && \
       [[ -f "/etc/systemd/system/proxy-b.service" ]] && \
       [[ -f "/usr/local/bin/blue-green" ]]; then
        return 0
    else
        return 1
    fi
}

# 配置蓝绿部署
setup_blue_green_deployment() {
    lang_echo "${Blue}============================================${Font}" "${Blue}============================================${Font}"
    lang_echo "${Green}    配置双实例蓝绿热备部署${Font}" "${Green}    Setup Blue-Green Deployment${Font}"
    lang_echo "${Blue}============================================${Font}" "${Blue}============================================${Font}"
    echo
    
    # 检查是否已安装
    if check_blue_green_installed; then
        lang_echo "${Yellow}检测到已安装蓝绿部署，是否重新配置？${Font}" "${Yellow}Blue-Green deployment detected. Reconfigure?${Font}"
        read -p "$(lang_text "(y/n): " "(y/n): ")" confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            lang_echo "${Yellow}已取消${Font}" "${Yellow}Cancelled${Font}"
            return 0
        fi
    fi
    
    lang_echo "${Yellow}[1/7]${Font} $(lang_text "检测代理软件..." "Detecting proxy software...")"
    
    # 检测代理软件
    local detection=$(detect_proxy_software)
    local proxy_type=$(echo "$detection" | cut -d'|' -f1)
    local config_dir=$(echo "$detection" | cut -d'|' -f2)
    local bin_path=$(echo "$detection" | cut -d'|' -f3)
    
    if [[ -z "$proxy_type" ]]; then
        lang_echo "${Red}错误：未检测到支持的代理软件 (xray/sing-box/v2ray)${Font}" "${Red}Error: No supported proxy software found${Font}"
        lang_echo "${Yellow}请先安装代理软件后再配置蓝绿部署${Font}" "${Yellow}Please install proxy software first${Font}"
        return 1
    fi

    # 确保二进制路径可用
    bin_path=$(resolve_proxy_binary "$proxy_type" "$bin_path")
    if [[ -z "$bin_path" ]]; then
        lang_echo "${Yellow}未检测到可执行文件，请手动输入二进制路径${Font}" "${Yellow}Binary not found, please enter the binary path${Font}"
        while true; do
            read -p "$(lang_text "请输入完整二进制路径: " "Enter full binary path: ")" bin_path
            if [[ -n "$bin_path" && -x "$bin_path" ]]; then
                break
            fi
            lang_echo "${Red}路径无效或不可执行，请重新输入${Font}" "${Red}Invalid or non-executable path, try again${Font}"
        done
    fi
    
    lang_echo "${Green}  检测到: ${proxy_type}${Font}" "${Green}  Detected: ${proxy_type}${Font}"
    lang_echo "${Green}  二进制: ${bin_path}${Font}" "${Green}  Binary: ${bin_path}${Font}"
    lang_echo "${Green}  配置目录: ${config_dir}${Font}" "${Green}  Config dir: ${config_dir}${Font}"
    echo
    
    # 检查原配置文件
    lang_echo "${Yellow}[2/7]${Font} $(lang_text "检查配置文件..." "Checking config files...")"
    local original_config=""
    
    if [[ -f "${config_dir}/config.json" ]]; then
        original_config="${config_dir}/config.json"
    else
        lang_echo "${Red}错误：未找到配置文件 ${config_dir}/config.json${Font}" "${Red}Error: Config file not found${Font}"
        return 1
    fi
    
    lang_echo "${Green}  原配置文件: ${original_config}${Font}" "${Green}  Original config: ${original_config}${Font}"
    echo
    
    # 备份原配置并创建双实例配置
    lang_echo "${Yellow}[3/7]${Font} $(lang_text "创建双实例配置..." "Creating dual-instance configs...")"

    # 选择实例端口
    local port_a=10080
    local port_b=10081

    if ! is_port_available "$port_a" || ! is_port_available "$port_b"; then
        lang_echo "${Yellow}检测到默认端口被占用，请手动设置端口${Font}" "${Yellow}Default ports are in use, please set custom ports${Font}"
        while true; do
            read -p "$(lang_text "请输入实例 A 端口 [10080]: " "Enter instance A port [10080]: ")" port_a
            port_a=${port_a:-10080}
            read -p "$(lang_text "请输入实例 B 端口 [10081]: " "Enter instance B port [10081]: ")" port_b
            port_b=${port_b:-10081}

            if ! is_valid_port "$port_a" || ! is_valid_port "$port_b"; then
                lang_echo "${Red}端口无效，请输入 1-65535 的数字${Font}" "${Red}Invalid port, use 1-65535${Font}"
                continue
            fi
            if [[ "$port_a" == "$port_b" ]]; then
                lang_echo "${Red}A/B 端口不能相同${Font}" "${Red}Ports for A/B must be different${Font}"
                continue
            fi
            if is_port_available "$port_a" && is_port_available "$port_b"; then
                break
            fi
            lang_echo "${Red}端口被占用，请重新输入${Font}" "${Red}Ports in use, please try again${Font}"
        done
    fi
    
    # 备份原配置
    if [[ ! -f "${original_config}.backup" ]]; then
        cp "${original_config}" "${original_config}.backup"
        lang_echo "${Green}  已备份原配置${Font}" "${Green}  Original config backed up${Font}"
    fi
    
    # 读取原配置中的端口（如果存在）
    local original_port="443"
    if command -v jq >/dev/null 2>&1; then
        if [[ "$proxy_type" == "sing-box" ]]; then
            original_port=$(jq -r '.inbounds[0].listen_port // 443' "${original_config}" 2>/dev/null || echo "443")
        else
            original_port=$(jq -r '.inbounds[0].port // 443' "${original_config}" 2>/dev/null || echo "443")
        fi
    fi
    
    # 创建实例 A 配置（端口 10080）
    if [[ "$proxy_type" == "xray" || "$proxy_type" == "v2ray" ]]; then
        # 对于 xray/v2ray，修改端口
        if command -v jq >/dev/null 2>&1; then
            jq ".inbounds[0].port = ${port_a}" "${original_config}" > "${config_dir}/config_a.json"
            jq ".inbounds[0].port = ${port_b}" "${original_config}" > "${config_dir}/config_b.json"
        else
            # 简单复制（用户需要手动修改端口）
            cp "${original_config}" "${config_dir}/config_a.json"
            cp "${original_config}" "${config_dir}/config_b.json"
            lang_echo "${Yellow}  警告：未安装 jq，请手动修改端口为 ${port_a} 和 ${port_b}${Font}" "${Yellow}  Warning: jq not installed, please manually change ports to ${port_a} and ${port_b}${Font}"
        fi
    else
        # sing-box 配置
        if command -v jq >/dev/null 2>&1; then
            jq ".inbounds[0].listen_port = ${port_a}" "${original_config}" > "${config_dir}/config_a.json"
            jq ".inbounds[0].listen_port = ${port_b}" "${original_config}" > "${config_dir}/config_b.json"
        else
            cp "${original_config}" "${config_dir}/config_a.json"
            cp "${original_config}" "${config_dir}/config_b.json"
            lang_echo "${Yellow}  警告：未安装 jq，请手动修改端口为 ${port_a} 和 ${port_b}${Font}" "${Yellow}  Warning: jq not installed, please manually change ports to ${port_a} and ${port_b}${Font}"
        fi
    fi
    
    lang_echo "${Green}  配置 A: ${config_dir}/config_a.json (端口 ${port_a})${Font}" "${Green}  Config A: ${config_dir}/config_a.json (port ${port_a})${Font}"
    lang_echo "${Green}  配置 B: ${config_dir}/config_b.json (端口 ${port_b})${Font}" "${Green}  Config B: ${config_dir}/config_b.json (port ${port_b})${Font}"
    echo

    # 写入端口配置供管理脚本使用
    cat > /etc/v2ray-agent/blue_green_ports.conf << EOF
PORT_A=${port_a}
PORT_B=${port_b}
EXTERNAL_PORT=${original_port}
EOF
    
    # 确保日志目录存在，避免 systemd namespace 失败
    install -d -m 755 "/var/log/${proxy_type}"
    
    # 创建 systemd 服务文件
    lang_echo "${Yellow}[4/7]${Font} $(lang_text "创建 systemd 服务..." "Creating systemd services...")"
    
    # 检测系统内存
    local total_mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local mem_limit="220M"
    
    if [[ $total_mem_kb -gt 900000 ]]; then
        mem_limit="400M"
    fi
    
    lang_echo "${Green}  检测到内存: $(($total_mem_kb / 1024)) MB${Font}" "${Green}  Detected memory: $(($total_mem_kb / 1024)) MB${Font}"
    lang_echo "${Green}  设置内存限制: ${mem_limit}${Font}" "${Green}  Memory limit: ${mem_limit}${Font}"
    
    # 创建服务 A
    cat > /etc/systemd/system/proxy-a.service << EOF
[Unit]
Description=Proxy Instance A (VLESS+Reality Blue-Green Deployment)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=${bin_path} run -c ${config_dir}/config_a.json
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=300
StartLimitBurst=5

# 资源隔离
MemoryMax=${mem_limit}
MemoryHigh=$((${mem_limit%M} - 20))M
CPUWeight=80
LimitNOFILE=1048576
Nice=5

# 安全加固
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/${proxy_type}

StandardOutput=journal
StandardError=journal
SyslogIdentifier=proxy-a

[Install]
WantedBy=multi-user.target
EOF
    
    # 创建服务 B
    cat > /etc/systemd/system/proxy-b.service << EOF
[Unit]
Description=Proxy Instance B (VLESS+Reality Blue-Green Deployment)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=${bin_path} run -c ${config_dir}/config_b.json
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=300
StartLimitBurst=5

# 资源隔离
MemoryMax=${mem_limit}
MemoryHigh=$((${mem_limit%M} - 20))M
CPUWeight=80
LimitNOFILE=1048576
Nice=5

# 安全加固
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/${proxy_type}

StandardOutput=journal
StandardError=journal
SyslogIdentifier=proxy-b

[Install]
WantedBy=multi-user.target
EOF
    
    lang_echo "${Green}  服务文件已创建${Font}" "${Green}  Service files created${Font}"
    echo
    
    # 安装管理脚本
    lang_echo "${Yellow}[5/7]${Font} $(lang_text "安装蓝绿管理脚本..." "Installing Blue-Green manager...")"
    
    local base_url="https://raw.githubusercontent.com/charleslkx/one-script/master"
    local manager_script="/usr/local/bin/blue-green"
    
    if wget -qO "${manager_script}" "${base_url}/blue_green_manager.sh" 2>/dev/null || \
       curl -fsSL "${base_url}/blue_green_manager.sh" -o "${manager_script}" 2>/dev/null; then
        chmod +x "${manager_script}"
        lang_echo "${Green}  管理脚本已安装: blue-green${Font}" "${Green}  Manager installed: blue-green${Font}"
    else
        lang_echo "${Red}错误：无法下载管理脚本${Font}" "${Red}Error: Failed to download manager${Font}"
        return 1
    fi
    echo
    
    # 重载 systemd
    lang_echo "${Yellow}[6/7]${Font} $(lang_text "重载 systemd 守护进程..." "Reloading systemd daemon...")"
    systemctl daemon-reload
    systemctl enable proxy-a.service proxy-b.service
    lang_echo "${Green}  服务已启用${Font}" "${Green}  Services enabled${Font}"
    echo
    
    # 初始化部署
    lang_echo "${Yellow}[7/7]${Font} $(lang_text "初始化蓝绿部署..." "Initializing Blue-Green deployment...")"
    echo
    
    # 停止可能存在的原服务
    systemctl stop xray 2>/dev/null
    systemctl stop sing-box 2>/dev/null
    systemctl stop v2ray 2>/dev/null
    
    # 使用管理脚本初始化
    if "${manager_script}" init; then
        echo
        lang_echo "${Green}============================================${Font}" "${Green}============================================${Font}"
        lang_echo "${Green}  蓝绿部署配置完成！${Font}" "${Green}  Blue-Green deployment configured!${Font}"
        lang_echo "${Green}============================================${Font}" "${Green}============================================${Font}"
        echo
        lang_echo "${Yellow}使用方法：${Font}" "${Yellow}Usage:${Font}"
        lang_echo "${Green}  blue-green${Font}          $(lang_text "- 打开管理菜单" "- Open management menu")"
        lang_echo "${Green}  blue-green status${Font}   $(lang_text "- 查看状态" "- View status")"
        lang_echo "${Green}  blue-green restart${Font}  $(lang_text "- 零中断重启" "- Zero-downtime restart")"
        echo
        
        # 移除旧的定时重启
        if crontab -l 2>/dev/null | grep -q "/sbin/reboot"; then
            lang_echo "${Yellow}检测到旧的定时重启任务，是否移除？${Font}" "${Yellow}Old scheduled reboot detected. Remove?${Font}"
            read -p "$(lang_text "(y/n): " "(y/n): ")" remove_cron
            if [[ "$remove_cron" == "y" || "$remove_cron" == "Y" ]]; then
                crontab -l 2>/dev/null | grep -v "/sbin/reboot" | crontab -
                lang_echo "${Green}已移除定时重启任务${Font}" "${Green}Scheduled reboot removed${Font}"
            fi
        fi
        
        return 0
    else
        lang_echo "${Red}初始化失败，请检查日志${Font}" "${Red}Initialization failed${Font}"
        return 1
    fi
}

# 卸载蓝绿部署
uninstall_blue_green_deployment() {
    lang_echo "${Blue}============================================${Font}" "${Blue}============================================${Font}"
    lang_echo "${Yellow}    卸载双实例蓝绿部署${Font}" "${Yellow}    Uninstall Blue-Green Deployment${Font}"
    lang_echo "${Blue}============================================${Font}" "${Blue}============================================${Font}"
    echo
    
    if ! check_blue_green_installed; then
        lang_echo "${Yellow}未检测到蓝绿部署${Font}" "${Yellow}Blue-Green deployment not found${Font}"
        return 0
    fi
    
    lang_echo "${Red}警告：卸载将停止所有代理服务！${Font}" "${Red}Warning: This will stop all proxy services!${Font}"
    read -p "$(lang_text "确认卸载? (y/n): " "Confirm uninstall? (y/n): ")" confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        lang_echo "${Yellow}已取消${Font}" "${Yellow}Cancelled${Font}"
        return 0
    fi
    
    echo
    lang_echo "${Yellow}[1/5]${Font} $(lang_text "停止服务..." "Stopping services...")"
    systemctl stop proxy-a.service proxy-b.service 2>/dev/null
    systemctl disable proxy-a.service proxy-b.service 2>/dev/null
    lang_echo "${Green}  服务已停止${Font}" "${Green}  Services stopped${Font}"
    
    lang_echo "${Yellow}[2/5]${Font} $(lang_text "清理 iptables 规则..." "Cleaning iptables rules...")"
    iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 10080 2>/dev/null
    iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 10081 2>/dev/null
    iptables -t nat -D OUTPUT -p tcp --dport 443 -o lo -j REDIRECT --to-ports 10080 2>/dev/null
    iptables -t nat -D OUTPUT -p tcp --dport 443 -o lo -j REDIRECT --to-ports 10081 2>/dev/null
    
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1
    fi
    lang_echo "${Green}  iptables 规则已清理${Font}" "${Green}  iptables rules cleaned${Font}"
    
    lang_echo "${Yellow}[3/5]${Font} $(lang_text "删除服务文件..." "Removing service files...")"
    rm -f /etc/systemd/system/proxy-a.service
    rm -f /etc/systemd/system/proxy-b.service
    systemctl daemon-reload
    lang_echo "${Green}  服务文件已删除${Font}" "${Green}  Service files removed${Font}"
    
    lang_echo "${Yellow}[4/5]${Font} $(lang_text "删除管理脚本..." "Removing manager script...")"
    rm -f /usr/local/bin/blue-green
    lang_echo "${Green}  管理脚本已删除${Font}" "${Green}  Manager script removed${Font}"
    
    lang_echo "${Yellow}[5/5]${Font} $(lang_text "清理配置文件..." "Cleaning config files...")"
    read -p "$(lang_text "是否删除双实例配置文件 (config_a.json, config_b.json)? (y/n): " "Delete dual configs? (y/n): ")" del_config
    
    if [[ "$del_config" == "y" || "$del_config" == "Y" ]]; then
        local detection=$(detect_proxy_software)
        local config_dir=$(echo "$detection" | cut -d'|' -f2)
        
        if [[ -n "$config_dir" ]]; then
            rm -f "${config_dir}/config_a.json"
            rm -f "${config_dir}/config_b.json"
            lang_echo "${Green}  配置文件已删除${Font}" "${Green}  Config files removed${Font}"
            
            # 恢复原配置
            if [[ -f "${config_dir}/config.json.backup" ]]; then
                cp "${config_dir}/config.json.backup" "${config_dir}/config.json"
                lang_echo "${Green}  已恢复原配置文件${Font}" "${Green}  Original config restored${Font}"
            fi
        fi
    else
        lang_echo "${Yellow}  配置文件保留${Font}" "${Yellow}  Config files kept${Font}"
    fi
    
    echo
    lang_echo "${Green}============================================${Font}" "${Green}============================================${Font}"
    lang_echo "${Green}  蓝绿部署已完全卸载${Font}" "${Green}  Blue-Green deployment uninstalled${Font}"
    lang_echo "${Green}============================================${Font}" "${Green}============================================${Font}"
    echo
}

# 蓝绿部署管理菜单
blue_green_menu() {
    while true; do
        echo -e "${Blue}============================================${Font}"
        lang_echo "${Green}       蓝绿部署管理${Font}" "${Green}       Blue-Green Management${Font}"
        echo -e "${Blue}============================================${Font}"
        echo
        
        if check_blue_green_installed; then
            lang_echo "${Green}状态: 已安装${Font}" "${Green}Status: Installed${Font}"
        else
            lang_echo "${Yellow}状态: 未安装${Font}" "${Yellow}Status: Not installed${Font}"
        fi
        echo
        
        lang_echo "${Yellow}1.${Font} $(lang_text "配置/重新配置蓝绿部署" "Setup/Reconfigure Blue-Green")"
        lang_echo "${Yellow}2.${Font} $(lang_text "查看部署状态" "View deployment status")"
        lang_echo "${Yellow}3.${Font} $(lang_text "执行零中断重启" "Execute zero-downtime restart")"
        lang_echo "${Yellow}4.${Font} $(lang_text "打开完整管理菜单" "Open full management menu")"
        lang_echo "${Yellow}5.${Font} $(lang_text "卸载蓝绿部署" "Uninstall Blue-Green")"
        lang_echo "${Yellow}6.${Font} $(lang_text "返回主菜单" "Back to main menu")"
        echo
        echo -e "${Blue}============================================${Font}"
        
        read -p "$(lang_text "请选择操作 [1-6]: " "Choose [1-6]: ")" choice
        echo
        
        case $choice in
            1)
                setup_blue_green_deployment
                ;;
            2)
                if check_blue_green_installed; then
                    /usr/local/bin/blue-green status
                else
                    lang_echo "${Yellow}请先安装蓝绿部署${Font}" "${Yellow}Please install Blue-Green first${Font}"
                fi
                ;;
            3)
                if check_blue_green_installed; then
                    /usr/local/bin/blue-green restart
                else
                    lang_echo "${Yellow}请先安装蓝绿部署${Font}" "${Yellow}Please install Blue-Green first${Font}"
                fi
                ;;
            4)
                if check_blue_green_installed; then
                    /usr/local/bin/blue-green
                else
                    lang_echo "${Yellow}请先安装蓝绿部署${Font}" "${Yellow}Please install Blue-Green first${Font}"
                fi
                ;;
            5)
                uninstall_blue_green_deployment
                ;;
            6)
                return 0
                ;;
            *)
                lang_echo "${Red}无效选择${Font}" "${Red}Invalid choice${Font}"
                ;;
        esac
        
        echo
        read -p "$(lang_text "按回车键继续..." "Press Enter to continue...")"
        clear
    done
}

# 主菜单
main_menu() {
    while true; do
        show_script_menu
        read -p "$(lang_text "请输入您的选择 [1-12]: " "Choose an option [1-12]: ")" choice
        execute_script "$choice"
        echo
        if [[ "$choice" != "12" ]]; then
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
    echo -e "${Green}      One-Script 环境初始化${Font}"
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
    
    echo -e "${Green}环境初始化完成！${Font}"
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
    local available_algos=$(sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | sed 's/^.*=//')
    local kernel_version
    kernel_version=$(uname -r 2>/dev/null)
    local bbr_module_loaded="no"
    if lsmod 2>/dev/null | awk '{print $1}' | grep -qx "tcp_bbr"; then
        bbr_module_loaded="yes"
    fi
    
    lang_echo "${Yellow}当前 TCP 拥塞控制算法：${current_algo:-未知}${Font}" "${Yellow}Current TCP congestion control: ${current_algo:-unknown}${Font}"
    lang_echo "${Yellow}当前队列调度算法：${current_qdisc:-未知}${Font}" "${Yellow}Current queue discipline: ${current_qdisc:-unknown}${Font}"
    if [[ -n "${available_algos// }" ]]; then
        lang_echo "${Yellow}可用拥塞控制算法：${available_algos}${Font}" "${Yellow}Available congestion controls: ${available_algos}${Font}"
    fi
    lang_echo "${Yellow}内核版本：${kernel_version:-未知}${Font}" "${Yellow}Kernel: ${kernel_version:-unknown}${Font}"
    lang_echo "${Yellow}BBR 模块加载状态：${bbr_module_loaded}${Font}" "${Yellow}BBR module loaded: ${bbr_module_loaded}${Font}"
    echo
    
    lang_echo "${Green}请选择操作：${Font}" "${Green}Choose an action:${Font}"
    lang_echo "${Yellow}1.${Font} 开启 BBR v1 + FQ" "${Yellow}1.${Font} Enable BBR v1 + FQ"
    lang_echo "${Yellow}2.${Font} 关闭 BBR (恢复默认 cubic)" "${Yellow}2.${Font} Disable BBR (restore cubic)"
    lang_echo "${Yellow}3.${Font} 返回上级菜单" "${Yellow}3.${Font} Back"
    echo
    
    read -p "$(lang_text "请输入选择 [1-3]: " "Choose [1-3]: ")" bbr_choice
    case $bbr_choice in
        1)
    if [[ -n "${available_algos// }" ]] && ! echo "${available_algos}" | grep -qw "bbr"; then
        if modprobe tcp_bbr >/dev/null 2>&1; then
            available_algos=$(sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | sed 's/^.*=//')
        fi
        if [[ -n "${available_algos// }" ]] && ! echo "${available_algos}" | grep -qw "bbr"; then
            lang_echo "${Red}未检测到内核支持 BBR，无法开启。${Font}" "${Red}BBR not supported by kernel; cannot enable.${Font}"
            read -p "$(lang_text "按回车键返回..." "Press Enter to return...")"
            system_tools_menu
            return 0
        fi
    fi
            lang_echo "${Green}正在开启 BBR v1 + FQ...${Font}" "${Green}Enabling BBR v1 + FQ...${Font}"
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
            current_algo=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
            current_qdisc=$(sysctl net.core.default_qdisc 2>/dev/null | awk '{print $3}')
            if [[ "${current_algo}" == "bbr" && "${current_qdisc}" == "fq" ]]; then
                lang_echo "${Green}BBR 已开启！${Font}" "${Green}BBR enabled!${Font}"
            else
                lang_echo "${Red}BBR 开启失败，请检查内核支持与配置。${Font}" "${Red}Failed to enable BBR; check kernel support/config.${Font}"
            fi
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
                echo -e "${Yellow}返回主菜单${Font}"
                return 0
                ;;
            *)
                echo -e "${Red}无效选择，请输入 1-10${Font}"
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
    echo -e "${Green}      One-Script 脚本帮助信息${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    echo -e "${Green}用法：${Font}"
    echo -e "  $(basename "$0") [选项]"
    echo
    echo -e "${Green}选项：${Font}"
    echo -e "  ${Yellow}--help, -h${Font}              显示此帮助信息"
    echo -e "  ${Yellow}--version, -v${Font}           显示版本信息"
    echo -e "  ${Yellow}--install-command${Font}       安装简易命令 (v2ray)"
    echo -e "  ${Yellow}--uninstall-command${Font}     卸载简易命令"
    echo
    echo -e "${Green}简易命令：${Font}"
    echo -e "  安装后可通过 '${Yellow}v2ray${Font}' 命令启动脚本"
    echo -e "  使用方法：${Yellow}sudo v2ray${Font}"
    echo -e "  模式：${Yellow}远程运行（始终获取最新版本）${Font}"
    echo
    echo -e "${Green}功能特性：${Font}"
    echo -e "  • 智能 Swap 内存管理"
    echo -e "  • 远程脚本获取执行"
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
    
    local base_url="https://raw.githubusercontent.com/charleslkx/one-script/master"
    local script_path="$0"
    local temp_script="/tmp/main_new.sh"
    
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
    
    local base_url="https://raw.githubusercontent.com/charleslkx/one-script/master"
    local script_path="$0"
    local temp_script="/tmp/main_new.sh"
    
    # 下载最新版本
    if wget -qO "$temp_script" "${base_url}/main.sh" 2>/dev/null || curl -fsSL "${base_url}/main.sh" -o "$temp_script" 2>/dev/null; then
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
    
    local base_url="https://raw.githubusercontent.com/charleslkx/one-script/master"
    local script_path="$0"
    local temp_script="/tmp/main_new.sh"
    
    # 下载最新版本
    if wget -qO "$temp_script" "${base_url}/main.sh" 2>/dev/null || curl -fsSL "${base_url}/main.sh" -o "$temp_script" 2>/dev/null; then
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
    lang_echo "${Green}           命令管理${Font}" "${Green}           Command Management${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    local command_name="v2ray"
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
    lang_echo "${Green}命令管理选项：${Font}" "${Green}Command options:${Font}"
    lang_echo "${Yellow}1.${Font} 安装远程运行命令 (${command_name})" "${Yellow}1.${Font} Install remote command (${command_name})"
    lang_echo "${Yellow}2.${Font} 卸载远程运行命令" "${Yellow}2.${Font} Uninstall remote command"
    lang_echo "${Yellow}3.${Font} 查看详细状态" "${Yellow}3.${Font} Show detailed status"
    lang_echo "${Yellow}4.${Font} 返回主菜单" "${Yellow}4.${Font} Back to main menu"
    echo
    echo -e "${Blue}============================================${Font}"
    
    local choice
    while true; do
        read -p "$(lang_text "请选择操作 [1-4]: " "Choose an action [1-4]: ")" choice
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
                lang_echo "${Yellow}返回主菜单${Font}" "${Yellow}Back to main menu${Font}"
                return 0
                ;;
            *)
                lang_echo "${Red}无效选择，请输入 1-4${Font}" "${Red}Invalid choice, enter 1-4${Font}"
                ;;
        esac
    done
}

# 显示命令状态
show_command_status() {
    echo -e "${Blue}============================================${Font}"
    lang_echo "${Green}         简易命令状态信息${Font}" "${Green}         Command Status Info${Font}"
    echo -e "${Blue}============================================${Font}"
    
    local command_name="v2ray"
    local script_path="$(readlink -f "$0")"
    local found=false
    
    lang_echo "${Green}当前脚本路径：${Font}${script_path}" "${Green}Current script path:${Font} ${script_path}"
    lang_echo "${Green}简易命令名称：${Font}${command_name}" "${Green}Command name:${Font} ${command_name}"
    echo
    
    # 检查各个位置的命令
    lang_echo "${Green}命令安装状态：${Font}" "${Green}Installation status:${Font}"
    
    if [[ -f "/usr/bin/${command_name}" ]]; then
        echo -e "${Green}  /usr/bin/${command_name} ✓${Font}"
        lang_echo "${Green}  链接目标：$(readlink "/usr/bin/${command_name}" 2>/dev/null || echo "无法读取")${Font}" "${Green}  Link target: $(readlink "/usr/bin/${command_name}" 2>/dev/null || echo "N/A")${Font}"
        found=true
    else
        echo -e "${Yellow}  /usr/bin/${command_name} ✗${Font}"
    fi
    
    if [[ -f "/usr/sbin/${command_name}" ]]; then
        echo -e "${Green}  /usr/sbin/${command_name} ✓${Font}"
        lang_echo "${Green}  链接目标：$(readlink "/usr/sbin/${command_name}" 2>/dev/null || echo "无法读取")${Font}" "${Green}  Link target: $(readlink "/usr/sbin/${command_name}" 2>/dev/null || echo "N/A")${Font}"
        found=true
    else
        echo -e "${Yellow}  /usr/sbin/${command_name} ✗${Font}"
    fi
    
    if [[ -f "/usr/local/bin/${command_name}" ]]; then
        echo -e "${Green}  /usr/local/bin/${command_name} ✓${Font}"
        lang_echo "${Green}  链接目标：$(readlink "/usr/local/bin/${command_name}" 2>/dev/null || echo "无法读取")${Font}" "${Green}  Link target: $(readlink "/usr/local/bin/${command_name}" 2>/dev/null || echo "N/A")${Font}"
        found=true
    else
        echo -e "${Yellow}  /usr/local/bin/${command_name} ✗${Font}"
    fi
    
    echo
    if [[ "$found" == "true" ]]; then
        lang_echo "${Green}总体状态：${Font}已安装 ✓（远程运行模式）" "${Green}Overall status:${Font} Installed ✓ (remote mode)"
        echo
        lang_echo "${Green}使用方法：${Font}" "${Green}Usage:${Font}"
        echo -e "  ${Blue}${command_name}${Font}                # 从远程启动最新版本脚本"
        echo -e "  ${Blue}sudo ${command_name}${Font}           # 以root权限从远程启动脚本"
        echo -e "  ${Blue}${command_name} --help${Font}         # 查看帮助信息"
        echo -e "  ${Blue}${command_name} --version${Font}      # 查看版本信息"
        echo
        lang_echo "${Green}特性：${Font}" "${Green}Features:${Font}"
        echo -e "  • 始终运行最新版本"
        echo -e "  • 无需本地存储脚本"
        echo -e "  • 自动检查网络连接"
    else
        lang_echo "${Yellow}总体状态：${Font}未安装" "${Yellow}Overall status:${Font} Not installed"
        echo
        lang_echo "${Yellow}安装后可使用：${Font}" "${Yellow}After installation:${Font}"
        echo -e "  ${Blue}sudo ${command_name}${Font}           # 从远程启动脚本"
    fi
    
    echo
    lang_echo "${Yellow}PATH 环境变量：${Font}" "${Yellow}PATH environment:${Font}"
    echo -e "${Blue}$(echo $PATH | tr ':' '\n' | grep -E '(usr/bin|usr/sbin|usr/local/bin)' || echo "未找到相关路径")${Font}"
    
    echo -e "${Blue}============================================${Font}"
    echo
}

# 启动脚本
main "$@"
