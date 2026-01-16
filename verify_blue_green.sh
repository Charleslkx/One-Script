#!/usr/bin/env bash
# 蓝绿部署配置验证脚本

# 颜色定义
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[34m"
Font="\033[0m"

PORTS_CONF="/etc/v2ray-agent/blue_green_ports.conf"
EXTERNAL_PORT=443
if [[ -f "$PORTS_CONF" ]]; then
    # shellcheck disable=SC1090
    source "$PORTS_CONF"
fi

echo -e "${Blue}============================================${Font}"
echo -e "${Green}    蓝绿部署配置验证${Font}"
echo -e "${Blue}============================================${Font}"
echo

# 检查项计数
total_checks=0
passed_checks=0
failed_checks=0

check_item() {
    local item=$1
    local check_cmd=$2
    local success_msg=$3
    local fail_msg=$4
    
    total_checks=$((total_checks + 1))
    
    if eval "$check_cmd"; then
        echo -e "${Green}✓${Font} $item: $success_msg"
        passed_checks=$((passed_checks + 1))
        return 0
    else
        echo -e "${Red}✗${Font} $item: $fail_msg"
        failed_checks=$((failed_checks + 1))
        return 1
    fi
}

echo -e "${Yellow}正在检查蓝绿部署配置...${Font}"
echo

# 1. 检查 systemd 服务文件
check_item "服务文件 A" \
    "[[ -f /etc/systemd/system/proxy-a.service ]]" \
    "已安装" \
    "未找到"

check_item "服务文件 B" \
    "[[ -f /etc/systemd/system/proxy-b.service ]]" \
    "已安装" \
    "未找到"

# 2. 检查管理脚本
check_item "管理脚本" \
    "[[ -f /usr/local/bin/blue-green ]]" \
    "已安装" \
    "未找到"

check_item "脚本可执行" \
    "[[ -x /usr/local/bin/blue-green ]]" \
    "有执行权限" \
    "无执行权限"

# 3. 检查服务状态
if systemctl list-unit-files | grep -q "proxy-a.service"; then
    check_item "服务 A 注册" \
        "systemctl list-unit-files | grep -q proxy-a.service" \
        "已注册到 systemd" \
        "未注册"
    
    if systemctl is-enabled proxy-a.service >/dev/null 2>&1; then
        echo -e "${Green}  • 服务 A 已启用${Font}"
    else
        echo -e "${Yellow}  • 服务 A 未启用${Font}"
    fi
    
    if systemctl is-active proxy-a.service >/dev/null 2>&1; then
        echo -e "${Green}  • 服务 A 正在运行${Font}"
    else
        echo -e "${Yellow}  • 服务 A 未运行${Font}"
    fi
fi

if systemctl list-unit-files | grep -q "proxy-b.service"; then
    check_item "服务 B 注册" \
        "systemctl list-unit-files | grep -q proxy-b.service" \
        "已注册到 systemd" \
        "未注册"
    
    if systemctl is-enabled proxy-b.service >/dev/null 2>&1; then
        echo -e "${Green}  • 服务 B 已启用${Font}"
    else
        echo -e "${Yellow}  • 服务 B 未启用${Font}"
    fi
    
    if systemctl is-active proxy-b.service >/dev/null 2>&1; then
        echo -e "${Green}  • 服务 B 正在运行${Font}"
    else
        echo -e "${Yellow}  • 服务 B 未运行${Font}"
    fi
fi

# 4. 检查端口监听
check_item "端口 10080 监听" \
    "ss -tlnp 2>/dev/null | grep -q ':10080' || netstat -tlnp 2>/dev/null | grep -q ':10080'" \
    "实例 A 正在监听" \
    "实例 A 未监听"

check_item "端口 10081 监听" \
    "ss -tlnp 2>/dev/null | grep -q ':10081' || netstat -tlnp 2>/dev/null | grep -q ':10081'" \
    "实例 B 正在监听" \
    "实例 B 未监听"

# 5. 检查 iptables 规则
check_item "iptables 转发规则 (dpt:${EXTERNAL_PORT})" \
    "iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q \"dpt:${EXTERNAL_PORT}\"" \
    "已配置" \
    "未配置"

# 6. 检查配置文件
check_item "配置文件 A" \
    "[[ -f /etc/v2ray-agent/xray/conf/config_a.json ]] || [[ -f /etc/v2ray-agent/sing-box/conf/config_a.json ]]" \
    "已创建" \
    "未找到"

check_item "配置文件 B" \
    "[[ -f /etc/v2ray-agent/xray/conf/config_b.json ]] || [[ -f /etc/v2ray-agent/sing-box/conf/config_b.json ]]" \
    "已创建" \
    "未找到"

check_item "配置备份" \
    "[[ -f /etc/v2ray-agent/xray/conf/config.json.backup ]] || [[ -f /etc/v2ray-agent/sing-box/conf/config.json.backup ]]" \
    "已备份" \
    "未找到"

# 7. 检查内核转发
check_item "内核转发" \
    "sysctl net.ipv4.ip_forward | grep -q '= 1'" \
    "已启用" \
    "未启用"

echo
echo -e "${Blue}============================================${Font}"
echo -e "${Green}检查完成${Font}"
echo -e "${Blue}============================================${Font}"
echo
echo -e "总检查项: ${Blue}${total_checks}${Font}"
echo -e "通过: ${Green}${passed_checks}${Font}"
echo -e "失败: ${Red}${failed_checks}${Font}"
echo

if [[ $failed_checks -eq 0 ]]; then
    echo -e "${Green}✓ 蓝绿部署配置完整！${Font}"
    echo
    echo -e "${Yellow}可用命令：${Font}"
    echo -e "  ${Green}blue-green status${Font}   - 查看状态"
    echo -e "  ${Green}blue-green restart${Font}  - 零中断重启"
    echo -e "  ${Green}blue-green${Font}          - 打开管理菜单"
    exit 0
else
    echo -e "${Yellow}⚠ 部分配置缺失或未启动${Font}"
    echo
    echo -e "${Yellow}建议操作：${Font}"
    echo -e "  1. 运行 ${Green}bash main.sh${Font}"
    echo -e "  2. 选择 ${Green}10 - 蓝绿部署管理${Font}"
    echo -e "  3. 选择 ${Green}1 - 配置蓝绿部署${Font}"
    exit 1
fi
