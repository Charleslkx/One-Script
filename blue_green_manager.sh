#!/usr/bin/env bash
# 双实例蓝绿热备管理脚本 - Blue/Green Deployment Manager
# 用于 VLESS+Reality 等代理服务的零/极短中断切换

# 颜色定义
Green="\033[32m"
Font="\033[0m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[34m"

# 配置常量
PORT_A=10080
PORT_B=10081
EXTERNAL_PORT=443
SERVICE_NAME_A="proxy-a"
SERVICE_NAME_B="proxy-b"
HEALTH_CHECK_RETRIES=5
HEALTH_CHECK_INTERVAL=2

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

# 读取自定义端口配置（如有）
PORTS_CONF="/etc/v2ray-agent/blue_green_ports.conf"
if [[ -f "$PORTS_CONF" ]]; then
    # shellcheck disable=SC1090
    source "$PORTS_CONF"
fi

if ! is_valid_port "$PORT_A"; then
    PORT_A=10080
fi
if ! is_valid_port "$PORT_B"; then
    PORT_B=10081
fi
if ! is_valid_port "$EXTERNAL_PORT"; then
    EXTERNAL_PORT=443
fi

# 日志函数
log_info() {
    echo -e "${Green}[INFO]${Font} $1"
}

log_warn() {
    echo -e "${Yellow}[WARN]${Font} $1"
}

log_error() {
    echo -e "${Red}[ERROR]${Font} $1"
}

log_service_logs_hint() {
    local service=$1
    log_info "日志查看: journalctl -u ${service} -e --no-pager"
    log_info "状态查看: systemctl status ${service} --no-pager"
}

# 检查是否为 root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本必须以 root 权限运行"
        exit 1
    fi
}

# 检查端口是否在监听
check_port_listening() {
    local port=$1
    if ss -tlnp 2>/dev/null | grep -q ":${port} " || netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
        return 0
    else
        return 1
    fi
}

# 健康检查
health_check() {
    local port=$1
    local retries=${2:-$HEALTH_CHECK_RETRIES}
    
    log_info "正在对端口 ${port} 进行健康检查..."
    
    for i in $(seq 1 $retries); do
        if check_port_listening "$port"; then
            log_info "健康检查通过 (尝试 $i/$retries)"
            return 0
        fi
        log_warn "健康检查失败 (尝试 $i/$retries)，等待 ${HEALTH_CHECK_INTERVAL} 秒..."
        sleep $HEALTH_CHECK_INTERVAL
    done
    
    log_error "健康检查失败：端口 ${port} 未响应"
    return 1
}

# 获取当前激活的实例
get_active_instance() {
    # 检查 iptables 规则判断当前转发到哪个端口
    if iptables -t nat -L PREROUTING -n -v 2>/dev/null | grep -q "redir ports ${PORT_A}"; then
        echo "A"
    elif iptables -t nat -L PREROUTING -n -v 2>/dev/null | grep -q "redir ports ${PORT_B}"; then
        echo "B"
    else
        echo "NONE"
    fi
}

# 切换流量到指定实例
switch_traffic() {
    local target=$1  # A 或 B
    local target_port
    
    if [[ "$target" == "A" ]]; then
        target_port=$PORT_A
    elif [[ "$target" == "B" ]]; then
        target_port=$PORT_B
    else
        log_error "无效的目标实例：$target"
        return 1
    fi
    
    log_info "准备切换流量到实例 ${target} (端口 ${target_port})..."
    
    # 先进行健康检查
    if ! health_check "$target_port" 3; then
        log_error "目标实例健康检查失败，取消切换"
        return 1
    fi
    
    # 启用内核转发
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    
    # 清理旧规则
    log_info "清理旧的 iptables 规则..."
    iptables -t nat -D PREROUTING -p tcp --dport $EXTERNAL_PORT -j REDIRECT --to-ports $PORT_A 2>/dev/null
    iptables -t nat -D PREROUTING -p tcp --dport $EXTERNAL_PORT -j REDIRECT --to-ports $PORT_B 2>/dev/null
    iptables -t nat -D OUTPUT -p tcp --dport $EXTERNAL_PORT -o lo -j REDIRECT --to-ports $PORT_A 2>/dev/null
    iptables -t nat -D OUTPUT -p tcp --dport $EXTERNAL_PORT -o lo -j REDIRECT --to-ports $PORT_B 2>/dev/null
    
    # 添加新规则
    log_info "添加新的 iptables 规则..."
    iptables -t nat -A PREROUTING -p tcp --dport $EXTERNAL_PORT -j REDIRECT --to-ports $target_port
    iptables -t nat -A OUTPUT -p tcp --dport $EXTERNAL_PORT -o lo -j REDIRECT --to-ports $target_port
    
    # 保存规则（根据系统选择合适的方法）
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1
    elif command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /etc/iptables.rules 2>/dev/null
    fi
    
    log_info "${Green}流量已成功切换到实例 ${target}！${Font}"
    return 0
}

# 显示当前状态
show_status() {
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}       双实例蓝绿部署状态${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    # 检查服务状态
    local status_a=$(systemctl is-active $SERVICE_NAME_A 2>/dev/null || echo "inactive")
    local status_b=$(systemctl is-active $SERVICE_NAME_B 2>/dev/null || echo "inactive")
    
    echo -e "${Yellow}实例 A ($SERVICE_NAME_A):${Font}"
    echo -e "  服务状态: $status_a"
    echo -e "  监听端口: $PORT_A"
    if check_port_listening $PORT_A; then
        echo -e "  端口状态: ${Green}监听中${Font}"
    else
        echo -e "  端口状态: ${Red}未监听${Font}"
    fi
    echo
    
    echo -e "${Yellow}实例 B ($SERVICE_NAME_B):${Font}"
    echo -e "  服务状态: $status_b"
    echo -e "  监听端口: $PORT_B"
    if check_port_listening $PORT_B; then
        echo -e "  端口状态: ${Green}监听中${Font}"
    else
        echo -e "  端口状态: ${Red}未监听${Font}"
    fi
    echo
    
    # 检查当前激活实例
    local active=$(get_active_instance)
    echo -e "${Yellow}当前对外服务实例:${Font}"
    if [[ "$active" == "NONE" ]]; then
        echo -e "  ${Red}无激活实例（流量未配置）${Font}"
    else
        echo -e "  ${Green}实例 ${active}${Font}"
    fi
    echo
    
    # 显示 iptables 规则
    echo -e "${Yellow}当前 iptables 转发规则:${Font}"
    iptables -t nat -L PREROUTING -n -v 2>/dev/null | grep "dpt:$EXTERNAL_PORT" || echo "  无相关规则"
    echo
}

# 无感升级/重启流程
zero_downtime_restart() {
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}    启动零中断重启流程${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    local current=$(get_active_instance)
    
    if [[ "$current" == "NONE" ]]; then
        log_error "未检测到激活实例，请先初始化部署"
        return 1
    fi
    
    local standby
    local current_service
    local standby_service
    
    if [[ "$current" == "A" ]]; then
        standby="B"
        current_service=$SERVICE_NAME_A
        standby_service=$SERVICE_NAME_B
    else
        standby="A"
        current_service=$SERVICE_NAME_B
        standby_service=$SERVICE_NAME_A
    fi
    
    log_info "当前激活实例: $current"
    log_info "待命实例: $standby"
    echo
    
    # 步骤 1: 启动待命实例
    log_info "[步骤 1/4] 启动待命实例 $standby..."
    systemctl start $standby_service
    sleep 3
    
    # 步骤 2: 健康检查待命实例
    log_info "[步骤 2/4] 对待命实例进行健康检查..."
    local standby_port
    if [[ "$standby" == "A" ]]; then
        standby_port=$PORT_A
    else
        standby_port=$PORT_B
    fi
    
    if ! health_check "$standby_port"; then
        log_error "待命实例健康检查失败，中止切换"
        return 1
    fi
    
    # 步骤 3: 切换流量
    log_info "[步骤 3/4] 切换流量到待命实例 $standby..."
    if ! switch_traffic "$standby"; then
        log_error "流量切换失败"
        return 1
    fi
    
    log_info "等待 5 秒确保流量切换稳定..."
    sleep 5
    
    # 步骤 4: 重启原实例
    log_info "[步骤 4/4] 重启原实例 $current..."
    systemctl restart $current_service
    
    echo
    log_info "${Green}零中断重启完成！${Font}"
    log_info "新的激活实例: $standby"
    log_info "备用实例: $current"
    echo
    
    show_status
}

# 初始化部署
init_deployment() {
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}    初始化双实例蓝绿部署${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    
    # 启动实例 A
    log_info "启动实例 A..."
    systemctl start $SERVICE_NAME_A
    sleep 3
    
    if ! health_check $PORT_A; then
        log_error "实例 A 启动失败"
        log_service_logs_hint "$SERVICE_NAME_A"
        return 1
    fi
    
    # 将流量指向 A
    log_info "配置流量转发到实例 A..."
    switch_traffic "A"
    
    # 启动实例 B 作为热备
    log_info "启动实例 B 作为热备..."
    systemctl start $SERVICE_NAME_B
    sleep 3
    
    if ! health_check $PORT_B; then
        log_warn "实例 B 启动失败，但不影响服务"
        log_service_logs_hint "$SERVICE_NAME_B"
    fi
    
    echo
    log_info "${Green}初始化完成！${Font}"
    show_status
}

# 主菜单
show_menu() {
    echo -e "${Blue}============================================${Font}"
    echo -e "${Green}    双实例蓝绿部署管理${Font}"
    echo -e "${Blue}============================================${Font}"
    echo
    echo -e "${Yellow}1.${Font} 查看当前状态"
    echo -e "${Yellow}2.${Font} 初始化部署（首次使用）"
    echo -e "${Yellow}3.${Font} 零中断重启/升级"
    echo -e "${Yellow}4.${Font} 手动切换到实例 A"
    echo -e "${Yellow}5.${Font} 手动切换到实例 B"
    echo -e "${Yellow}6.${Font} 重启实例 A"
    echo -e "${Yellow}7.${Font} 重启实例 B"
    echo -e "${Yellow}8.${Font} 停止所有实例"
    echo -e "${Yellow}9.${Font} 启动所有实例"
    echo -e "${Yellow}0.${Font} 退出"
    echo
    echo -e "${Blue}============================================${Font}"
}

# 主程序
main() {
    check_root
    
    if [[ $# -eq 0 ]]; then
        # 交互模式
        while true; do
            show_menu
            read -p "请选择操作 [0-9]: " choice
            echo
            
            case $choice in
                1)
                    show_status
                    ;;
                2)
                    init_deployment
                    ;;
                3)
                    zero_downtime_restart
                    ;;
                4)
                    switch_traffic "A"
                    show_status
                    ;;
                5)
                    switch_traffic "B"
                    show_status
                    ;;
                6)
                    systemctl restart $SERVICE_NAME_A
                    log_info "实例 A 已重启"
                    ;;
                7)
                    systemctl restart $SERVICE_NAME_B
                    log_info "实例 B 已重启"
                    ;;
                8)
                    systemctl stop $SERVICE_NAME_A $SERVICE_NAME_B
                    log_info "所有实例已停止"
                    ;;
                9)
                    systemctl start $SERVICE_NAME_A $SERVICE_NAME_B
                    log_info "所有实例已启动"
                    show_status
                    ;;
                0)
                    log_info "退出"
                    exit 0
                    ;;
                *)
                    log_error "无效选择"
                    ;;
            esac
            
            echo
            read -p "按回车键继续..."
            clear
        done
    else
        # 命令行模式
        case "$1" in
            status)
                show_status
                ;;
            init)
                init_deployment
                ;;
            restart)
                zero_downtime_restart
                ;;
            switch)
                if [[ -n "$2" && ("$2" == "A" || "$2" == "B") ]]; then
                    switch_traffic "$2"
                else
                    log_error "用法: $0 switch [A|B]"
                    exit 1
                fi
                ;;
            *)
                echo "用法: $0 [status|init|restart|switch A|B]"
                exit 1
                ;;
        esac
    fi
}

main "$@"
