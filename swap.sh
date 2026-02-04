#!/usr/bin/env bash
#Blog:https://www.moerats.com/

Green="\033[32m"
Font="\033[0m"
Red="\033[31m" 

clear() {
    :
}

#root权限
root_need(){
    if [[ $EUID -ne 0 ]]; then
        echo -e "${Red}Error:This script must be run as root!${Font}"
        exit 1
    fi
}

#检测ovz
ovz_no(){
    if [[ -d "/proc/vz" ]]; then
        echo -e "${Red}Your VPS is based on OpenVZ，not supported!${Font}"
        exit 1
    fi
}

run_hybrid_memory_tool() {
    local action="${1:---hybrid-memory}"
    local base_url="${ONE_SCRIPT_BASE_URL:-}"
    local channel="${ONE_SCRIPT_CHANNEL:-}"
    if [[ -z "${base_url}" ]]; then
        if [[ -n "${channel}" ]]; then
            base_url="https://raw.githubusercontent.com/charleslkx/one-script/${channel}"
        else
            base_url="https://raw.githubusercontent.com/charleslkx/one-script/main"
        fi
    fi

    if command -v wget >/dev/null 2>&1; then
        bash <(wget -qO- "${base_url}/main.sh" 2>/dev/null) "${action}"
        return $?
    fi
    if command -v curl >/dev/null 2>&1; then
        bash <(curl -fsSL "${base_url}/main.sh" 2>/dev/null) "${action}"
        return $?
    fi
    echo -e "${Red}错误：未找到 wget 或 curl 工具${Font}"
    return 1
}

add_swap(){
echo -e "${Green}请输入需要添加的swap，建议为内存的2倍！${Font}"
read -p "请输入swap数值:" swapsize

#检查是否存在swapfile
grep -q "swapfile" /etc/fstab

#如果不存在将为其创建swap
if [ $? -ne 0 ]; then
	echo -e "${Green}swapfile未发现，正在为其创建swapfile${Font}"
	fallocate -l ${swapsize}M /swapfile
	chmod 600 /swapfile
	mkswap /swapfile
	swapon /swapfile
	echo '/swapfile none swap defaults 0 0' >> /etc/fstab
         echo -e "${Green}swap创建成功，并查看信息：${Font}"
         cat /proc/swaps
         cat /proc/meminfo | grep Swap
else
    echo -e "${Yellow}检测到已有 swapfile，是否替换？[y/N]: ${Font}"
    read -r replace_choice
    if [[ $replace_choice =~ ^[Yy]$ ]]; then
        del_swap
        add_swap
    else
        echo -e "${Yellow}已取消调整 swap${Font}"
    fi
fi
}

del_swap(){
#检查是否存在swapfile
grep -q "swapfile" /etc/fstab

#如果存在就将其移除
if [ $? -eq 0 ]; then
	echo -e "${Green}swapfile已发现，正在将其移除...${Font}"
	sed -i '/swapfile/d' /etc/fstab
	echo "3" > /proc/sys/vm/drop_caches
	swapoff -a
	rm -f /swapfile
    echo -e "${Green}swap已删除！${Font}"
else
	echo -e "${Red}swapfile未发现，swap删除失败！${Font}"
fi
}

#开始菜单
main(){
root_need
ovz_no
clear
echo -e "———————————————————————————————————————"
echo -e "${Green}Linux VPS一键添加/删除swap脚本${Font}"
echo -e "${Green}1、查看ZRAM/Swap状态${Font}"
echo -e "${Green}2、调整ZRAM${Font}"
echo -e "${Green}3、停用ZRAM${Font}"
echo -e "${Green}4、添加/调整swap${Font}"
echo -e "${Green}5、删除swap${Font}"
echo -e "${Green}6、混合内存管理 (ZRAM/Swap)${Font}"
echo -e "———————————————————————————————————————"
read -p "请输入数字 [1-6]:" num
case "$num" in
    1)
    run_hybrid_memory_tool --zram-status
    ;;
    2)
    run_hybrid_memory_tool --zram-config
    ;;
    3)
    run_hybrid_memory_tool --zram-disable
    ;;
    4)
    add_swap
    ;;
    5)
    del_swap
    ;;
    6)
    run_hybrid_memory_tool
    ;;
    *)
    clear
    echo -e "${Green}请输入正确数字 [1-6]${Font}"
    sleep 2s
    main
    ;;
    esac
}
main
