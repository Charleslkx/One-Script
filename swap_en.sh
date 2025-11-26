#!/usr/bin/env bash
#Blog:https://www.moerats.com/

Green="\033[32m"
Font="\033[0m"
Red="\033[31m" 

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

add_swap(){
lang_echo "${Green}请输入需要添加的swap，建议为内存的2倍！${Font}" "${Green}Enter swap size to add (MB). Suggested: twice your RAM.${Font}"
read -p "$(lang_text "请输入swap数值:" "Enter swap size (MB): ")" swapsize

#检查是否存在swapfile
grep -q "swapfile" /etc/fstab

#如果不存在将为其创建swap
if [ $? -ne 0 ]; then
	lang_echo "${Green}swapfile未发现，正在为其创建swapfile${Font}" "${Green}swapfile not found, creating...${Font}"
	fallocate -l ${swapsize}M /swapfile
	chmod 600 /swapfile
	mkswap /swapfile
	swapon /swapfile
	echo '/swapfile none swap defaults 0 0' >> /etc/fstab
         lang_echo "${Green}swap创建成功，并查看信息：${Font}" "${Green}Swap created. Details:${Font}"
         cat /proc/swaps
         cat /proc/meminfo | grep Swap
else
	lang_echo "${Red}swapfile已存在，swap设置失败，请先运行脚本删除swap后重新设置！${Font}" "${Red}swapfile already exists. Delete it first before re-adding!${Font}"
fi
}

del_swap(){
#检查是否存在swapfile
grep -q "swapfile" /etc/fstab

#如果存在就将其移除
if [ $? -eq 0 ]; then
	lang_echo "${Green}swapfile已发现，正在将其移除...${Font}" "${Green}swapfile found, removing...${Font}"
	sed -i '/swapfile/d' /etc/fstab
	echo "3" > /proc/sys/vm/drop_caches
	swapoff -a
	rm -f /swapfile
    lang_echo "${Green}swap已删除！${Font}" "${Green}Swap removed!${Font}"
else
	lang_echo "${Red}swapfile未发现，swap删除失败！${Font}" "${Red}swapfile not found, nothing to delete!${Font}"
fi
}

#开始菜单
main(){
root_need
ovz_no
clear
echo -e "———————————————————————————————————————"
lang_echo "${Green}Linux VPS一键添加/删除swap脚本${Font}" "${Green}Linux VPS swap add/remove script${Font}"
lang_echo "${Green}1、添加swap${Font}" "${Green}1) Add swap${Font}"
lang_echo "${Green}2、删除swap${Font}" "${Green}2) Delete swap${Font}"
echo -e "———————————————————————————————————————"
read -p "$(lang_text "请输入数字 [1-2]:" "Enter choice [1-2]: ")" num
case "$num" in
    1)
    add_swap
    ;;
    2)
    del_swap
    ;;
    *)
    clear
    lang_echo "${Green}请输入正确数字 [1-2]${Font}" "${Green}Please enter a valid number [1-2]${Font}"
    sleep 2s
    main
    ;;
    esac
}
main
