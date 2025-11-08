# One-Script 多协议一键安装脚本

基于 V2Ray-Agent 的八合一共存脚本，支持多操作系统，提供安装、配置、管理功能。

## 一键安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/charleslkx/one-script/master/main.sh)
```

## 文件说明

- `main.sh` 统一管理脚本
- `hy2.sh` Hysteria2 安装脚本
- `v2ray.sh` V2Ray 安装脚本
- `swap.sh` Swap 管理脚本
- `install_kernel.sh` kernel 脚本

## 主要功能

- Hysteria 2/V2Ray/Xray/REALITY/Tuic 多协议共存
- 智能 Swap 管理
- 内核安装和配置管理
- 自动端口跳跃（Hysteria2 专属）
- 防火墙规则持久化
- 自动定时重启
- 一键命令 hy2 快速启动
- 默认出站优先 IPv6，无法命中 IPv6 时自动回落 IPv4

## 使用说明

### 统一管理（推荐）

```bash
# 下载并运行主脚本
bash <(curl -fsSL https://raw.githubusercontent.com/charleslkx/one-script/master/main.sh)
```

- 按提示初始化环境（root 权限、swap、虚拟化检查）
- 选择所需功能（V2Ray、Hysteria2、Swap、kernel 脚本、脚本更新等）
- 可通过菜单或参数安装 hy2 命令，安装后可用 `sudo hy2` 快速启动

### 传统安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/charleslkx/one-script/master/hy2.sh)
```

## 常用命令

```bash
./main.sh --help              # 帮助信息
./main.sh --version           # 版本信息
./main.sh --install-command   # 安装 hy2 命令
./main.sh --uninstall-command # 卸载 hy2 命令
```

## 注意事项

- 建议使用纯净系统环境，需 root 权限
- 需准备域名并正确解析
- OpenVZ 不支持 swap

## 故障排除

- 检查磁盘空间：`df -h`
- 测试 swap 创建：`fallocate -l 1G /test_swapfile && rm /test_swapfile`
- 检查 hy2 命令：`which hy2`
- 重新安装命令：`bash main.sh --install-command`

## 鸣谢

- [v2ray-agent](https://github.com/mack-a/v2ray-agent)
- [v2ray](https://github.com/233boy/v2ray)
- [one_click_script](https://github.com/jinwyp/one_click_script)

## 免责声明

仅供学习和研究使用，风险自负。
