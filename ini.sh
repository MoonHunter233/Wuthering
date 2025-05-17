#!/bin/bash
set -e

TUN_NAME="tun0"

echo "[+] 创建 TUN 接口 $TUN_NAME"

# 检查 /dev/net/tun 是否存在
# if [ ! -c /dev/net/tun ]; then
#     echo "[-] /dev/net/tun 不存在，请加载 tun 模块：sudo modprobe tun"
#     exit 1
# fi

# 创建 TUN 接口
sudo ip tuntap add dev $TUN_NAME mode tun

# 启用接口（无需设置 IP）
sudo ip link set $TUN_NAME up

echo "[✓] $TUN_NAME 已启用（不绑定 IP，供程序监听）"
