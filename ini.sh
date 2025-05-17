#!/bin/bash
set -e

TUN_NAME="tun0"
OUT_IF="wlan0"

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

# 启用转发
echo 1 > /proc/sys/net/ipv4/ip_forward

sudo iptables -t nat -A POSTROUTING -o $OUT_IF -j MASQUERADE

echo "[✓] $TUN_NAME 已启用（不绑定 IP，供程序监听）"
