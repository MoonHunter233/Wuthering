#!/bin/bash
DEV=tun0
TUN_IP=192.168.99.1
TUN_NET=192.168.99.0/24
# OUTIF=wlan0  # 或者 eth0，看你实际的网络设备

# 创建并配置 tun0
ip tuntap add dev $DEV mode tun
ip addr add $TUN_IP/24 dev $DEV
ip link set dev $DEV up

# 启用转发
echo 1 > /proc/sys/net/ipv4/ip_forward
