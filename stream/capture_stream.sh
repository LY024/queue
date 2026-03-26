#!/bin/bash

# 检查参数数量是否正确
if [ "$#" -ne 2 ]; then
    echo "使用方法: $0 <目标IP> <文件名>"
    echo "示例: sudo $0 10.170.170.2 test_traffic_164"
    exit 1
fi

TARGET_IP=$1
FILE_NAME=$2

# 检查是否以 root 权限运行（tcpdump 通常需要）
if [ "$EUID" -ne 0 ]; then
  echo "请使用 sudo 运行此脚本"
  exit 1
fi

echo "正在开始抓包..."
echo "目标 IP: $TARGET_IP"
echo "保存文件: ${FILE_NAME}.pcap"
echo "按 Ctrl+C 停止抓包"

# 执行 tcpdump
# 这里自动补全了 .pcap 后缀，如果你输入时已经带了后缀，可以去掉下面的 .pcap
tcpdump -i any dst host "$TARGET_IP" -w "${FILE_NAME}.pcap"