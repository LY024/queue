#!/bin/bash
# client.sh

# 1. 检查输入参数
if [ "$#" -ne 3 ]; then
    echo "使用方法: sudo $0 <目标IP> <流数量> <持续时间>"
    echo "实例: sudo $0 10.164.164.2 16 20"
    exit 1
fi

DEST_IP=$1
NUM_STREAMS=$2
DURATION=$3
BASE_PORT=5201

# 2. 准备环境
mkdir -p client_log
echo "Starting $NUM_STREAMS parallel streams to $DEST_IP for $DURATION seconds..."

# 3. 循环启动子流
# 使用 seq 生成从 0 到 (NUM_STREAMS-1) 的序列
for i in $(seq 0 $((NUM_STREAMS - 1)))
do
    CURRENT_PORT=$((BASE_PORT + i))
    # TOS 值设定：根据需求这里设为 i+1
    TOS_VALUE=$((i + 1)) 

    echo "Stream $i: Port $CURRENT_PORT, TOS $TOS_VALUE"
    
    # 后台运行 iperf3 (UDP 模式)
    # -S 指定 TOS，-b 2M 限制带宽
    iperf3 -u -c "$DEST_IP" -p "$CURRENT_PORT" -S "$TOS_VALUE" -t "$DURATION" -i 1 -b 2M --logfile "client_log/client_log_$i.txt" & 
done

# 等待所有后台进程结束
wait
echo "All $NUM_STREAMS streams finished."