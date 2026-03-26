#!/bin/bash
# server.sh

# 1. 检查输入参数
# 如果没有提供参数，则默认开启 16 个流，或者显示使用说明
if [ "$#" -lt 1 ]; then
    echo "使用方法: sudo $0 <流数量>"
    echo "实例: sudo $0 16"
    # 如果你想让它更智能，可以设置一个默认值：NUM_STREAMS=16
    # 但为了严谨，这里要求显式输入
    exit 1
fi

NUM_STREAMS=$1
BASE_PORT=5201

# 2. 彻底清理后台残留进程，防止端口占用导致启动失败
echo "Cleaning up existing iperf3 processes..."
sudo pkill iperf3

# 3. 准备日志目录
mkdir -p server_log

echo "Starting $NUM_STREAMS iperf3 servers (Ports $BASE_PORT to $((BASE_PORT + NUM_STREAMS - 1)))..."

# 4. 循环启动服务端
for i in $(seq 0 $((NUM_STREAMS - 1)))
do
    CURRENT_PORT=$((BASE_PORT + i))
    
    # -s: 以服务端模式运行
    # -p: 指定监听端口
    # -1: 接收一次客户端连接并完成传输后自动退出（非常适合自动化测试）
    # --logfile: 将输出重定向到指定文件
    iperf3 -s -p "$CURRENT_PORT" -1 --logfile "server_log/server_log_$i.txt" &
done

# 5. 等待所有后台 server 进程结束
# 因为使用了 -1 参数，当 client.sh 运行结束时，这些 server 进程也会随之正常退出
wait

echo "All $NUM_STREAMS servers have received data and closed."