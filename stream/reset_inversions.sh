#!/bin/bash
# reset_inversions.sh

# 1. 设置端口：如果没有参数则使用默认 9090-9095
if [ "$#" -eq 0 ]; then
    TARGET_PORTS=(9090 9091 9092 9093 9094 9095)
else
    TARGET_PORTS=("$@")
fi

echo "Targeting Switch Ports: ${TARGET_PORTS[*]}"
echo "--------------------------------------------------"

# 2. 遍历端口
for PORT in "${TARGET_PORTS[@]}"
do
    echo "[Port $PORT] Processing Registers..."
    
    # 构造命令字符串
    # 每一个 reset 后面跟一个 read，用于查看结果
    COMMANDS="register_reset total_inversions
register_read total_inversions 0
register_reset rank_inversions_sppifo
register_read rank_inversions_sppifo 0
register_reset rank_inversions_fifo
register_read rank_inversions_fifo 0
register_reset last_enqueued_rank
register_read last_enqueued_rank 0"

    # 执行命令
    # 去掉了 grep，改用 simple_switch_CLI 的 --no-status 模式（如果支持）或直接输出
    # 如果你的 simple_switch_CLI 版本较老，直接运行即可
    echo "$COMMANDS" | simple_switch_CLI --thrift-port $PORT
    
    echo "--------------------------------------------------"
done

echo "All specified registers processed."