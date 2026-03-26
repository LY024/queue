
# Stream 脚本说明（中文）

概述
----
本目录包含用于 P4/交换机测试的脚本与工具，主要涉及基于 iperf3 的流生成/接收，以及通过 simple_switch_CLI 操作交换机寄存器、采集并绘图的脚本。

全局依赖
----
- iperf3（用于网络流量生成/接收）
- simple_switch_CLI（用于通过 Thrift 操作交换机寄存器）
- Python3，及包：matplotlib、numpy（用于绘图与分析）
- 部分脚本需要 root 权限（使用 sudo 运行）

文件说明与用法
----

1) server.sh
- 功能：在本机并行启动多个 iperf3 服务端（每个端口一个 server），每个 server 使用 -1 参数接收一次连接后退出，并把输出写入 server_log。
- 用法：sudo ./server.sh <流数量>
- 示例：sudo ./server.sh 16
- 输出：server_log/server_log_*.txt
- 默认端口：从 5201 开始，连续 NUM_STREAMS 个端口。

2) client.sh
- 功能：并行向目标 IP 发起指定数量的 UDP iperf3 流（每流不同端口与 TOS），并把每个流的日志写入 client_log。
- 用法：sudo ./client.sh <目标IP> <流数量> <持续时间>
- 示例：sudo ./client.sh 10.164.164.2 16 20
- 参数说明：带宽 -b 2M、TOS = (i+1)、默认端口从 5201 起。
- 输出：client_log/client_log_*.txt

3) reset_inversions.sh
- 功能：遍历目标 thrift 端口，重置并读取若干统计寄存器（如 total_inversions、rank_inversions_*、last_enqueued_rank）。
- 用法：./reset_inversions.sh [port1 port2 ...]
- 示例：./reset_inversions.sh 9090 9091
- 默认端口：9090 9091 9092 9093 9094 9095
- 注意：需确保 simple_switch_CLI 在 PATH 中并且对应的 thrift 服务在监听。

4) read_inversions.py
- 功能：读取交换机上有关反转（inversions）的寄存器，解析数值并绘制图表（保存为 report_port_<port>.png）。
- 用法：python3 read_inversions.py [port1 port2 ...]
- 示例：python3 read_inversions.py 9090 9091
- 默认端口：9090-9095（若未提供参数）
- 配置：脚本顶部 CLI_BIN 可调整为实际的 simple_switch_CLI 可执行路径
- 依赖：matplotlib、numpy

5) rank_reset.py
- 功能：对一组交换机（脚本内定义）执行 register_reset queue_bound 并读取以确认。
- 用法：python3 rank_reset.py
- 脚本内部有 switch 名称与 thrift 端口映射（可按需修改）。

6) rank_read.py
- 功能：依次读取 queue_bound 的多个索引（0..7）以检查队列边界设置。
- 用法：python3 rank_read.py
- 输出：在 stdout 打印 simple_switch_CLI 的返回信息。

7) queue_switch.py
- 功能：切换传输模型寄存器 transmition_model（先 reset，再写入，再读回以确认），支持对多个 thrift 端口并行操作。
- 用法：python3 queue_switch.py <0|1> [port1 port2 ...]
- 示例：python3 queue_switch.py 1 9090 9091
- 默认端口：9090-9095（当未提供端口参数时）

常见注意事项
----
- 运行 server.sh 与 client.sh 时通常需要 sudo 权限（使用原脚本的提示）。
- 确保 simple_switch_CLI 可以连接到目标交换机的 thrift 端口（9090-9095 为常用设置）。
- 如果 CLI 返回异常或找不到命令，请检查环境变量 PATH 或指定脚本中 CLI_BIN 的绝对路径。
- 若要批量处理，请先用 reset_inversions.sh 清理统计，再用 client/server 产生流量，最后用 read_inversions.py 收集并绘图。

合规提示
----
- 修改寄存器与重启服务会影响交换机行为，请在受控测试环境中操作。
- 日志和图表会保存在当前目录下的 client_log、server_log 和 report_port_*.png。

结束
----
将 README.md 保存到本目录后，用户可按上述示例运行相应脚本进行测试与数据采集。