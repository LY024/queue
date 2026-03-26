import subprocess
import matplotlib.pyplot as plt
import numpy as np
import sys
import os

# ================= 配置区 =================
CLI_BIN = "simple_switch_CLI"

# 寄存器名称
REG_TOTAL = "total_inversions"
REG_RANK_SP = "rank_inversions_sppifo"
REG_RANK_FIFO = "rank_inversions_fifo"
# =========================================

def run_cli_command(thrift_port, command):
    """执行 CLI 命令并返回原始输出字符串"""
    full_cmd = f"echo '{command}' | {CLI_BIN} --thrift-port {thrift_port}"
    try:
        output = subprocess.check_output(full_cmd, shell=True, stderr=subprocess.STDOUT).decode('utf-8')
        return output
    except subprocess.CalledProcessError:
        return ""

def parse_register_values(raw_output):
    """解析 CLI 返回的批量或单值格式"""
    values = []
    for line in raw_output.split('\n'):
        if '=' in line:
            right_part = line.split('=')[1].strip()
            if ',' in right_part:
                parts = right_part.split(',')
                for p in parts:
                    if p.strip():
                        values.append(int(p.strip()))
            else:
                if right_part:
                    try:
                        values.append(int(right_part))
                    except ValueError:
                        continue
    return values

def process_switch(thrift_port):
    print(f"\n" + "="*50)
    print(f"正在处理交换机端口: {thrift_port}")
    print("="*50)

    # 1. 读取总反转次数 (索引0: SP-PIFO, 索引1: FIFO)
    raw_total = run_cli_command(thrift_port, f"register_read {REG_TOTAL}")
    if not raw_total:
        print(f"无法连接到端口 {thrift_port} 或寄存器不存在。")
        return

    total_vals = parse_register_values(raw_total)

    if len(total_vals) < 2:
        print(f"端口 {thrift_port}: 无法获取足够的反转数据 (可能尚未产生流量)。")
        return

    sp_total = total_vals[0]
    fifo_total = total_vals[1]
    
    improvement = ((fifo_total - sp_total) / fifo_total * 100) if fifo_total > 0 else 0

    print(f"数据采集成功:")
    print(f"  [SP-PIFO] 总反转数: {sp_total}")
    print(f"  [FIFO    ] 总反转数: {fifo_total}")
    print(f"  [性能提升] 减少了 {improvement:.2f}% 的反转")

    # 2. 读取 Rank 分布
    raw_sp_ranks = run_cli_command(thrift_port, f"register_read {REG_RANK_SP}")
    raw_fifo_ranks = run_cli_command(thrift_port, f"register_read {REG_RANK_FIFO}")
    
    sp_ranks = parse_register_values(raw_sp_ranks)
    fifo_ranks = parse_register_values(raw_fifo_ranks)

    # 3. 绘图逻辑
    if sp_total > 0 or fifo_total > 0:
        draw_plots(thrift_port, sp_total, fifo_total, sp_ranks, fifo_ranks)
    else:
        print(f"端口 {thrift_port}: 数据全为 0，跳过绘图。")

def draw_plots(port, sp_total, fifo_total, sp_ranks, fifo_ranks):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

    # --- 左图：柱状图对比 ---
    methods = ['SP-PIFO', 'FIFO']
    counts = [sp_total, fifo_total]
    colors = ['#1f77b4', '#d62728']
    
    bars = ax1.bar(methods, counts, color=colors, width=0.6)
    ax1.set_title(f'Total Inversions (Port {port})', fontsize=12)
    ax1.set_ylabel('Count')
    for bar in bars:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                f'{int(height)}', ha='center', va='bottom', fontweight='bold')

    # --- 右图：Rank 分布图 (前 64) ---
    plot_range = 64 
    x = np.arange(plot_range)
    # 填充 0 确保长度匹配
    y_sp = (sp_ranks[:plot_range] + [0]*plot_range)[:plot_range]
    y_fifo = (fifo_ranks[:plot_range] + [0]*plot_range)[:plot_range]

    ax2.plot(x, y_sp, label='SP-PIFO', color='#1f77b4', linewidth=2)
    ax2.plot(x, y_fifo, label='FIFO', color='#d62728', linestyle='--', alpha=0.7)
    
    ax2.set_title(f'Distribution (First {plot_range} Ranks)', fontsize=12)
    ax2.set_xlabel('Rank')
    ax2.set_ylabel('Freq')
    ax2.legend()
    ax2.grid(True, linestyle=':', alpha=0.5)

    plt.suptitle(f'Switch Performance Analysis - Port {port}', fontsize=16)
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    
    output_file = f"report_port_{port}.png"
    plt.savefig(output_file)
    print(f"图表已保存至: {output_file}")
    plt.close()

if __name__ == "__main__":
    # --- 参数解析核心部分 ---
    
    # 1. 检查是否有命令行参数输入
    if len(sys.argv) > 1:
        # 使用用户输入的端口
        ports = sys.argv[1:]
    else:
        # 默认端口列表 9090-9095
        print("未检测到输入端口，使用默认端口: 9090-9095")
        ports = [9090, 9091, 9092, 9093, 9094, 9095]

    # 2. 遍历执行
    for p in ports:
        try:
            # 确保端口为字符串格式传递给 process_switch
            process_switch(str(p))
        except Exception as e:
            print(f"处理端口 {p} 时发生错误: {e}")

    print("\n所有指定的交换机数据分析完成。")