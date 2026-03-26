import subprocess
import sys

def update_switch_register(thrift_port, value):
    """
    向指定端口的交换机发送寄存器修改命令
    """
    print(f"--- Updating Switch on port {thrift_port} to value {value} ---")
    
    # 构造 CLI 命令：先重置，再写入，后读取验证
    commands = [
        'register_reset transmition_model',
        f'register_write transmition_model 0 {value}',
        'register_read transmition_model 0'
    ]
    
    input_str = "\n".join(commands) + "\n"
    
    try:
        process = subprocess.Popen(
            f'simple_switch_CLI --thrift-port {thrift_port}',
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        out, err = process.communicate(input=input_str)
        
        if err and "RuntimeCmd" not in err: # 忽略正常的交互式提示错误
            print(f"Error on port {thrift_port}: {err}")
        else:
            # 提取读取结果进行展示
            lines = out.splitlines()
            for line in lines:
                if "transmition_model[0]" in line:
                    print(f"Confirmation from port {thrift_port}: {line.strip()}")
            
    except Exception as e:
        print(f"Failed to connect to port {thrift_port}: {e}")

if __name__ == "__main__":
    # --- 参数解析逻辑 ---
    
    # 默认值
    target_value = 0
    target_ports = [9090, 9091, 9092, 9093, 9094, 9095]

    # 如果提供了参数
    if len(sys.argv) > 1:
        # 第一个参数是开关状态 (0 或 1)
        try:
            target_value = int(sys.argv[1])
        except ValueError:
            print("错误: 第一个参数必须是 0 或 1")
            sys.exit(1)
        
        # 如果后续还有参数，则是指定的端口列表
        if len(sys.argv) > 2:
            try:
                target_ports = [int(p) for p in sys.argv[2:]]
            except ValueError:
                print("错误: 端口号必须是整数")
                sys.exit(1)

    print(f"Action: {'OPEN' if target_value == 1 else 'CLOSE'} (Value: {target_value})")
    print(f"Target Ports: {target_ports}")
    print("-" * 40)

    # 遍历执行
    for port in target_ports:
        update_switch_register(port, target_value)

    print("\nAll queue switch operations completed.")