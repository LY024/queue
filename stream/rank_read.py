import subprocess

def update_switch_register(thrift_port, switch_name):
    print(f"--- Updating {switch_name} on port {thrift_port} ---")
    
    # 构造 CLI 命令
    # 我们将所有指令一次性写入 stdin
    commands = [
        'register_read queue_bound 0',
        'register_read queue_bound 1',
        'register_read queue_bound 2',
        'register_read queue_bound 3',
        'register_read queue_bound 4',
        'register_read queue_bound 5',
        'register_read queue_bound 6',
        'register_read queue_bound 7' 
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
        
        if err:
            print(f"Error on {switch_name}: {err}")
        else:
            print(f"Output from {switch_name}:\n{out}")
            
    except Exception as e:
        print(f"Failed to connect to {switch_name}: {e}")

if __name__ == "__main__":
    # 定义交换机名称与对应端口的映射
    switches = [
        ("s176", 9090),
        ("s178", 9091),
        ("s182", 9092),
        ("s184", 9093),
        ("s186", 9094),
        ("s188", 9095)
    ]

    for name, port in switches:
        update_switch_register(port, name)

    print("All registration updates completed.")