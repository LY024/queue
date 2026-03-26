import os
import sys
from scapy.all import *
import binascii
import netifaces

# --- 全局变量 ---
show_all = 1
data = []

def parser_ethernet(ethernet_header):
    dst_mac = ethernet_header[0:12]
    src_mac = ethernet_header[12:24]
    eth_type = int(ethernet_header[24:28], 16)
    if show_all == 1:
        print("-" * 40)
        print(f"Ethernet: SRC={src_mac} DST={dst_mac} TYPE={eth_type}")
    return eth_type

def parser_probe(probe_header):
    hop_cnt = int(probe_header[0:2], 16)
    data_cnt = int(probe_header[2:4], 16)
    if show_all == 1:
        print(f"PROBE Header: HopCnt={hop_cnt}, DataCnt={data_cnt}, Clone={clone}")
    return hop_cnt, data_cnt

def parser_probe_data(probe_data_header):
    global data
    # 按照 94 字符(47字节)的偏移解析
    d_ = {
        'swid': int(probe_data_header[0:2], 16),
        'port_ingress': int(probe_data_header[2:4], 16),
        'port_egress': int(probe_data_header[4:6], 16),
        'byte_ingress': int(probe_data_header[6:14], 16),
        'byte_egress': int(probe_data_header[14:22], 16),
        'count_ingress': int(probe_data_header[22:30], 16),
        'count_egress': int(probe_data_header[30:38], 16),
        'last_time_ingress': int(probe_data_header[38:50], 16),
        'last_time_egress': int(probe_data_header[50:62], 16),
        'current_time_ingress': int(probe_data_header[62:74], 16),
        'current_time_egress': int(probe_data_header[74:86], 16),
        'qdepth': int(probe_data_header[86:94], 16)
    }
    data.append(d_)

def parser_packet(packet_hex):
    global data
    data.clear()
    
    # 解析以太网头
    eth_type = parser_ethernet(packet_hex[0:28])
    
    # 2066 (0x0812) 假设为你定义的 INT 协议号
    if eth_type == 2066:
        probe_header = packet_hex[28:34]
        hop_cnt, data_cnt, clone = parser_probe(probe_header)
        
        start = 34
        # 跳过转发头 (FWD Header)
        start += (hop_cnt * 2)
        
        # 解析数据段
        for _ in range(data_cnt):
            if len(packet_hex) >= start + 94:
                parser_probe_data(packet_hex[start:start+94])
                start += 94

        # 计算链路指标 (反向遍历计算每一跳)
        for i in range(len(data) - 1):
            d_curr = data[i]     # 当前交换机
            d_prev = data[i+1]   # 上一跳交换机
            
            # 计算带宽利用率 (假设时间单位与字节匹配)
            time_diff = d_curr['current_time_egress'] - d_curr['last_time_egress']
            utilization = (8.0 * d_curr['byte_egress'] / time_diff) if time_diff > 0 else 0
            
            # 计算时延与丢包
            delay = d_curr['current_time_ingress'] - d_prev['current_time_egress']
            drop_pkt = d_prev['count_egress'] - d_curr['count_ingress']
            
            print(f"Link: {d_prev['swid']} -> {d_curr['swid']} | Delay: {delay}us | BW: {utilization:.2f}Mbps | Drop: {drop_pkt}")

def receive_probe_pkt(pkt):
    try:
        raw_hex = binascii.hexlify(bytes(pkt)).decode()
        parser_packet(raw_hex)
    except Exception as e:
        pass # 忽略畸形包

def find_target_interfaces(suffix="-eth0"):
    """
    自动查找所有以 -eth0 结尾的网卡
    """
    all_ifs = netifaces.interfaces()
    target_ifs = [i for i in all_ifs if i.endswith(suffix)]
    return target_ifs

if __name__ == '__main__':
    # 自动识别网卡
    ifaces = find_target_interfaces("-eth0")
    
    if not ifaces:
        print("Error: 未找到符合 '***-eth0' 格式的网卡!")
        sys.exit(1)
        
    print(f"Sniffing on: {ifaces}")
    print("*************** START MONITORING ***************")
    sys.stdout.flush()
    
    # 开始抓包，store=0 防止内存泄漏
    sniff(iface=ifaces, prn=receive_probe_pkt, store=0)