import os
import sys
from scapy.all import *
import binascii
import math
import netifaces
import time
import threading
import requests
from datetime import datetime
import json

def parser_ethernet(ethernet_header):
    dst_mac = ethernet_header[0:12]
    src_mac = ethernet_header[12:24]
    eth_type = ethernet_header[24:28]
    eth_type = int(eth_type,16)
    if show_all == 1:
        print("****************************************")
        print("***        Ethernet Header           ***")
        print("****************************************")
        print("*** src_mac        * %s    ***" %(dst_mac))
        print("*** dst_mac        * %s    ***" %(src_mac))
        print("*** eth_type       * %s    ***" %(eth_type))
    return eth_type

def parser_probe(probe_header):
    hop_cnt = probe_header[0:2]
    hop_cnt = int(hop_cnt,16)
    data_cnt = probe_header[2:4]
    data_cnt = int(data_cnt,16)
    clone = probe_header[4:6]
    clone = int(clone,16)
    if show_all == 1:
        print("****************************************")
        print("***           PROBE Header           ***")
        print("****************************************")
        print("*** hop count * %d ***" %(hop_cnt))
        print("*** datacount * %d ***" %(data_cnt))
        print("*** clone * %d ***" %(clone))
    return hop_cnt, data_cnt, clone

def parser_probe_fwd(probe_fwd_header):
    swid = probe_fwd_header
    swid = int(swid,16)
    if show_all == 1:
        print("****************************************")
        print("***       PROBE FWD Header           ***")
        print("****************************************")
        print("*** swid * %d ***" %(swid))
    return 0

def parser_probe_data(probe_data_header):
    global data
    # print(probe_data_header)
    swid = probe_data_header[0:2]
    port_ingress = probe_data_header[2:4]
    port_egress = probe_data_header[4:6]
    byte_ingress = probe_data_header[6:14]
    byte_egress = probe_data_header[14:22]
    count_ingress = probe_data_header[22:30]
    count_egress = probe_data_header[30:38]
    last_time_ingress = probe_data_header[38:50]
    last_time_egress = probe_data_header[50:62]
    current_time_ingress = probe_data_header[62:74]
    current_time_egress = probe_data_header[74:86]
    qdepth = probe_data_header[86:94]
    swid = int(swid,16)
    port_ingress = int(port_ingress,16)
    port_egress = int(port_egress,16)
    byte_ingress = int(byte_ingress,16)
    byte_egress = int(byte_egress,16)
    count_ingress = int(count_ingress,16)
    count_egress = int(count_egress,16)
    last_time_ingress = int(last_time_ingress,16)
    last_time_egress = int(last_time_egress,16)
    current_time_ingress = int(current_time_ingress,16)
    current_time_egress = int(current_time_egress,16)
    qdepth = int(qdepth,16)
    data_ = {}
    data_['swid'] = swid
    data_['port_ingress'] = port_ingress
    data_['port_egress'] = port_egress
    data_['byte_ingress'] = byte_ingress
    data_['byte_egress'] = byte_egress
    data_['count_ingress'] = count_ingress
    data_['count_egress'] = count_egress
    data_['last_time_ingress'] = last_time_ingress
    data_['last_time_egress'] = last_time_egress
    data_['current_time_ingress'] = current_time_ingress
    data_['current_time_egress'] = current_time_egress
    data_['qdepth'] = qdepth
    data.append(data_)
    #print(f"Added new data: {data_}")
    if show_all == 1:
        print("****************************************")
        print("***       PROBE DATA Header          ***")
        print("****************************************")
        print("*** swid * %d ***" %(swid))
        print("*** port_ingress * %d ***" %(port_ingress))
        print("*** port_egress * %d ***" %(port_egress))
        print("*** byte_ingress * %d ***" %(byte_ingress))
        print("*** byte_egress * %d ***" %(byte_egress))
        print("*** count_ingress * %d ***" %(count_ingress))
        print("*** count_egress * %d ***" %(count_egress))
        print("*** last_time_ingress * %d ***" %(last_time_ingress))
        print("*** last_time_egress * %d ***" %(last_time_egress))
        print("*** current_time_ingress * %d ***" %(current_time_ingress))
        print("*** current_time_egress * %d ***" %(current_time_egress))
        print("*** qdepth * %d ***" %(qdepth))

def parser_packet(aaa):
    global data    #使用全局变量
    data.clear()   #清空列表
    # print("whole: %s" %(aaa))
    ethernet_header = aaa[0:28]
    eth_type = parser_ethernet(ethernet_header)
    if (eth_type == 2066):
        probe_header = aaa[28:34]
        hop_cnt, data_cnt, clone = parser_probe(probe_header)
        start = 34
        for i in range(hop_cnt):
            probe_fwd_header = aaa[start:start+2]
            parser_probe_fwd(probe_fwd_header)
            start = start + 2
        for i in range(data_cnt):
            probe_data_header = aaa[start:start+94]
            parser_probe_data(probe_data_header)
            start = start + 94
        #print(f"Updated data list: {data}")   #打印更新数据
        for i in range(data_cnt - 1):
            data1 = data[i+1]  #上一个交换机
            data2 = data[i]    #当前交换机
            node1 = data1['swid']  #上一个交换机
            node2 = data2['swid']  #当前交换机
            time1_bw = data2['current_time_egress']  #当前INT包在上一跳交换机出口处的当前时间
            time2_bw = data2['last_time_egress']     #当前交换机上一个INT包出口处时间
            byte_bw = data2['byte_egress']           #出口处字节数
            time1_dalay = data1['current_time_egress']   #当前INT包在上一跳交换机出口处的当前时间
            time2_dalay = data2['current_time_ingress']  #当前INT包在这一跳进口处的当前时间
            drop1 = data1['count_egress']  #上一跳交换机出口处包个数
            drop2 = data2['count_ingress']  #当前交换机进口处包个数
            print(drop1)
            print(drop2)    
            utilization = 0 if time1_bw == time2_bw else  8.0 * byte_bw / (time1_bw - time2_bw)
            droppkt = drop1 - drop2
            delay = time2_dalay -  time1_dalay
            print("node1:{} node2:{} delay:{}us bw:{} Mbps droppkt:{} \n".format(node1, node2, delay, utilization, droppkt))

    
def receive_probe_pkt(pkt):
    sys.stdout.flush()
    #aaa = str(pkt).hex()
    c = binascii.b2a_hex(bytes(pkt))
    d = str(c)
    # print(d)
    parser_packet(d[2:len(d)-1])

def get_if(s):
    ifs=netifaces.interfaces()
    ifs_ = []
    for i in ifs:
        if "-"+s in i:
            ifs_.append(i)
    return ifs_

def find_target_interfaces(suffix="-eth0"):
    """
    自动查找所有以 -eth0 结尾的网卡
    """
    all_ifs = netifaces.interfaces()
    target_ifs = [i for i in all_ifs if i.endswith(suffix)]
    return target_ifs


if __name__ == '__main__':
    show_all = 1
    data = []
    iface = get_if("eth0")
    print("sniffing on %s" % iface)
    print("*************** START ***************")
    sys.stdout.flush()
    sniff(iface = iface, prn = lambda x: receive_probe_pkt(x))
