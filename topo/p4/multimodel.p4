/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#define PKT_INSTANCE_TYPE_IGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_NORMAL 0

//------------------------------------------------------------
// 定义协议号
const bit<16> TYPE_ARP = 0x0806;
const bit<16> TYPE_PROBE = 0x0812;
const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  IP_PROTO_ICMP = 0x01;
const bit<8>  IP_PROTO_TCP = 0x06;
const bit<8>  IP_PROTO_UDP = 0x11;

#define MAX_HOPS 10
#define MAX_PORTS 10
#define NUM_BUCKETS 101000
//ECCN统计最大流数目

// ECCN与multipath判断
register< bit<32> >(8) transmition_model;
// 共8个寄存器，索引为32位，每个寄存器存一个32位的数
// transmition_model[0]=1，则使用ECCN，=0则不用，并且保证transmition_model[2]=0
// transmition_model[1]=1，则使用多路径，=0则不用，并且保证transmition_model[2]=0、transmition_model[3]=0
// transmition_model[2]=1, 则使用拥塞感知功能，并且保证transmition_model[0]=0、transmition_model[1]=0、transmition_model[3]=0、transmition_model[4]=0
// transmition_model[3]=1, 则使用多路径冗余传输算法，并且保证transmition_model[0]=0、transmition_model[1]=0、transmition_model[2]=0
// transmition_model[4]=1, 则开启并使用优先级队列，并且保证transmition_model[2]=0

// multipath寄存器
register< bit<32> >(8) multipath_ability;
// 共8个寄存器，索引为32位，每个寄存器存一个32位的数
// multipath_ability[0]=1，则支持多路径，=0则不支持
register< bit<32> >(8) multipath_count; 
// 共8个寄存器，索引为32位，每个寄存器存32位的数
// multipath_count[2,3,4]分别代表端口2,3,4的发包量
register< bit<32> >(8) multipath_initial;
// 共8个寄存器，索引为32位，每个寄存器存32位的数
// multipath_initial[2,3,4]分别代表端口2,3,4的发包初始量
register< bit<32> >(8) multipath_order;
// 共8个寄存器，索引为32位，每个寄存器存32位的数
// multipath_order[2,3,4]分别代表端口2,3,4的发包顺序

//INT寄存器
register<bit<32>>(MAX_PORTS) int_byte_ingress; 
// 共MAX_PORTS个寄存器，索引为32位，每个寄存器存32位的数
// 存储端口累积入流量，INT协议使用，int_byte_ingress[1]代表端口1的累计入流量
register<bit<32>>(MAX_PORTS) int_byte_egress; 
// 共MAX_PORTS个寄存器，索引为32位，每个寄存器存32位的数
// 存储端口累积出流量，INT协议使用，int_byte_egress[1]代表端口1的累计出流量
register<bit<32>>(MAX_PORTS) int_count_ingress;
// 共MAX_PORTS个寄存器，索引为32位，每个寄存器存32位的数
// 存储端口累积入个数，INT协议使用，int_count_ingress[1]代表端口1的累计入个数
register<bit<32>>(MAX_PORTS) int_count_egress;
// 共MAX_PORTS个寄存器，索引为32位，每个寄存器存32位的数
// 存储端口累积出个数，INT协议使用，int_count_egress[1]代表端口1的累计出个数
register<bit<48>>(MAX_PORTS) int_last_time_ingress; 
// 共MAX_PORTS个寄存器，索引为32位，每个寄存器存48位的数
// 存储上一个INT包进入端口时间，INT协议使用，int_last_time_ingress[1]代表端口1的入INT包时间
register<bit<48>>(MAX_PORTS) int_last_time_egress; 
// 共MAX_PORTS个寄存器，索引为32位，每个寄存器存48位的数
// 存储上一个INT包离开出端口时间，INT协议使用，int_last_time_egress[1]代表端口1的出INT包时间

// ECCN寄存器
register<bit<48>>(NUM_BUCKETS) congestion_time_reg;
// 最近一次发生拥塞的时间，此时间的后一秒内收到的ACK都要被增加my_wnd字段
register<bit<48>>(1) num_flow;
// 统计经过数据流数量(有问题，只加)
register<bit<32>>(NUM_BUCKETS) byte_dropped_cnt_reg;
// 最近一次发生拥塞时，丢弃的字节数
register<bit<32>>(NUM_BUCKETS) max_cwnd_reg;
// 记录流最大拥塞窗口值
register<bit<32>>(NUM_BUCKETS) cur_cwnd_reg;
// 记录流当前拥塞窗口值
register<bit<48>>(NUM_BUCKETS) modify_time_reg;
// 记录上一次cwnd修改时间
// register<bit<48>>(NUM_BUCKETS) time_dif_reg;
// // 记录流修改间隔
// register<bit<32>>(NUM_BUCKETS) init_cwnd_reg;
// // 初始cwnd状态表

//------------------------------------------------------------
// 定义首部
// 物理层首部
header ethernet_h {
    bit<48>  dst_mac;
    bit<48>  src_mac;
    bit<16>  ether_type;
}
//--------------------------
// ARP首部
header arp_h {
    bit<16>  hardware_type;
    bit<16>  protocol_type;
    bit<8>   HLEN;
    bit<8>   PLEN;
    bit<16>  OPER;
    bit<48>  sender_ha;
    bit<32>  sender_ip;
    bit<48>  target_ha;
    bit<32>  target_ip;
}
//--------------------------
//INT首部
header probe_h {
    bit<8>    hop_cnt; // probe_fwd字段个数
    bit<8>    data_cnt; // probe_data字段个数
    bit<8>    clone;   // 标识是否为拥塞感知数据包
}
header probe_fwd_h {
    bit<8>   swid; // 交换机端口标识
}
header probe_data_h {
    bit<8>    swid; // 交换机标识
    bit<8>    port_ingress; // 入端口号
    bit<8>    port_egress; // 出端口号
    bit<32>   byte_ingress; // 入端口累计入流量
    bit<32>   byte_egress; // 出端口累计出流量
    bit<32>   count_ingress; // 入端口累计入个数
    bit<32>   count_egress; // 出端口累计出个数
    bit<48>   last_time_ingress; // 入端口上一个INT包进入时间
    bit<48>   last_time_egress; // 出端口上一个INT包离开时间
    bit<48>   current_time_ingress; // 入端口当前INT包进入时间
    bit<48>   current_time_egress; // 出端口当前INT包离开时间
    bit<32>   qdepth; // 队列长度
}
//--------------------------
// IPv4首部
header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}
//--------------------------
// ICMP首部
header icmp_h {
    bit<8>   type;
    bit<8>   code;
    bit<16>  hdr_checksum;
}
//--------------------------
//TCP首部
header tcp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<4>   res;
    bit<8>   flags;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}
//--------------------------
//UDP首部
header udp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<16>  hdr_length;
    bit<16>  checksum;
}
//--------------------------
//ECCN首部
header my_wnd_t{
	bit<8>		type;
	bit<8>		length;
	bit<16>		value;
}

header options_t{
	varbit<320>		nop_nop_timeStamps;
}
//--------------------------
struct metadata {
    bit<8> clone_id;
    bit<8> packet_can_multipath;
    bit<8> multipath_port;
    bit<8> int_hop_cnt;
    bit<8> int_data_cnt;
    bit<16> TCP_length;	
    bit<32> hash_value;
    bool isupdated;
    bit<48> cur_flow;
}
//--------------------------
//完整首部
struct headers {
    ethernet_h               ethernet;
    arp_h                    arp;
    probe_h                  probe;
    probe_fwd_h[MAX_HOPS]    probe_fwd;
    probe_data_h[MAX_HOPS]   probe_data;
    ipv4_h                   ipv4;
    icmp_h                   icmp;
    tcp_h                    tcp;
    udp_h                    udp;
    my_wnd_t		    my_wnd;
    my_wnd_t		    test_wnd;
    options_t		    options;
}
//------------------------------------------------------------
parser c_parser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        meta = {0, 0, 0, 0, 0, 0, 0, false, 0};
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_ARP: parse_arp;
            TYPE_PROBE: parse_probe;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
    state parse_probe {
        packet.extract(hdr.probe);
        meta.int_hop_cnt = hdr.probe.hop_cnt;
        meta.int_data_cnt = hdr.probe.data_cnt;
        transition parse_probe_fwd_h;
    }
    state parse_probe_fwd_h {
        transition select(meta.int_hop_cnt) {
            0: parse_probe_data_h;
            default: parse_probe_fwd;
        }
    }
    state parse_probe_fwd {
        packet.extract(hdr.probe_fwd.next);
        meta.int_hop_cnt = meta.int_hop_cnt - 1;
        transition select(meta.int_hop_cnt) {
            0: parse_probe_data_h;
            default: parse_probe_fwd;
        }
    }
    state parse_probe_data_h {
        transition select(meta.int_data_cnt) {
            0: accept;
            default: parse_probe_data;
        }
    }
    state parse_probe_data {
        packet.extract(hdr.probe_data.next);
        meta.int_data_cnt = meta.int_data_cnt - 1;
        transition select(meta.int_data_cnt) {
            0: accept;
            default: parse_probe_data;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_ICMP: parse_icmp;
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }
    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
    state parse_tcp {
       packet.extract(hdr.tcp);
       transition select(hdr.tcp.data_offset) {
            5: accept;
            default: parse_my_wnd;
        }
    }
    state parse_my_wnd {
        packet.extract(hdr.test_wnd);
        transition parse_options;
    }

    state parse_options {
       packet.extract(hdr.options,(bit<32>)(((bit<16>)hdr.tcp.data_offset - 6) * 32));
       transition accept;
    }
    state parse_udp {
       packet.extract(hdr.udp);
       transition accept;
    }
}
//------------------------------------------------------------
control c_verify_checksum(inout headers hdr, 
                          inout metadata meta) {
    apply {

    }
}
//------------------------------------------------------------
control c_ingress(inout headers hdr, 
                  inout metadata meta, 
                  inout standard_metadata_t standard_metadata) {
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    action probe_forward(bit<48> src_mac, bit<48> dst_mac, bit<9> port) {
        hdr.ethernet.src_mac = src_mac;
        hdr.ethernet.dst_mac = dst_mac;
        standard_metadata.egress_spec = port;
    }
    table probe_exact {
        key = {
            hdr.probe_fwd[0].swid: exact;
        }
        actions = {
            probe_forward;
  //          _drop;
        }
        size = 1024;
  //      default_action = _drop();
    }
    action packet_can_multipath() {
        meta.packet_can_multipath = 1;
    }
    action packet_cannot_multipath() {
        meta.packet_can_multipath = 0;
    }
    table ipv4_is_for_video {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            packet_can_multipath;
            packet_cannot_multipath;
  //          _drop;
        }
        size = 1024;
  //      default_action = _drop();
    }
    action ipv4_multipath(bit<48> src_mac, bit<48> dst_mac, bit<9> port) {
        hdr.ethernet.src_mac = src_mac;
        hdr.ethernet.dst_mac = dst_mac;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    table ipv4_multipath_lpm {
        key = {
            meta.multipath_port: exact;
        }
        actions = {
            ipv4_multipath;
  //          _drop;
        }
        size = 1024;
 //       default_action = _drop();
    }
    action ipv4_singlepath(bit<48> src_mac, bit<48> dst_mac, bit<9> port) {
        hdr.ethernet.src_mac = src_mac;
        hdr.ethernet.dst_mac = dst_mac;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    table ipv4_singlepath_lpm {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            ipv4_singlepath;
  //          _drop;
        }
        size = 1024;
  //      default_action = _drop();
    }

    action clone_packet() {
        standard_metadata.mcast_grp =  1;
        clone(CloneType.I2E, 500);
    }

    action ipv4_forward_million_tcp(bit<48> src_mac, bit<48> dst_mac, bit<9> port) {
        hdr.ethernet.src_mac = src_mac;
        hdr.ethernet.dst_mac = dst_mac;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    table ipv4_million_tcp {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            ipv4_forward_million_tcp;
  //          _drop;
        }
        size = 1024;
  //      default_action = _drop();
    }
    
    action packet_can_eccn() {
        // 区分TCP数据包和ACK包。ACK包没有data部分，只有32个字节的首部（20固定+12可选项[每个2字节的填充和10字节的时间戳]） 
        meta.TCP_length = (bit<16>)hdr.ipv4.total_len - ((bit<16>)hdr.ipv4.ihl << 2);
        num_flow.read(meta.cur_flow, 0); 
        meta.cur_flow =meta.cur_flow +1;
        num_flow.write(0,meta.cur_flow); 
    }
    table ipv4_is_for_eccn {
        key = {
            hdr.ipv4.dst_addr: exact;
            hdr.ipv4.src_addr: exact;
        }
        actions = {
            packet_can_eccn;
  //          _drop;
        }
        size = 1024;
  //      default_action = _drop();
    }

    apply {
        if (hdr.arp.isValid()) {
            // is the packet for arp
            if (hdr.arp.target_ip == 0x0aa6a601) {
                //ask who is 10.166.166.1
                hdr.ethernet.dst_mac = hdr.ethernet.src_mac;
                hdr.ethernet.src_mac = 0x00000000086;
                hdr.arp.OPER = 2;
                hdr.arp.target_ha = hdr.arp.sender_ha;
                hdr.arp.target_ip = hdr.arp.sender_ip;
                hdr.arp.sender_ip = 0x0aa6a601;
                hdr.arp.sender_ha = 0x000000000186;
                standard_metadata.egress_spec = standard_metadata.ingress_port;
            }
            else if (hdr.arp.target_ip == 0x0aa8a801) {
                //ask who is 10.168.168.1
                hdr.ethernet.dst_mac = hdr.ethernet.src_mac;
                hdr.ethernet.src_mac = 0x000000000188;
                hdr.arp.OPER = 2;
                hdr.arp.target_ha = hdr.arp.sender_ha;
                hdr.arp.target_ip = hdr.arp.sender_ip;
                hdr.arp.sender_ip = 0x0aa8a801;
                hdr.arp.sender_ha = 0x000000000188;
                standard_metadata.egress_spec = standard_metadata.ingress_port;
            }            
            else if (hdr.arp.target_ip == 0x0aa4a401) {
                //ask who is 10.164.164.1
                hdr.ethernet.dst_mac = hdr.ethernet.src_mac;
                hdr.ethernet.src_mac = 0x000000000184;
                hdr.arp.OPER = 2;
                hdr.arp.target_ha = hdr.arp.sender_ha;
                hdr.arp.target_ip = hdr.arp.sender_ip;
                hdr.arp.sender_ip = 0x0aa4a401;
                hdr.arp.sender_ha = 0x000000000184;
                standard_metadata.egress_spec = standard_metadata.ingress_port;
            }
            else if (hdr.arp.target_ip == 0x0aa2a201) {
                //ask who is 10.162.162.1
                hdr.ethernet.dst_mac = hdr.ethernet.src_mac;
                hdr.ethernet.src_mac = 0x000000000182;
                hdr.arp.OPER = 2;
                hdr.arp.target_ha = hdr.arp.sender_ha;
                hdr.arp.target_ip = hdr.arp.sender_ip;
                hdr.arp.sender_ip = 0x0aa2a201;
                hdr.arp.sender_ha = 0x000000000182;
                standard_metadata.egress_spec = standard_metadata.ingress_port;
            }
            else if (hdr.arp.target_ip == 0x0aaaaa01) {
                //ask who is 10.170.170.1
                hdr.ethernet.dst_mac = hdr.ethernet.src_mac;
                hdr.ethernet.src_mac = 0x000000000176;
                hdr.arp.OPER = 2;
                hdr.arp.target_ha = hdr.arp.sender_ha;
                hdr.arp.target_ip = hdr.arp.sender_ip;
                hdr.arp.sender_ip = 0x0aaaaa01;
                hdr.arp.sender_ha = 0x000000000176;
                standard_metadata.egress_spec = standard_metadata.ingress_port;
            }
            else if (hdr.arp.target_ip == 0x0aacac01) {
                //ask who is 10.172.172.1
                hdr.ethernet.dst_mac = hdr.ethernet.src_mac;
                hdr.ethernet.src_mac = 0x000000000176;
                hdr.arp.OPER = 2;
                hdr.arp.target_ha = hdr.arp.sender_ha;
                hdr.arp.target_ip = hdr.arp.sender_ip;
                hdr.arp.sender_ip = 0x0aacac01;
                hdr.arp.sender_ha = 0x000000000176;
                standard_metadata.egress_spec = standard_metadata.ingress_port;
            }
            else if (hdr.arp.target_ip == 0x0aaeae01) {
                //ask who is 10.174.174.1
                hdr.ethernet.dst_mac = hdr.ethernet.src_mac;
                hdr.ethernet.src_mac = 0x000000000178;
                hdr.arp.OPER = 2;
                hdr.arp.target_ha = hdr.arp.sender_ha;
                hdr.arp.target_ip = hdr.arp.sender_ip;
                hdr.arp.sender_ip = 0x0aaeae01;
                hdr.arp.sender_ha = 0x000000000178;
                standard_metadata.egress_spec = standard_metadata.ingress_port;
            }
            else if (hdr.arp.target_ip == 0x0ab4b401) {
                //ask who is 10.180.180.1
                hdr.ethernet.dst_mac = hdr.ethernet.src_mac;
                hdr.ethernet.src_mac = 0x000000000178;
                hdr.arp.OPER = 2;
                hdr.arp.target_ha = hdr.arp.sender_ha;
                hdr.arp.target_ip = hdr.arp.sender_ip;
                hdr.arp.sender_ip = 0x0ab4b401;
                hdr.arp.sender_ha = 0x000000000178;
                standard_metadata.egress_spec = standard_metadata.ingress_port;
            }
            else if (hdr.arp.target_ip == 0x0abebe01) {
                //ask who is 10.190.190.1
                hdr.ethernet.dst_mac = hdr.ethernet.src_mac;
                hdr.ethernet.src_mac = 0x000000000176;
                hdr.arp.OPER = 2;
                hdr.arp.target_ha = hdr.arp.sender_ha;
                hdr.arp.target_ip = hdr.arp.sender_ip;
                hdr.arp.sender_ip = 0x0abebe01;
                hdr.arp.sender_ha = 0x000000000176;
                standard_metadata.egress_spec = standard_metadata.ingress_port;
            }       
        }
        else if (hdr.probe.isValid()) {
            // is the packet for int
            hdr.probe.data_cnt = hdr.probe.data_cnt + 1;
            hdr.probe_data.push_front(1);
            hdr.probe_data[0].setValid(); 
            hdr.probe_data[0].swid = hdr.probe_fwd[0].swid; // 存入swid
            hdr.probe_data[0].port_ingress = (bit<8>)standard_metadata.ingress_port; // 存入入端口号
            bit<32> temp_byte_ingress = 0;
            int_byte_ingress.read(temp_byte_ingress, (bit<32>)standard_metadata.ingress_port); // 读取入端口累计入流量
            hdr.probe_data[0].byte_ingress = temp_byte_ingress; // 存入入端口累计入流量
            temp_byte_ingress = 0; // 累加入流量清零
            int_byte_ingress.write((bit<32>)standard_metadata.ingress_port, temp_byte_ingress); // 存入新累计入流量
            bit<32> temp_count_ingress = 0;
            int_count_ingress.read(temp_count_ingress, (bit<32>)standard_metadata.ingress_port); // 读取入端口累计入数量
            hdr.probe_data[0].count_ingress = temp_count_ingress; // 存入入端口累计入数量
            temp_count_ingress = 0; // 累加入数量清零
            int_count_ingress.write((bit<32>)standard_metadata.ingress_port, temp_count_ingress); // 存入新累计入数量
            bit<48> temp_last_time_ingress = 0;
            int_last_time_ingress.read(temp_last_time_ingress, (bit<32>)standard_metadata.ingress_port); // 读取入端口上一个INT包进入时间
            hdr.probe_data[0].last_time_ingress = temp_last_time_ingress; // 存入入端口上一个INT包进入时间
            temp_last_time_ingress = standard_metadata.ingress_global_timestamp; // 更新上一个INT包进入时间
            int_last_time_ingress.write((bit<32>)standard_metadata.ingress_port, temp_last_time_ingress);  // 存入新上一个INT包进入时间
            hdr.probe_data[0].current_time_ingress = standard_metadata.ingress_global_timestamp;  // 存入入端口当前INT包进入时间

            hdr.probe.hop_cnt = hdr.probe.hop_cnt - 1;
            hdr.probe_fwd.pop_front(1);
            probe_exact.apply();

            // eccn int link drop judgment
            if (hdr.probe_data[1].count_egress > hdr.probe_data[0].count_ingress){
                bit<32> byte_dropped_cnt = hdr.probe_data[1].count_egress - hdr.probe_data[0].count_ingress;
                byte_dropped_cnt_reg.write((bit<32>)0, byte_dropped_cnt);    // 把丢弃的字节数写入寄存器
                congestion_time_reg.write(0,(bit<48>)standard_metadata.ingress_global_timestamp);    // 把拥塞修改次数写入
            }
        }
        else if (ipv4_is_for_video.apply().hit) {
            // is the packet for video
            // int first
            bit<32> temp_byte_ingress = 0;
            int_byte_ingress.read(temp_byte_ingress, (bit<32>)standard_metadata.ingress_port); // 读取入端口累计入流量
            temp_byte_ingress = temp_byte_ingress + standard_metadata.packet_length; // 累加当前入流量
            int_byte_ingress.write((bit<32>)standard_metadata.ingress_port, temp_byte_ingress); // 存入新累计入流量
            bit<32> temp_count_ingress = 0;
            int_count_ingress.read(temp_count_ingress, (bit<32>)standard_metadata.ingress_port); // 读取入端口累计入数量
            temp_count_ingress = temp_count_ingress + 1; // 累加1
            int_count_ingress.write((bit<32>)standard_metadata.ingress_port, temp_count_ingress); // 存入新累计入数量

            // multipath second
            bit<32> temp_eccn = 0;
            bit<32> temp_multipath = 0;
            bit<32> temp_multipath2 = 0;
            bit<32> priority_queue = 0;
            transmition_model.read(temp_eccn, (bit<32>)0);
            transmition_model.read(temp_multipath, (bit<32>)1);
            transmition_model.read(temp_multipath2, (bit<32>)3);
            transmition_model.read(priority_queue, (bit<32>)4);
            if ( temp_multipath == 1 && temp_multipath2 == 0 && (hdr.tcp.isValid() || hdr.udp.isValid() || hdr.icmp.isValid()) ) {
                // the tcp packet should be forwarded multipath
                bit<32> temp_multipath_ability = 0;
                multipath_ability.read(temp_multipath_ability, (bit<32>)0);
                if (temp_multipath_ability == 0) {
                    // the node cannot multipath
                    ipv4_singlepath_lpm.apply();
                }
                else {
                    // the node can multipath
                    if (meta.packet_can_multipath == 1) {
                        // the packet can multipath
                        bit<32> temp2 = 0;
                        bit<32> temp3 = 0;
                        bit<32> temp4 = 0;
                        multipath_count.read(temp2, (bit<32>)2);
                        multipath_count.read(temp3, (bit<32>)3);
                        multipath_count.read(temp4, (bit<32>)4);
                        bit<32> ord2 = 0;
                        bit<32> ord3 = 0;
                        bit<32> ord4 = 0;
                        multipath_order.read(ord2, (bit<32>)2);
                        multipath_order.read(ord3, (bit<32>)3);
                        multipath_order.read(ord4, (bit<32>)4);
                        if (ord2 == 1) {
                            if (temp2 > 0) {
                                meta.multipath_port = 2;
                                temp2 = temp2 - 1;
                                multipath_count.write((bit<32>)2, temp2);
                            }
                            else {
                                if (ord3 == 2) {
                                    if (temp3 > 0) {
                                        meta.multipath_port = 3;
                                        temp3 = temp3 - 1;
                                        multipath_count.write((bit<32>)3, temp3);
                                    }
                                    else {
                                        if (temp4 > 0) {
                                            meta.multipath_port = 4;
                                            temp4 = temp4 - 1;
                                            multipath_count.write((bit<32>)4, temp4);
                                        }
                                    }
                                }
                                else if (ord4 == 2) {
                                    if (temp4 > 0) {
                                        meta.multipath_port = 4;
                                        temp4 = temp4 - 1;
                                        multipath_count.write((bit<32>)4, temp4);
                                    }
                                    else {
                                        if (temp3 > 0) {
                                            meta.multipath_port = 3;
                                            temp3 = temp3 - 1;
                                            multipath_count.write((bit<32>)3, temp3);
                                        }
                                    }
                                }
                            }
                        }
                        else if (ord3 == 1) {
                            if (temp3 > 0) {
                                meta.multipath_port = 3;
                                temp3 = temp3 - 1;
                                multipath_count.write((bit<32>)3, temp3);
                            }
                            else {
                                if (ord2 == 2) {
                                    if (temp2 > 0) {
                                        meta.multipath_port = 2;
                                        temp2 = temp2 - 1;
                                        multipath_count.write((bit<32>)2, temp2);
                                    }
                                    else {
                                        if (temp4 > 0) {
                                            meta.multipath_port = 4;
                                            temp4 = temp4 - 1;
                                            multipath_count.write((bit<32>)4, temp4);
                                        }
                                    }
                                }
                                else if (ord4 == 2) {
                                    if (temp4 > 0) {
                                        meta.multipath_port = 4;
                                        temp4 = temp4 - 1;
                                        multipath_count.write((bit<32>)4, temp4);
                                    }
                                    else {
                                        if (temp2 > 0) {
                                            meta.multipath_port = 2;
                                            temp2 = temp2 - 1;
                                            multipath_count.write((bit<32>)2, temp2);
                                        }
                                    }
                                }
                            }
                        }
                        else if (ord4 == 1) {
                            if (temp4 > 0) {
                                meta.multipath_port = 4;
                                temp4 = temp4 - 1;
                                multipath_count.write((bit<32>)4, temp4);
                            }
                            else {
                                if (ord2 == 2) {
                                    if (temp2 > 0) {
                                        meta.multipath_port = 2;
                                        temp2 = temp2 - 1;
                                        multipath_count.write((bit<32>)2, temp2);
                                    }
                                    else {
                                        if (temp3 > 0) {
                                            meta.multipath_port = 3;
                                            temp3 = temp3 - 1;
                                            multipath_count.write((bit<32>)3, temp3);
                                        }
                                    }
                                }
                                else if (ord3 == 2) {
                                    if (temp3 > 0) {
                                        meta.multipath_port = 3;
                                        temp3 = temp3 - 1;
                                        multipath_count.write((bit<32>)3, temp3);
                                    }
                                    else {
                                        if (temp2 > 0) {
                                            meta.multipath_port = 2;
                                            temp2 = temp2 - 1;
                                            multipath_count.write((bit<32>)2, temp2);
                                        }
                                    }
                                }
                            }
                        }
                        if (temp2 == 0) {
                            if (temp3 == 0) {
                                if (temp4 == 0) {
                                    multipath_initial.read(temp2, (bit<32>)2);
                                    multipath_initial.read(temp3, (bit<32>)3);
                                    multipath_initial.read(temp4, (bit<32>)4);
                                    multipath_count.write((bit<32>)2, temp2);
                                    multipath_count.write((bit<32>)3, temp3);
                                    multipath_count.write((bit<32>)4, temp4);
                                }
                            }
                        }
                        ipv4_multipath_lpm.apply();
                    }
                    else {
                        // the packet can not multipath
                        ipv4_singlepath_lpm.apply();
                    }
                }
            }
            else {
                // other packet should be forwarded singlepath
                ipv4_singlepath_lpm.apply();
            }

            // eccn third
            if (temp_eccn == 1 && hdr.ipv4.protocol == IP_PROTO_TCP) {
                // the packet should be used eccn
                // 区分TCP数据包和ACK包。ACK包没有data部分，只有32个字节的首部（20固定+12可选项[每个2字节的填充和10字节的时间戳]） 
                meta.TCP_length = (bit<16>)hdr.ipv4.total_len - ((bit<16>)hdr.ipv4.ihl << 2);
                num_flow.read(meta.cur_flow, 0); 
                meta.cur_flow =meta.cur_flow +1;
                num_flow.write(0,meta.cur_flow); 
                // 计算hash作为寄存器下标
                if( (hdr.ipv4.src_addr >= hdr.ipv4.dst_addr) && (hdr.tcp.src_port >= hdr.tcp.dst_port)){
                    hash(meta.hash_value, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port }, (bit<32>) NUM_BUCKETS);  // 根据流四元组计算出一个索引
                }
                else if( (hdr.ipv4.src_addr >= hdr.ipv4.dst_addr) && (hdr.tcp.src_port < hdr.tcp.dst_port)){
                    hash(meta.hash_value, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.dst_port, hdr.tcp.src_port }, (bit<32>) NUM_BUCKETS);  // 根据流四元组计算出一个索引
                }
                else if( (hdr.ipv4.src_addr < hdr.ipv4.dst_addr) && (hdr.tcp.src_port >= hdr.tcp.dst_port)){
                    hash(meta.hash_value, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.dst_addr, hdr.ipv4.src_addr, hdr.tcp.src_port, hdr.tcp.dst_port }, (bit<32>) NUM_BUCKETS);  // 根据流四元组计算出一个索引
                }
                else{
                    hash(meta.hash_value, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.dst_addr, hdr.ipv4.src_addr, hdr.tcp.dst_port, hdr.tcp.src_port }, (bit<32>) NUM_BUCKETS);  // 根据流四元组计算出一个索引
                }
                bit<48> congestion_time;
                bit<48> modify_time;
                bit<48> time_dif;
                bit<48> cur_time = standard_metadata.ingress_global_timestamp;
                modify_time_reg.read(modify_time,(bit<32>)meta.hash_value);
                congestion_time_reg.read(congestion_time,(bit<32>)meta.hash_value);
                bit<48> time_difference = cur_time - modify_time;   // 当前时间与上次修改时间的时间差
                bit<48> time_difference2 = cur_time - congestion_time;   // 当前时间与上次拥塞时间的时间差
                // 拥塞控制时间以内、超出数据包传输时间、是ACK包、不是入网第一跳才修改
                if(time_difference > 1000000 && meta.TCP_length <= 36 && hdr.ipv4.ttl <= 62){  //time_difference > time_dif time_dif_reg.read(time_dif,(bit<32>)meta.hash_value)
                    modify_time_reg.write((bit<32>)meta.hash_value, cur_time);
                    // log_msg("meta.TCP_length : {}",{meta.TCP_length});
                    // log_msg("hdr.ipv4.ttl : {}",{hdr.ipv4.ttl});
                    bit<32> max_cwnd;
                    bit<32> cur_cwnd;
                    max_cwnd_reg.read(max_cwnd, (bit<32>)meta.hash_value);
                    cur_cwnd_reg.read(cur_cwnd, (bit<32>)meta.hash_value);
                    if(time_difference2 > 1000000 ){   // 如果没有发生过拥塞，或者拥塞处理完了，窗口就慢慢增加
                        if (max_cwnd == 0 && cur_cwnd == 0){
                            max_cwnd = 40;   //init_cwnd_reg.read(max_cwnd,(bit<32>)meta.hash_value)
                            cur_cwnd = max_cwnd;

                        }
                        else{
                            cur_cwnd = cur_cwnd + 1;
                            max_cwnd = (cur_cwnd >= max_cwnd) ? cur_cwnd : max_cwnd;
                        }
                        max_cwnd_reg.write((bit<32>)meta.hash_value, max_cwnd);
                        cur_cwnd_reg.write((bit<32>)meta.hash_value, cur_cwnd);
                    }
                    else{   // 如果现在时间在拥塞发生时间的100ms以内才会增加ACK字段
                        max_cwnd = cur_cwnd;
                        max_cwnd_reg.write((bit<32>)meta.hash_value, max_cwnd);
                        bit<32> byte_dropped_cnt;
                        byte_dropped_cnt_reg.read(byte_dropped_cnt, (bit<32>)0);
                        cur_cwnd = cur_cwnd - byte_dropped_cnt >> 1;//有待解决
                        cur_cwnd_reg.write((bit<32>)meta.hash_value, cur_cwnd);
                    }
                    // 判断是否需要增添头部
                    meta.isupdated = false;
                    if(hdr.test_wnd.isValid() && hdr.test_wnd.type == 0xfe){
                        if(cur_cwnd <= (bit<32>)hdr.test_wnd.value){
                            hdr.test_wnd.value = (bit<16>)cur_cwnd;
                            meta.isupdated = true;
                        }
                    }
                    else{
                        hdr.my_wnd.setValid();
                        hdr.my_wnd.type = 0xfe;		// type固定254
                        hdr.my_wnd.length = 0x04;	// 该字段(TLV)的总长度为4
                        hdr.my_wnd.value = (bit<16>)cur_cwnd;	// 算法交互字段； 写入的值在内核里会被wscale放大的
                        hdr.tcp.data_offset = hdr.tcp.data_offset + 1; // tcp的offset字段就是tcp包的首部总长度	（它的单位是4个字节）
                        hdr.ipv4.total_len = hdr.ipv4.total_len + 4; // IP首部记录的报文总长度字段			
                        meta.TCP_length = meta.TCP_length + 4;	// 重新计算TCP长度
                    }
                }
            }

            //多路径2 fourth
            if(temp_multipath2 == 1 && (hdr.tcp.isValid() || hdr.udp.isValid() || hdr.icmp.isValid()))
            {
               if(hdr.ipv4.dst_addr == 0x0aaaaa02){
                   clone_packet();
               }
               //因为上面多路径1的else里已经设置了单路转发，所以此处无需设置转发
            }

            //priority_queue fifth
            if (priority_queue == 1 && (hdr.tcp.isValid() || hdr.udp.isValid() || hdr.icmp.isValid()) ) {
                // transmition_model索引为4的位置为1且是tcp传输,开启优先级队列
                // 该情况下已经满足该流为视频流，直接设定队列的优先级，设为最高优先级3
                //因为上面多路径1的else里已经设置了单路转发，所以此处无需设置转发
                standard_metadata.priority = (bit<3>)3;
            }
        }
        else {
            // is the packet for backstream
            // int first
            bit<32> temp_byte_ingress = 0;
            int_byte_ingress.read(temp_byte_ingress, (bit<32>)standard_metadata.ingress_port); // 读取入端口累计入流量
            temp_byte_ingress = temp_byte_ingress + standard_metadata.packet_length; // 累加当前入流量
            int_byte_ingress.write((bit<32>)standard_metadata.ingress_port, temp_byte_ingress); // 存入新累计入流量
            bit<32> temp_count_ingress = 0;
            int_count_ingress.read(temp_count_ingress, (bit<32>)standard_metadata.ingress_port); // 读取入端口累计入数量
            temp_count_ingress = temp_count_ingress + 1; // 累加1
            int_count_ingress.write((bit<32>)standard_metadata.ingress_port, temp_count_ingress); // 存入新累计入数量

            // backstream second
            ipv4_million_tcp.apply();

            //eccn thrid
            bit<32> temp_eccn = 0;
            transmition_model.read(temp_eccn, (bit<32>)0);
            if (temp_eccn == 1 && hdr.ipv4.protocol == IP_PROTO_TCP && ipv4_is_for_eccn.apply().hit) {
                // the backstream packet should be used eccn
                // 计算hash作为寄存器下标
                if( (hdr.ipv4.src_addr >= hdr.ipv4.dst_addr) && (hdr.tcp.src_port >= hdr.tcp.dst_port)){
                    hash(meta.hash_value, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port }, (bit<32>) NUM_BUCKETS);  // 根据流四元组计算出一个索引
                }
                else if( (hdr.ipv4.src_addr >= hdr.ipv4.dst_addr) && (hdr.tcp.src_port < hdr.tcp.dst_port)){
                    hash(meta.hash_value, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.dst_port, hdr.tcp.src_port }, (bit<32>) NUM_BUCKETS);  // 根据流四元组计算出一个索引
                }
                else if( (hdr.ipv4.src_addr < hdr.ipv4.dst_addr) && (hdr.tcp.src_port >= hdr.tcp.dst_port)){
                    hash(meta.hash_value, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.dst_addr, hdr.ipv4.src_addr, hdr.tcp.src_port, hdr.tcp.dst_port }, (bit<32>) NUM_BUCKETS);  // 根据流四元组计算出一个索引
                }
                else{
                    hash(meta.hash_value, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.dst_addr, hdr.ipv4.src_addr, hdr.tcp.dst_port, hdr.tcp.src_port }, (bit<32>) NUM_BUCKETS);  // 根据流四元组计算出一个索引
                }
                bit<48> congestion_time;
                bit<48> modify_time;
                bit<48> time_dif;
                bit<48> cur_time = standard_metadata.ingress_global_timestamp;
                modify_time_reg.read(modify_time,(bit<32>)meta.hash_value);
                congestion_time_reg.read(congestion_time,(bit<32>)meta.hash_value);
                bit<48> time_difference = cur_time - modify_time;   // 当前时间与上次修改时间的时间差
                bit<48> time_difference2 = cur_time - congestion_time;   // 当前时间与上次拥塞时间的时间差
                // 拥塞控制时间以内、超出数据包传输时间、是ACK包、不是入网第一跳才修改
                if(time_difference > 1000000 && meta.TCP_length <= 36 && hdr.ipv4.ttl <= 62){  //time_difference > time_dif time_dif_reg.read(time_dif,(bit<32>)meta.hash_value)
                    modify_time_reg.write((bit<32>)meta.hash_value, cur_time);
                    // log_msg("meta.TCP_length : {}",{meta.TCP_length});
                    // log_msg("hdr.ipv4.ttl : {}",{hdr.ipv4.ttl});
                    bit<32> max_cwnd;
                    bit<32> cur_cwnd;
                    max_cwnd_reg.read(max_cwnd, (bit<32>)meta.hash_value);
                    cur_cwnd_reg.read(cur_cwnd, (bit<32>)meta.hash_value);
                    if(time_difference2 > 1000000 ){   // 如果没有发生过拥塞，或者拥塞处理完了，窗口就慢慢增加
                        if (max_cwnd == 0 && cur_cwnd == 0){
                            max_cwnd = 40;   //init_cwnd_reg.read(max_cwnd,(bit<32>)meta.hash_value)
                            cur_cwnd = max_cwnd;

                        }
                        else{
                            cur_cwnd = cur_cwnd + 1;
                            max_cwnd = (cur_cwnd >= max_cwnd) ? cur_cwnd : max_cwnd;
                        }
                        max_cwnd_reg.write((bit<32>)meta.hash_value, max_cwnd);
                        cur_cwnd_reg.write((bit<32>)meta.hash_value, cur_cwnd);
                    }
                    else{   // 如果现在时间在拥塞发生时间的100ms以内才会增加ACK字段
                        max_cwnd = cur_cwnd;
                        max_cwnd_reg.write((bit<32>)meta.hash_value, max_cwnd);
                        bit<32> byte_dropped_cnt;
                        byte_dropped_cnt_reg.read(byte_dropped_cnt, (bit<32>)0);
                        cur_cwnd = cur_cwnd - byte_dropped_cnt >> 1;//有待解决
                        cur_cwnd_reg.write((bit<32>)meta.hash_value, cur_cwnd);
                    }
                    // 判断是否需要增添头部
                    meta.isupdated = false;
                    if(hdr.test_wnd.isValid() && hdr.test_wnd.type == 0xfe){
                        if(cur_cwnd <= (bit<32>)hdr.test_wnd.value){
                            hdr.test_wnd.value = (bit<16>)cur_cwnd;
                            meta.isupdated = true;
                        }
                    }
                    else{
                        hdr.my_wnd.setValid();
                        hdr.my_wnd.type = 0xfe;		// type固定254
                        hdr.my_wnd.length = 0x04;	// 该字段(TLV)的总长度为4
                        hdr.my_wnd.value = (bit<16>)cur_cwnd;	// 算法交互字段； 写入的值在内核里会被wscale放大的
                        hdr.tcp.data_offset = hdr.tcp.data_offset + 1; // tcp的offset字段就是tcp包的首部总长度	（它的单位是4个字节）
                        hdr.ipv4.total_len = hdr.ipv4.total_len + 4; // IP首部记录的报文总长度字段			
                        meta.TCP_length = meta.TCP_length + 4;	// 重新计算TCP长度 
                    }
                }
            }

            //priority_queue fourth
            bit<32> priority_queue = 0;
            transmition_model.read(priority_queue, (bit<32>)4);
            if (priority_queue == 1){
                if (hdr.ipv4.dst_addr != 0x0ab4b402 && hdr.ipv4.dst_addr != 0x0aaaaa02){
                    // 目前最高优先级是3，这里将背景流的优先级设为2
                    standard_metadata.priority = (bit<3>)2;
                }
            }
        }
    }
}
//------------------------------------------------------------
control c_egress(inout headers hdr, 
                 inout metadata meta, 
                 inout standard_metadata_t standard_metadata) {
    apply {
        if (standard_metadata.instance_type != 0){   //如果要发回源端，加一个或判断，判断clone_i是2
            meta.clone_id = 2;
            hdr.probe.clone = meta.clone_id;
        }
        else if (hdr.arp.isValid()) {
            // is the packet for arp
        }
        else if (hdr.probe.isValid()) {
            // is the packet for int
            hdr.probe_data[0].port_egress = (bit<8>)standard_metadata.egress_port; // 存入出端口号
            bit<32> temp_byte_egress = 0;
            int_byte_egress.read(temp_byte_egress, (bit<32>)standard_metadata.egress_port); // 读取出端口累计出流量
            hdr.probe_data[0].byte_egress = temp_byte_egress; // 存入出端口累计出流量
            temp_byte_egress = 0; // 累加出流量清零
            int_byte_egress.write((bit<32>)standard_metadata.egress_port, temp_byte_egress); // 存入新累计出流量
            bit<32> temp_count_egress = 0;
            int_count_egress.read(temp_count_egress, (bit<32>)standard_metadata.egress_port); // 读取出端口累计出数量
            hdr.probe_data[0].count_egress = temp_count_egress; // 存入出端口累计出数量
            temp_count_egress = 0; // 累加出数量清零
            int_count_egress.write((bit<32>)standard_metadata.egress_port, temp_count_egress); // 存入新累计出数量
            bit<48> temp_last_time_egress = 0;
            int_last_time_egress.read(temp_last_time_egress, (bit<32>)standard_metadata.egress_port); // 读取出端口上一个INT包进出时间
            hdr.probe_data[0].last_time_egress = temp_last_time_egress; // 存入出端口上一个INT包进出时间
            temp_last_time_egress = standard_metadata.egress_global_timestamp; // 更新上一个INT包进出时间
            int_last_time_egress.write((bit<32>)standard_metadata.egress_port, temp_last_time_egress);  // 存入新上一个INT包进出时间
            hdr.probe_data[0].current_time_egress = standard_metadata.egress_global_timestamp;  // 存入出端口当前INT包进出时间
            hdr.probe_data[0].qdepth = (bit<32>)standard_metadata.deq_qdepth; // 存入队列深度
            meta.clone_id = 0;
            hdr.probe.clone = meta.clone_id;
            bit<32> temp_rtt = 0;
            transmition_model.read(temp_rtt, (bit<32>)2);
            if (temp_rtt == 1 && ((hdr.probe_data[1].count_egress - hdr.probe_data[0].count_ingress) > 0) && ((hdr.probe_data[0].swid == (bit<8>)182) || (hdr.probe_data[0].swid == (bit<8>)184))) {
                clone(CloneType.E2E,100);
            }
        }
        else {
            // is the packet for video or backstream
            // int last
            bit<32> temp_byte_egress = 0;
            int_byte_egress.read(temp_byte_egress, (bit<32>)standard_metadata.egress_port); // 读取出端口累计出流量
            temp_byte_egress = temp_byte_egress + standard_metadata.packet_length; // 累加当前出流量
            int_byte_egress.write((bit<32>)standard_metadata.egress_port, temp_byte_egress); // 存出新累计出流量
            bit<32> temp_count_egress = 0;
            int_count_egress.read(temp_count_egress, (bit<32>)standard_metadata.egress_port); // 读取出端口累计出数量
            temp_count_egress = temp_count_egress + 1; // 累加1
            int_count_egress.write((bit<32>)standard_metadata.egress_port, temp_count_egress); // 存出新累计出数量
        }
    }
}
//------------------------------------------------------------
control c_compute_checksum(inout headers hdr,
                           inout metadata meta) {
    apply {
        update_checksum(	// IP 和 TCP 的校验和计算使用相同的计算方法。
            hdr.ipv4.isValid(),
                { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr },
                hdr.ipv4.hdr_checksum,
                HashAlgorithm.csum16);

        update_checksum(	// 更新TCP校验和
            hdr.my_wnd.isValid(),
                { hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                (bit<8>)0x00,		// 8bit 全0填充
                hdr.ipv4.protocol,
                meta.TCP_length,		// TCP包的总长度，得计算得到
                // 以上是伪首部
                // TCP的校验和计算需要伪首部+TCP所有字段，但这里我们需要重新计算TCP校验和的情况只有增加ACK内容时，所以只使用了如下这些TCP字段值。
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                hdr.tcp.seq_no,
                hdr.tcp.ack_no,
                hdr.tcp.data_offset,
                hdr.tcp.res,
                hdr.tcp.flags,
                hdr.tcp.window,
                hdr.tcp.urgent_ptr,
                hdr.my_wnd.type,
                hdr.my_wnd.length,
                hdr.my_wnd.value,
                hdr.test_wnd.type,
                hdr.test_wnd.length,
                hdr.test_wnd.value,
                hdr.options.nop_nop_timeStamps
                },
                hdr.tcp.checksum,
                HashAlgorithm.csum16);

        update_checksum(	// 更新TCP校验和
            meta.isupdated,
                { hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                (bit<8>)0x00,		// 8bit 全0填充
                hdr.ipv4.protocol,
                meta.TCP_length,		// TCP包的总长度，得计算得到
                // 以上是伪首部
                // TCP的校验和计算需要伪首部+TCP所有字段，但这里我们需要重新计算TCP校验和的情况只有增加ACK内容时，所以只使用了如下这些TCP字段值。
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                hdr.tcp.seq_no,
                hdr.tcp.ack_no,
                hdr.tcp.data_offset,
                hdr.tcp.res,
                hdr.tcp.flags,
                hdr.tcp.window,
                hdr.tcp.urgent_ptr,
                hdr.test_wnd.type,
                hdr.test_wnd.length,
                hdr.test_wnd.value,
                hdr.options.nop_nop_timeStamps
                },
                hdr.tcp.checksum,
                HashAlgorithm.csum16);
    }
}
//------------------------------------------------------------
control c_deparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.probe);
        packet.emit(hdr.probe_fwd);
        packet.emit(hdr.probe_data);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.my_wnd);
        packet.emit(hdr.test_wnd);
        packet.emit(hdr.options);
        packet.emit(hdr.udp);
    }
}
//------------------------------------------------------------
V1Switch(
    c_parser(),
    c_verify_checksum(),
    c_ingress(),
    c_egress(),
    c_compute_checksum(),
    c_deparser()
) main;
