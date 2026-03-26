/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
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

// ================= INT寄存器 =================
//队列开关，[0]=1开启，=0关闭
register<bit<32>>(8) transmition_model;
/*Queue with index 0 is the bottom one, with lowest priority*/
register<bit<32>>(8) queue_bound;

// 记录总反转次数：索引 0 存储 SP-PIFO 的总反转数，索引 1 存储 FIFO 的总反转数
register<bit<32>>(2) total_inversions;
// 记录每个 Rank (0-255) 产生的反转次数
register<bit<32>>(256) rank_inversions_sppifo;
register<bit<32>>(256) rank_inversions_fifo;
// 辅助寄存器：仅用于 FIFO 模式，记录上一个入队包的 Rank 以便做前后比对
register<bit<32>>(1) last_enqueued_rank;


// ================= INT寄存器 =================
// 端口ingress累积入流量，INT协议使用，int_byte_ingress[1]代表端口1的累计入流量
register<bit<32>>(MAX_PORTS) int_byte_ingress; 
// 端口egress累积出流量，INT协议使用，int_byte_egress[1]代表端口1的累计出流量
register<bit<32>>(MAX_PORTS) int_byte_egress; 
// 端口ingress累积入包个数，INT协议使用，int_count_ingress[1]代表端口1的累计入个数
register<bit<32>>(MAX_PORTS) int_count_ingress;
// 端口egress累积出包个数，INT协议使用，int_count_egress[1]代表端口1的累计出个数
register<bit<32>>(MAX_PORTS) int_count_egress;
// 端口ingress上一个INT包进入时间，INT协议使用，int_last_time_ingress[1]代表端口1的入INT包时间
register<bit<48>>(MAX_PORTS) int_last_time_ingress; 
// 端口egress上一个INT包离开时间，INT协议使用，int_last_time_egress[1]代表端口1的出INT包时间
register<bit<48>>(MAX_PORTS) int_last_time_egress; 


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
    bit<8>   tos;
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
struct metadata {
    bit<8> int_hop_cnt;
    bit<8> int_data_cnt;
    bit<32> current_queue_bound;
    bit<32> rank;
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
}
//------------------------------------------------------------
parser c_parser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        meta = {0, 0, 0, 0};
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

    action drop() {
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
            drop;
        }
        size = 1024;
        // default_action = drop();
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
            drop;
        }
        size = 1024;
        // default_action = drop();
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
            //the packet for int
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
            temp_last_time_ingress = standard_metadata.ingress_global_timestamp; // 更新当前INT包进入时间
            hdr.probe_data[0].current_time_ingress = temp_last_time_ingress;  // 存入入端口当前INT包进入时间
            int_last_time_ingress.write((bit<32>)standard_metadata.ingress_port, temp_last_time_ingress);  // 存入当前INT包进入时间
            
            hdr.probe.hop_cnt = hdr.probe.hop_cnt - 1;
            hdr.probe_fwd.pop_front(1);
            probe_exact.apply();
        }
        else {
            // the packet for stream
            // int first
            bit<32> temp_byte_ingress = 0;
            int_byte_ingress.read(temp_byte_ingress, (bit<32>)standard_metadata.ingress_port); // 读取入端口累计入流量
            temp_byte_ingress = temp_byte_ingress + standard_metadata.packet_length; // 累加当前入流量
            int_byte_ingress.write((bit<32>)standard_metadata.ingress_port, temp_byte_ingress); // 存入新累计入流量

            bit<32> temp_count_ingress = 0;
            int_count_ingress.read(temp_count_ingress, (bit<32>)standard_metadata.ingress_port); // 读取入端口累计入数量
            temp_count_ingress = temp_count_ingress + 1; // 累加1
            int_count_ingress.write((bit<32>)standard_metadata.ingress_port, temp_count_ingress); // 存入新累计入数量

            //是否开启队列
            bit<32> queue = 0;
            transmition_model.read(queue, (bit<32>)0);
            //rank越大，优先级越低
            meta.rank = (bit<32>)hdr.ipv4.tos;
            log_msg("hdr.ipv4.tos = {}, meta.rank = {}", {hdr.ipv4.tos, meta.rank});
            //queue = 1,启用队列
            if(queue == 1) {
                //-----------------SP-PIFO---------------------//
                queue_bound.read(meta.current_queue_bound, 0);
                if ((meta.current_queue_bound <= meta.rank)) {
                    standard_metadata.priority = (bit<3>)0;
                    queue_bound.write(0, meta.rank);
                } else {
                    queue_bound.read(meta.current_queue_bound, 1);
                    if ((meta.current_queue_bound <= meta.rank)) {
                        standard_metadata.priority = (bit<3>)1;
                        queue_bound.write(1, meta.rank);
                    } else {
                        queue_bound.read(meta.current_queue_bound, 2);
                        if ((meta.current_queue_bound <= meta.rank)) {
                            standard_metadata.priority = (bit<3>)2;
                            queue_bound.write(2, meta.rank);
                        } else {
                            queue_bound.read(meta.current_queue_bound, 3);
                            if ((meta.current_queue_bound <= meta.rank)) {
                                standard_metadata.priority = (bit<3>)3;
                                queue_bound.write(3, meta.rank);
                            } else {
                                queue_bound.read(meta.current_queue_bound, 4);
                                if ((meta.current_queue_bound <= meta.rank)) {
                                    standard_metadata.priority = (bit<3>)4;
                                    queue_bound.write(4, meta.rank);
                                } else {
                                    queue_bound.read(meta.current_queue_bound, 5);
                                    if ((meta.current_queue_bound <= meta.rank)) {
                                        standard_metadata.priority = (bit<3>)5;
                                        queue_bound.write(5, meta.rank);
                                    } else {
                                        queue_bound.read(meta.current_queue_bound, 6);
                                        if ((meta.current_queue_bound <= meta.rank)) {
                                            standard_metadata.priority = (bit<3>)6;
                                            queue_bound.write(6, meta.rank);
                                        } else {
                                            standard_metadata.priority = (bit<3>)7;
                                            queue_bound.read(meta.current_queue_bound, 7);

                                            /*Blocking reaction*/
                                            if(meta.current_queue_bound > meta.rank) {
                                                bit<32> cost = meta.current_queue_bound - meta.rank;

                                                // === 新增：SP-PIFO 记录反转次数 ===
                                                // 此时包的 Rank 小于最高优先级队列的 Bound，发生反转
                                                bit<32> sp_total_inv;
                                                total_inversions.read(sp_total_inv, 0);
                                                total_inversions.write(0, sp_total_inv + 1);

                                                bit<32> sp_rank_inv;
                                                rank_inversions_sppifo.read(sp_rank_inv, meta.rank);
                                                rank_inversions_sppifo.write(meta.rank, sp_rank_inv + 1);

                                                /*Decrease the bound of all the following queues a factor equal to the cost of the blocking*/
                                                queue_bound.read(meta.current_queue_bound, 0);			    
                                                queue_bound.write(0, (bit<32>)(meta.current_queue_bound-cost));
                                                queue_bound.read(meta.current_queue_bound, 1);			    
                                                queue_bound.write(1, (bit<32>)(meta.current_queue_bound-cost));
                                                queue_bound.read(meta.current_queue_bound, 2);			    
                                                queue_bound.write(2, (bit<32>)(meta.current_queue_bound-cost));
                                                queue_bound.read(meta.current_queue_bound, 3);			    
                                                queue_bound.write(3, (bit<32>)(meta.current_queue_bound-cost));
                                                queue_bound.read(meta.current_queue_bound, 4);			    
                                                queue_bound.write(4, (bit<32>)(meta.current_queue_bound-cost));
                                                queue_bound.read(meta.current_queue_bound, 5);			    
                                                queue_bound.write(5, (bit<32>)(meta.current_queue_bound-cost));
                                                queue_bound.read(meta.current_queue_bound, 6);			    
                                                queue_bound.write(6, (bit<32>)(meta.current_queue_bound-cost));			    
                                                queue_bound.write(7, meta.rank);
                                            } else {
                                                queue_bound.write(7, meta.rank);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                //-----------------FIFO---------------------//
                bit<32> last_rank = 0;
                last_enqueued_rank.read(last_rank, 0);
                // 如果当前包的 Rank 比前一个包小（优先级高），却排在了它后面，即发生反转
                if (meta.rank < last_rank) {
                    bit<32> fifo_total_inv;
                    total_inversions.read(fifo_total_inv, 1);
                    total_inversions.write(1, fifo_total_inv + 1);

                    bit<32> fifo_rank_inv;
                    rank_inversions_fifo.read(fifo_rank_inv, meta.rank);
                    rank_inversions_fifo.write(meta.rank, fifo_rank_inv + 1);
                }
                // 将当前的 Rank 更新为"上一个包的 Rank"，供下一个包比对
                last_enqueued_rank.write(0, meta.rank);
            }
            // stream second
            ipv4_million_tcp.apply();
        }
    }
}
//------------------------------------------------------------
control c_egress(inout headers hdr, 
                 inout metadata meta, 
                 inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.arp.isValid()) {
            // the packet for arp
        }
        else if (hdr.probe.isValid()) {
            // the packet for int
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
            temp_last_time_egress = standard_metadata.egress_global_timestamp; // 更新当前INT包进入时间
            hdr.probe_data[0].current_time_egress = temp_last_time_egress;  // 存入出端口当前INT包进出时间
            int_last_time_egress.write((bit<32>)standard_metadata.egress_port, temp_last_time_egress);  // 存入当前INT包进出时间

            hdr.probe_data[0].qdepth = (bit<32>)standard_metadata.deq_qdepth; // 存入队列深度
        }
        else {
            // the packet for video or stream
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
                hdr.ipv4.tos,
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
