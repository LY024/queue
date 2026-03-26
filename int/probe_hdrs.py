from scapy.all import *

TYPE_PROBE = 0x0812

class Probe(Packet):
   fields_desc = [ ByteField("hop_cnt", 0),
                   ByteField("data_cnt", 0)]

class ProbeFwd(Packet):
   fields_desc = [ ByteField("swid", 0)]

class ProbeData(Packet):
   fields_desc = [ ByteField("swid", 0),
                   ByteField("port_ingress", 0),
                   ByteField("port_egress", 0),
                   IntField("byte_ingress", 0),
                   IntField("byte_egress", 0),
                   IntField("count_ingress", 0),
                   IntField("count_egress", 0),
                   BitField("last_time_ingress", 0, 48),
                   BitField("last_time_egress", 0, 48),
                   BitField("current_time_ingress", 0, 48),
                   BitField("current_time_egress", 0, 48),
                   BitField("qdepth", 0, 32)]

bind_layers(Ether, Probe, type=TYPE_PROBE)
bind_layers(Probe, ProbeData, data_hop=0)
bind_layers(Probe, ProbeFwd)
bind_layers(ProbeFwd, ProbeFwd)
bind_layers(ProbeFwd, ProbeData)
bind_layers(ProbeData, ProbeData)