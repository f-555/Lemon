import random
import string
from scapy.all import IP, UDP, sendp, Ether, RandShort, RandString, PcapWriter

def random_payload(size=64):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()

def generate_udp_flow(src_ip, dst_ip, src_port, dst_port, num_packets, payload_size=64):
    packets = []
    for _ in range(num_packets):
        ip = IP(src=src_ip, dst=dst_ip)
        udp = UDP(sport=src_port, dport=dst_port)
        payload = random_payload(payload_size)
        eth = Ether(src="00:00:00:00:00:00", dst="FF:FF:FF:FF:FF:FF") # MAC address is useless here
        pkt = eth/ip/udp/payload
        #pkt = ip/udp/payload
        packets.append(pkt)
    return packets

def generate_pcap(input_file="flows.txt", pcap_file="output.pcap"):
    writer = PcapWriter(pcap_file, append=True)
    r = open(input_file,'r')
    num_flows = r.readlines()
    r.close()
    for pkt_num in num_flows:
        src_ip = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
        dst_ip = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1024, 65535)
        
        num_packets_per_flow = int(eval(pkt_num[:-1]))
        packets = generate_udp_flow(src_ip, dst_ip, src_port, dst_port, num_packets_per_flow)
        
        for pkt in packets:
            writer.write(pkt)

    print(f"PCAP file {pcap_file} is generated, includes {flows_num} flows, each flow contain {num_packets_per_flow} packest")

def generate_pcap_carp(flows_num = 1, subnet = 24, pcap_file="output.pcap"):
    num_packets_per_flow = round(250000/flows_num)
    writer = PcapWriter(pcap_file, append=True)
    for pkt_num in range(0,flows_num):
        net = 32-subnet
        src_ip = f"{random.randint(1, 239)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        dst_ip = f"1.0.0.{random.randint(0, 2**net-1)}"
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1024, 65535)
        packets = generate_udp_flow(src_ip, dst_ip, src_port, dst_port, num_packets_per_flow)
        for pkt in packets:
            writer.write(pkt)
    print(f"PCAP file {pcap_file} is generated, includes {flows_num} flows, each flow contain {num_packets_per_flow} packest")

def generate_pcap_source(flows_num = 1, total = 250000, pcap_file="output.pcap"):
    num_packets_per_flow = round(total/flows_num)
    writer = PcapWriter(pcap_file, append=True)
    # creat UDP flows
    for pkt_num in range(0,flows_num):
        src_ip = f"{random.randint(1, 239)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        dst_ip = f"1.0.0.1"
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1024, 65535)
        
        # creat UDP packets for flows
        packets = generate_udp_flow(src_ip, dst_ip, src_port, dst_port, num_packets_per_flow)
        
        # write to pcap
        for pkt in packets:
            writer.write(pkt)
    print(f"PCAP file {pcap_file} is generated, includes {flows_num} flows, each flow contain {num_packets_per_flow} packest")

subnet_num = 32
flow_num = 1
num_all = 1
#generate_pcap_carp(flows_num = 100000, subnet=subnet_num, pcap_file=f"udp_carpet_{subnet_num}.pcap")
generate_pcap_source(flow_num,num_all, pcap_file=f"test_{flow_num}.pcap")