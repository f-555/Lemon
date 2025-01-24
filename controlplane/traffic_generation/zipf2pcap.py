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
        
        eth = Ether(src=RandString(6), dst=RandString(6)) 
        #pkt = eth/ip/udp/payload
        pkt = ip/udp/payload
        packets.append(pkt)
    return packets

def generate_pcap(input_file="flows.txt", pcap_file="output.pcap"):
    writer = PcapWriter(pcap_file, append=True)
    r = open(input_file,'r')
    num_flows = r.readlines()
    r.close()
    for pkt_num in num_flows:
        src_ip = f"{random.randint(1, 239)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        dst_ip = f"192.168.0.1"
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1024, 65535)
        
        num_packets_per_flow = int(eval(pkt_num[:-1]))
        packets = generate_udp_flow(src_ip, dst_ip, src_port, dst_port, num_packets_per_flow)
        
        for pkt in packets:
            writer.write(pkt)

#generate_pcap(input_file = "3000s.txt", pcap_file="3000s.pcap")
#generate_pcap(input_file = "flows_1_5.txt", pcap_file="udp_flows_1_5.pcap")
#generate_pcap(input_file = "flows_2.txt", pcap_file="udp_flows_2.pcap")
