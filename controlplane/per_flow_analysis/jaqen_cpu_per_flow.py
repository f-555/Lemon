import math
import hashlib
import dpkt
import dpkt
import socket

mem_ratio = 0.2
class Jaqen:
    def __init__(self, size = 262144):
        size = round(mem_ratio * size)
        self.registers = [0] * size
        self.size = size

    def insert(self, item_flow):
        hash_object = hashlib.sha256(item_flow.encode())
        hash_int = int(hash_object.hexdigest(), 16) % self.size
        self.registers[hash_int] += 1

    def query(self, item_flow):
        hash_object = hashlib.sha256(item_flow.encode())
        hash_int = int(hash_object.hexdigest(), 16) % self.size
        return self.registers[hash_int]

def merge_add(jaqen1,jaqen2):
    jaqen3 = Jaqen()
    for i in range(0,jaqen3.size):
        jaqen3.registers[i] = jaqen1.registers[i] + jaqen2.registers[i]
    return jaqen3

if __name__ == "__main__":
    # Example usage
    jaqen = Jaqen()
    jaqen1 = Jaqen()
    jaqen2 = Jaqen()
    jaqen3 = Jaqen()
   
    background_num = 5000000
    
    pcap_file = f'mawi.pcap'
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        pkg_count = 0
        for timestamp, buf in pcap:
            pkg_count = pkg_count + 1
            if pkg_count > background_num:
                break
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            
            #ip = dpkt.ip.IP(buf)
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            protocol = ip.p
            src_port = dst_port = None
            pkg_tag = None

            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                src_port = tcp.sport
                dst_port = tcp.dport
                seq_num = tcp.seq
                pkg_tag = str(seq_num)
                #print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, Seq: {seq_num}")
            else:
                if isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    src_port = udp.sport
                    dst_port = udp.dport

                # Make sure we have data payload to read
                payload = bytes(ip.data.data) if hasattr(ip.data, 'data') else b''
                payload_first_16 = payload[:16].hex()
                #print(f"Non-TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, Payload (first 16 bytes): {payload_first_16}")
                pkg_tag = str(payload_first_16)

            flow_id = f'{src_ip}{dst_ip}{src_port}{dst_port}{protocol}'
            pkg_id = f'{src_ip}{dst_ip}{src_port}{dst_port}{protocol}{pkg_tag}'

            jaqen.insert(flow_id)
            #simulating topologies by select Jaqen to insert

    #query Jaqen, enter your flow key before this
    flow_id = f'{src_ip}{dst_ip}{src_port}{dst_port}{protocol}'
    jaqen.query(flow_id)

