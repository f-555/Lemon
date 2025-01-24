import random
import dpkt
import socket
from concurrent.futures import ThreadPoolExecutor
import time
import routings

interfaces_list = ["s01-eth1", "s02-eth1", "s03-eth1", "s04-eth1", "s05-eth1", "s06-eth1", "s07-eth1", "s08-eth1",
              "s09-eth1", "s10-eth1", "s11-eth1", "s12-eth1", "s13-eth1", "s14-eth1", "s15-eth1", "s16-eth1",
              "s17-eth1", "s18-eth1", "s19-eth1", "s20-eth1", "s21-eth1", "s22-eth1", "s23-eth1", "s24-eth1",
              "s25-eth1", "s26-eth1", "s27-eth1", "s28-eth1"]

network_size = 1
interfaces = interfaces_list[0:network_size]

sock_list = []
for iface in interfaces:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((iface, 0))  # bind
    sock_list.append(sock)

background_num = 10000  # number of packet to send
pcap_file = "../../lemon_cpu/dataset/mawi2.pcap"  # path to dataset.pacp
num_send = 0
def send_packet_fullmesh_random(pcap_file, n, pkg_num):
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, packet in pcap:
            global num_send
            num_send += 1
            if num_send > pkg_num:
                break
            if num_send % 10000 == 0:
                print(num_send)
            
            eth = dpkt.ethernet.Ethernet(packet)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            selected_socks = random.sample(sock_list, n)
            for sock in selected_socks:
                sock.send(packet)
                time.sleep(0.0002)

def send_packet_random_routing(topology, pcap_file, n, pkg_num):
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, packet in pcap:
            global num_send
            num_send += 1
            if num_send > pkg_num:
                break
            if num_send % 10000 == 0:
                print(num_send)
            
            eth = dpkt.ethernet.Ethernet(packet)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            selected_socks = random.sample(sock_list, n)
            for sock in selected_socks:
                sock.send(packet)
                time.sleep(0.0002)

def send_packet_controlled(topology, pcap_file, n, pkg_num):
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, packet in pcap:
            global num_send
            num_send += 1
            if num_send > pkg_num:
                break
            if num_send % 10000 == 0:
                print(num_send)
            
            eth = dpkt.ethernet.Ethernet(packet)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            selected_socks = random.sample(sock_list, n)
            for sock in selected_socks:
                sock.send(packet)
                time.sleep(0.0002)

send_packet_fullmesh_random(pcap_file, network_size, background_num)
#send_packet_fullmesh_random(routing_abilene, pcap_file, network_size, background_num)
#send_packet_controlled('single', pcap_file, n, pkg_num)