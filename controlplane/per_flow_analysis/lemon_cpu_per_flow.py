import math
import hashlib
import dpkt
import dpkt
import socket
import cityhash
import zlib

class CRC32:
    def __init__(self, polynomial=0x04C11DB7, init_value=0xFFFFFFFF, xor_out=0xFFFFFFFF):
        self.polynomial = polynomial
        self.init_value = init_value
        self.xor_out = xor_out
        self.table = self._generate_crc_table()

    def _generate_crc_table(self):
        table = []
        for i in range(256):
            crc = i << 24
            for j in range(8):
                if crc & 0x80000000:
                    crc = (crc << 1) ^ self.polynomial
                else:
                    crc <<= 1
            table.append(crc & 0xFFFFFFFF)
        return table

    def calculate(self, data: bytes) -> int:
        crc = self.init_value
        for byte in data:
            table_index = ((crc >> 24) ^ byte) & 0xFF
            crc = (crc << 8) ^ self.table[table_index]
            crc &= 0xFFFFFFFF 
        return crc ^ self.xor_out

class Bitmap:
    def __init__(self, size = 256):
        self.sum = 0
        self.size = size
        self.bitmap = [0] * size

    def _hash(self, item):
        hash_object = hashlib.md5(item.encode())
        hash_int = int(hash_object.hexdigest(), 16)
        return hash_int % self.size

    def add(self, item):
        index = self._hash(item)
        self.bitmap[index] = 1
        self.sum = self.sum + 1

    def count_0(self):
        sum_0 = 0
        for bit in self.bitmap:
            if bit == 0:
                sum_0 = sum_0 + 1
        return sum_0

    def count(self):
        m = self.size
        V = self.count_0()
        if V == 0:
            return m
        return -m * (math.log(V / m))

class Lemon_sketch:
    def __init__(self, size1 = 524288, size2 = 65536, size3 = 8192, size4 = 2048, size5 = 1024):
        #size1 = 65536
        self.l1_bitmapsize = 8
        self.l2_bitmapsize = 32
        self.l3_bitmapsize = 32
        self.l4_bitmapsize = 32
        self.l5_bitmapsize = 512

        self.sample1 = 16384
        self.sample2 = 4096
        self.sample3 = 1024
        self.sample4 = 256

        self.counter = [0] * size1

        self.layer1 = [Bitmap(self.l1_bitmapsize) for i in range(size1)]
        self.layer2 = [Bitmap(self.l2_bitmapsize) for i in range(size2)]
        self.layer3 = [Bitmap(self.l3_bitmapsize) for i in range(size3)]
        self.layer4 = [Bitmap(self.l4_bitmapsize) for i in range(size4)]
        self.layer5 = [Bitmap(self.l5_bitmapsize) for i in range(size5)]
        

        self.size1 = size1
        self.size2 = size2
        self.size3 = size3
        self.size4 = size4
        self.size5 = size5

    def insert(self, item_flow, item_pkg):
        """向数据结构中插入一个元素"""
        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer1 = int(hash_object.hexdigest(), 16) % self.size1

        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer2 = int(hash_object.hexdigest(), 16) % self.size2

        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer3 = int(hash_object.hexdigest(), 16) % self.size3

        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer4 = int(hash_object.hexdigest(), 16) % self.size4

        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer5 = int(hash_object.hexdigest(), 16) % self.size5

        hash_object = hashlib.sha512(item_pkg.encode())
        hash_deep = int(hash_object.hexdigest(), 16) % 65536


        self.counter[hash_layer1] = self.counter[hash_layer1] + 1

        if hash_deep < self.sample4:
            self.layer5[hash_layer5].add(item_pkg)
        elif hash_deep < self.sample3:
            self.layer4[hash_layer4].add(item_pkg)
        elif hash_deep < self.sample2:
            self.layer3[hash_layer3].add(item_pkg)
        elif hash_deep < self.sample1:
            self.layer2[hash_layer2].add(item_pkg)
        else:
            self.layer1[hash_layer1].add(item_pkg)

    def query(self, item_flow):
        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer1 = int(hash_object.hexdigest(), 16) % self.size1

        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer2 = int(hash_object.hexdigest(), 16) % self.size2

        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer3 = int(hash_object.hexdigest(), 16) % self.size3

        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer4 = int(hash_object.hexdigest(), 16) % self.size4

        hash_object = hashlib.sha384(item_flow.encode())
        hash_layer5 = int(hash_object.hexdigest(), 16) % self.size5

        l1_count_0 = self.layer1[hash_layer1].count_0()
        l2_count_0 = self.layer2[hash_layer2].count_0()
        l3_count_0 = self.layer3[hash_layer3].count_0()
        l4_count_0 = self.layer4[hash_layer4].count_0()
        l5_count_0 = self.layer5[hash_layer5].count_0()

        est1 = self.layer1[hash_layer1].count() + self.layer2[hash_layer2].count() + self.layer3[hash_layer3].count() + self.layer4[hash_layer4].count() 
        est2 = max(self.layer1[hash_layer1].count() * 65536/(65536 - self.sample1),1)
        est_layer1 = est2#min(est1,est2)

        est1 = self.layer2[hash_layer2].count() + self.layer3[hash_layer3].count() + self.layer4[hash_layer4].count() 
        est2 = self.layer2[hash_layer2].count() * 65536/(self.sample1 - self.sample2)
        est1 *= (65536/self.sample1)
        est_layer2 = est2#min(est1,est2)

        est1 = self.layer3[hash_layer3].count() + self.layer4[hash_layer4].count() 
        est2 = self.layer3[hash_layer3].count() * 65536/(self.sample2 - self.sample3)
        est1 *= (65536/self.sample2)
        est_layer3 = est2#min(est1,est2)

        est1 = self.layer4[hash_layer4].count() + self.layer5[hash_layer5].count() 
        est2 = self.layer4[hash_layer4].count() * (65536/(self.sample3 - self.sample4))
        est1 *= (65536/self.sample3)
        est_layer4 = est2#min(est1,est2)
    
        layertag = 0
        if l1_count_0 > self.l1_bitmapsize/5:
            return (est_layer1,1)#max(1,min(est1,est2))
        elif l2_count_0 > self.l2_bitmapsize/5:
            for i in range(0, int(self.size1/self.size2)):
                elimi_hash = hash_layer1 % self.size2 + i*self.size2
                if elimi_hash == hash_layer1:
                    continue
                est_layer2 -= self.layer1[elimi_hash].count() * 65536/(65536 - self.sample1)
            return (est_layer2,2)
        elif l3_count_0 > self.l3_bitmapsize/5:
            for i in range(0, int(self.size2/self.size3)):
                elimi_hash = hash_layer2 % self.size3 + i*self.size3
                if elimi_hash == hash_layer2:
                    continue
                est_layer3 -= self.layer2[elimi_hash].count()  * 65536/(self.sample1 - self.sample2)#* 65536/(65536 - self.sample2) * (65536/self.sample1)
            return (est_layer3,3)
        elif l4_count_0 > self.l4_bitmapsize/5:
            for i in range(0, int(self.size3/self.size4)):
                elimi_hash = hash_layer4 % self.size4 + i*self.size4
                if elimi_hash == hash_layer3:
                    continue
                est_layer4 -= self.layer3[elimi_hash].count() * 65536/(self.sample2 - self.sample3) #* 65536/(65536 - self.sample3) * (65536/self.sample2)
            return (est_layer4,4)
        else:
            est_layer5 = (self.layer5[hash_layer5].count() * (65536/self.sample4))
            for i in range(0, int(self.size4/self.size5)):
                elimi_hash = hash_layer4 % self.size5 + i*self.size5
                if elimi_hash == hash_layer4:
                    continue
                est_layer5 -= self.layer4[elimi_hash].count() * 65536/(self.sample3 - self.sample4)# 65536/(65536 - self.sample4) * (65536/self.sample3)
            return (est_layer5,5)

    def query_hash(self, hashnum):
        hash_layer1 = hashnum % self.size1
        hash_layer2 = hashnum % self.size2
        hash_layer3 = hashnum % self.size3
        hash_layer4 = hashnum % self.size4
        hash_layer5 = hashnum % self.size5

        l1_count_0 = self.layer1[hash_layer1].count_0()
        l2_count_0 = self.layer2[hash_layer2].count_0()
        l3_count_0 = self.layer3[hash_layer3].count_0()
        l4_count_0 = self.layer4[hash_layer4].count_0()
        l5_count_0 = self.layer5[hash_layer5].count_0()

        est1 = self.layer1[hash_layer1].count() + self.layer2[hash_layer2].count() + self.layer3[hash_layer3].count() + self.layer4[hash_layer4].count() 
        est2 = max(self.layer1[hash_layer1].count() * 65536/(65536 - self.sample1),1)
        est_layer1 = min(est1,est2)

        est1 = self.layer2[hash_layer2].count() + self.layer3[hash_layer3].count() + self.layer4[hash_layer4].count() 
        est2 = self.layer2[hash_layer2].count() * 65536/(65536 - self.sample2) * (65536/self.sample1)
        est1 *= (65536/self.sample1)
        est_layer2 = min(est1,est2)

        est1 = self.layer3[hash_layer3].count() + self.layer4[hash_layer4].count() 
        est2 = self.layer3[hash_layer3].count() * 65536/(65536 - self.sample3) * (65536/self.sample2)
        est1 *= (65536/self.sample2)
        est_layer3 = min(est1,est2)

        est1 = self.layer4[hash_layer4].count() + self.layer5[hash_layer5].count() 
        est2 = self.layer4[hash_layer4].count() * 65536/(65536 - self.sample4) * (65536/self.sample3)
        est1 *= (65536/self.sample3)
        est_layer4 = min(est1,est2)
    
        layertag = 0
        if l1_count_0 > self.l1_bitmapsize/5:
            return est_layer1#max(1,min(est1,est2))
        elif l2_count_0 > self.l2_bitmapsize/5:
            for i in range(0, int(self.size1/self.size2)):
                elimi_hash = hash_layer1 % self.size2 + i*self.size2
                if elimi_hash == hash_layer1:
                    continue
                est_layer2 -= self.layer1[elimi_hash].count() * 65536/(65536 - self.sample1)
            return est_layer2
        elif l3_count_0 > self.l3_bitmapsize/5:
            for i in range(0, int(self.size2/self.size3)):
                elimi_hash = hash_layer2 % self.size3 + i*self.size3
                if elimi_hash == hash_layer2:
                    continue
                est_layer3 -= self.layer2[elimi_hash].count()  * 65536/(65536 - self.sample2) * (65536/self.sample1)
            return est_layer3
        elif l4_count_0 > self.l4_bitmapsize/5:
            for i in range(0, int(self.size3/self.size4)):
                elimi_hash = hash_layer4 % self.size4 + i*self.size4
                if elimi_hash == hash_layer3:
                    continue
                est_layer4 -= self.layer3[elimi_hash].count()   * 65536/(65536 - self.sample3) * (65536/self.sample2)
            return est_layer4
        else:
            est_layer5 = (self.layer5[hash_layer5].count() * (65536/self.sample4))
            for i in range(0, int(self.size4/self.size5)):
                elimi_hash = hash_layer4 % self.size5 + i*self.size5
                if elimi_hash == hash_layer4:
                    continue
                est_layer5 -= self.layer4[elimi_hash].count() * 65536/(65536 - self.sample4) * (65536/self.sample3)
            return est_layer5


    def counter_query(self, item_flow):
        hash_object = hashlib.sha384(item_flow.encode())
        hash_int = int(hash_object.hexdigest(), 16) % self.size1
        l_count_0 = self.counter[hash_int]
        return l_count_0

def Lemon_merge(lemon1,lemon2):
    lemon3 = Lemon_sketch()
    for i in range(0,lemon3.size1):
        for bit in range(0,lemon3.l1_bitmapsize):
            lemon3.layer1[i].bitmap[bit] = lemon1.layer1[i].bitmap[bit] | lemon2.layer1[i].bitmap[bit]

    for i in range(0,lemon3.size2):
        for bit in range(0,lemon3.l2_bitmapsize):
            lemon3.layer2[i].bitmap[bit] = lemon1.layer2[i].bitmap[bit] | lemon2.layer2[i].bitmap[bit]

    for i in range(0,lemon3.size3):
        for bit in range(0,lemon3.l3_bitmapsize):
            lemon3.layer3[i].bitmap[bit] = lemon1.layer3[i].bitmap[bit] | lemon2.layer3[i].bitmap[bit]

    for i in range(0,lemon3.size4):
        for bit in range(0,lemon3.l4_bitmapsize):
            lemon3.layer4[i].bitmap[bit] = lemon1.layer4[i].bitmap[bit] | lemon2.layer4[i].bitmap[bit]
    
    
    for i in range(0,lemon3.size5):
        for bit in range(0,lemon3.l5_bitmapsize):
            lemon3.layer5[i].bitmap[bit] = lemon1.layer5[i].bitmap[bit] | lemon2.layer5[i].bitmap[bit]
    
    for i in range(0,lemon3.size1):    
        cardi_1 = lemon1.query_hash(i)
        counter_1 = lemon1.counter[i]

        cardi_2 = lemon2.query_hash(i)
        counter_2 = lemon2.counter[i]

        cardi_3 = lemon3.query_hash(i)

        if counter_1==0 or cardi_1==0:
            lemon3.counter[i] = counter_2
        elif counter_2==0 or cardi_2==0:
            lemon3.counter[i] = counter_1
        else:
            lemon3.counter[i] = cardi_3*(0.5*counter_1/cardi_1 + 0.5*counter_2/cardi_2)
    return lemon3

if __name__ == "__main__":
    # Example usage
    background_num = 5000000
    lemon = Lemon_sketch()
    lemon1 = Lemon_sketch()
    lemon2 = Lemon_sketch()
    lemon3 = Lemon_sketch()

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
            
            #ip = dpkt.ip.IP(buf) #eth.data
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            protocol = ip.p
            ipsum = ip.sum
            tcpsum = 0
            udpsum = 0
            src_port = dst_port = None
            pkg_tag = None

            #if not isinstance(ip.data, dpkt.udp.UDP):
            #    continue

            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                src_port = tcp.sport
                dst_port = tcp.dport
                tcpsum = tcp.sum
                seq_num = tcp.seq
                pkg_tag = str(seq_num)
                #print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, Seq: {seq_num}")
            else:
                if isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    src_port = udp.sport
                    dst_port = udp.dport
                    udpsum = udp.sum

                # Make sure we have data payload to read
                payload = bytes(ip.data.data) if hasattr(ip.data, 'data') else b''
                payload_first_16 = payload[:16].hex()
                #print(f"Non-TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, Payload (first 16 bytes): {payload_first_16}")
                pkg_tag = str(payload_first_16)

            flow_id = f'{src_ip}{dst_ip}{src_port}{dst_port}{protocol}'
            pkg_id = f'{src_ip}{dst_ip}{src_port}{dst_port}{protocol}{pkg_tag}{ipsum}{tcpsum}{udpsum}'
            lemon.insert(flow_id,pkg_id)
            #simulating topologies by select Lemon to insert

    #query lemon, enter your flow key before this
    flow_id = f'{src_ip}{dst_ip}{src_port}{dst_port}{protocol}'
    lemon.query(flow_id)
