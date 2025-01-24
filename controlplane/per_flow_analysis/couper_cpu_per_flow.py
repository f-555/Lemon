import math
import hashlib
import dpkt
import dpkt
import socket

class HyperLogLog:
    def __init__(self, b = 6):
        self.b = b
        self.m = 2 ** b
        self.alpha = self._get_alpha(self.m)
        self.registers = [0] * self.m

    def _get_alpha(self, m):
        if m == 16:
            return 0.673
        elif m == 32:
            return 0.697
        elif m == 64:
            return 0.709
        else:
            return 0.7213 / (1 + 1.079 / m)

    def _hash(self, data):
        return hashlib.md5(data.encode()).hexdigest()[-16:]

    def _rho(self, w):
        # Calculate the rank of the binary number w (number of leading zeros + 1)
        return len(bin(w)) - bin(w).rfind('1')

    def add(self, item):
        hashed_item = self._hash(item)
        hashed_item_int = int(hashed_item, 16)
        index = hashed_item_int >> (64 - self.b)
        w = hashed_item_int & ((1 << (64 - self.b)) - 1)
        self.registers[index] = max(self.registers[index], self._rho(w))

    def count(self):
        Z = 1.0 / sum([2.0 ** -reg for reg in self.registers])
        estimate = self.alpha * (self.m ** 2) * Z

        # Bias correction
        if estimate <= 2.5 * self.m:
            zeros = self.registers.count(0)
            if zeros != 0:
                estimate = self.m * math.log(self.m / zeros)
        elif estimate > (1 / 30.0) * 2 ** 32:
            estimate = -(2 ** 32) * math.log(1 - (estimate / 2 ** 32))

        return int(estimate)

class Bitmap:
    def __init__(self, size = 256):
        self.sum = 0
        self.size = size
        self.bitmap = [0] * size

    def _hash(self, item):
        hash_object = hashlib.sha512(item.encode())
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
            return 45
        return -m * (math.log(V / m))

class Couper:
    def __init__(self, lsize = 524288, hsize = 1024):
        self.lpart1_layer1 = [Bitmap(16) for i in range(lsize)] #[Bitmap(256)]*lsize
        #self.lpart1_layer2 = [Bitmap(256)]*lsize
        self.counter_layer1 = [0]* lsize
        #self.counter_layer2 = [0]*lsize
        self.hpart = [HyperLogLog() for i in range(hsize)] #[HyperLogLog()] * hsize
        self.l2h = 25
        self.lsize = lsize
        self.hsize = hsize

    def insert(self, item_flow, item_pkg):
        hash_object = hashlib.sha384(item_flow.encode())
        hash_int = int(hash_object.hexdigest(), 16) % self.lsize

        hash_object = hashlib.sha384(item_flow.encode())
        hash_int_h = int(hash_object.hexdigest(), 16) % self.hsize

        if self.counter_layer1[hash_int] < self.l2h:
            self.lpart1_layer1[hash_int].add(item_pkg)
            self.counter_layer1[hash_int] = self.counter_layer1[hash_int] + 1
           # print(hash_int)
            #print(hash_int)
        else:
            self.hpart[hash_int_h].add(item_pkg)

    def query(self, item_flow):
        hash_object = hashlib.sha384(item_flow.encode())
        hash_int = int(hash_object.hexdigest(), 16) % self.lsize

        hash_object = hashlib.sha384(item_flow.encode())
        hash_int_h = int(hash_object.hexdigest(), 16) % self.hsize

        l_count = self.lpart1_layer1[hash_int].count()
        if self.counter_layer1[hash_int] < self.l2h and not(l_count == 45):
            h_count = 0
            return l_count
        h_count = self.hpart[hash_int_h].count()
        #print(hash_int)
        #print(l_count)
        #print(self.counter_layer1[hash_int])
        return l_count + h_count

def merge(couper1,couper2):
    couper3 = Couper()
    for i in range(0,couper3.lsize):
        count_bit = 0
        for bit in range(0,16):
            couper3.lpart1_layer1[i].bitmap[bit] = couper1.lpart1_layer1[i].bitmap[bit] | couper2.lpart1_layer1[i].bitmap[bit]
            if couper3.lpart1_layer1[i].bitmap[bit] == 0:
                count_bit += 1
        if count_bit == 0:
            couper3.counter_layer1[i] = 1000
        else:
            couper3.counter_layer1[i] = -16 * (math.log(count_bit / 16))


    for i in range(0,couper3.hsize):
        for index in range(0,len(couper3.hpart[i].registers)):
            couper3.hpart[i].registers[index] = max(couper1.hpart[i].registers[index],couper2.hpart[i].registers[index])

    #for i in range(0,couper3.lsize):
    #    couper3.counter_layer1 = couper1.counter_layer1 + couper2.counter_layer1

    return couper3




if __name__ == "__main__":
    # Example usage
    couper = Couper()
    couper1 = Couper()
    couper2 = Couper()
    couper3 = Couper()
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
            
            ip = eth.data
            #ip = dpkt.ip.IP(buf)
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            protocol = ip.p
            src_port = dst_port = None
            pkg_tag = None
            ipsum = ip.sum
            tcpsum = 0
            udpsum = 0

            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                src_port = tcp.sport
                dst_port = tcp.dport
                seq_num = tcp.seq
                tcpsum = tcp.sum
                pkg_tag = str(seq_num) + str(tcpsum)
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
                pkg_tag = f'{str(payload_first_16)}{ipsum}{tcpsum}{udpsum}'

            flow_id = f'{src_ip}{dst_ip}{src_port}{dst_port}{protocol}'
            pkg_id = f'{src_ip}{dst_ip}{src_port}{dst_port}{protocol}{pkg_tag}'
            
            couper.insert(flow_id,pkg_id)
            #simulating topologies by select Couper to insert

            #query lemon, enter your flow key before this
            flow_id = f'{src_ip}{dst_ip}{src_port}{dst_port}{protocol}'
            couper.query(flow_id)

