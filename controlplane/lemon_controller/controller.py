#coding:utf-8
from calendar import EPOCH
from xml.dom.expatbuilder import theDOMImplementation
import struct
import threading
import time
import logging
import heapq
# from p4utils.utils.topology import Topology
# from p4utils.utils.sswitch_API import SimpleSwitchAPI
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.all import Ether, sniff, Packet, BitField,IP,sendp,raw
import csv
import os
import math
import numpy as np

def int_to_ip(num):
    return '.'.join([str(num >> 24 & 0xFF), str(num >> 16 & 0xFF), str(num >> 8 & 0xFF), str(num & 0xFF)])

def lc(zeros,bitmap):
    m = bitmap
    V = zeros
    if V == 0:
        return m 
    ##print(V,len(self.bitmap),self.sum)
    return -m * (math.log(V / m))

def epy(bloom_filter, size):
    total_elements = sum(bloom_filter)
    probabilities = [count / total_elements if total_elements > 0 else 0 for count in bloom_filter]
    entropy = 0
    for prob in probabilities:
        if prob > 0:
            entropy -= prob * math.log(prob,2)
    return entropy

def epy_old(counter,size): #return the number of 1 in bitmap
    counter_dst = [0] * int(round(max(counter)))
    num0 = 0
    for i in range(0,size):
        cnt = int(round(counter[i]))
        if cnt == 0:
            num0 = num0 + 1
            continue
        counter_dst[cnt-1] = counter_dst[cnt-1] + 1

    n_ini = int(round(max(counter))) - num0
    m = size
    lambda_all = n_ini/m

    counter_dst_em = [0] * int(round(max(counter)))
    counter_dst_em[512:int(round(max(counter)))-1] = counter_dst[512:int(round(max(counter)))-1]
    counter_dst_em[0] = counter_dst[0]

    for i in range(1,int(max(counter)/2)):
        if counter_dst[i] == 0:
            continue
        sp1 = 0
        sp2 = 0
        sump = 0
        for j in range(0,int((i+1)/2)+1):
            sp1 = float(j)
            sp2 = float(i-j+1)
            p = ((sp1/m)**1) * ((sp2/m)**1)
            if j == 0:
                p = ((sp2/m)**2)              
            sump = sump + p
        
        for j in range(0,int(i/2)+1):
            sp1 = float(j)
            sp2 = float(i-j+1)
            p = ((sp1/m)**1) * ((sp2/m)**1)
            if j == 0:
                p = ((sp2/m)**2)  

            if(sp1 == 0):
                counter_dst_em[int(sp2)] = counter_dst_em[int(sp2)] + p/sump * counter_dst[i]
            else:
                counter_dst_em[int(sp1)] = counter_dst_em[int(sp1)] + p/sump * counter_dst[i]
                counter_dst_em[int(sp2)] = counter_dst_em[int(sp2)] + p/sump * counter_dst[i]
            
    entropy_em = 0.0
    for i in range(0,int(round(max(counter)))):
        entropy_em = entropy_em + counter_dst_em[i]*(float(i+1)/sum(counter))*math.log(sum(counter)/float(i+1),2)

    return entropy_em

def checkbitmap(item): #return the number of 1 in bitmap
    ones = 0
    part = bin(item)[2:]
    for i in range(0,len(part)):
        if part[i] == '1':
            ones = ones + 1
    return ones

class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('hash',0,32),BitField('hash1',0,32), BitField('srcip', 0, 32), BitField('dstip', 0, 32),BitField('srcport', 0, 16),BitField('dstport', 0, 16),BitField('protocol', 0, 8),BitField('counter', 0, 32),BitField('epoch', 0, 16),BitField('outputport', 0, 8)]

class myController(object):
    def __init__(self):
        self.topo = load_topo("topology.json")
        self.controllers = {}

        self.hh_dip={}
        self.hh_hash={}
        self.hh_count={}
        self.layer1={}
        self.layer2={}
        self.layer3={} 
        self.layer4={}  
        self.layer5={} 
        self.counter={}

        self.l1_bitmapsize = 8
        self.l2_bitmapsize = 32
        self.l3_bitmapsize = 32
        self.l4_bitmapsize = 32
        self.l5_bitmapsize = 512

        self.sample1 = 16384
        self.sample2 = 8192
        self.sample3 = 1024
        self.sample4 = 256

        size1 = 524288
        size2 = 65536
        size3 = 8192
        size4 = 2048
        size5 = 1024

        self.size1 = size1
        self.size2 = size2
        self.size3 = size3
        self.size4 = size4
        self.size5 = size5

        
        self.layer1_merge=[0] * size1 * self.l1_bitmapsize
        self.layer2_merge=[0] * size2 * self.l2_bitmapsize
        self.layer3_merge=[0] * size3 * self.l3_bitmapsize
        self.layer4_merge=[0] * size4 * self.l4_bitmapsize
        self.layer5_merge=[0] * size5 * self.l5_bitmapsize
        
        self.heavysize = 8192
        self.connect_to_switches()

    def collect_merge(self):
        self.hh_dip={} # clean controller
        for p4switch in self.topo.get_p4switches():
            if (len(p4switch)==4):
                continue
            if (len(p4switch)>4):
                continue
            heavy_dip = self.controllers[p4switch].register_read("lemon_heavy_id")
            heavy_hash = self.controllers[p4switch].register_read("lemon_heavy_tag")
            self.layer1[p4switch] = self.controllers[p4switch].register_read("lemon_layer1")
            self.layer2[p4switch] = self.controllers[p4switch].register_read("lemon_layer2")
            self.layer3[p4switch] = self.controllers[p4switch].register_read("lemon_layer3")
            self.layer4[p4switch] = self.controllers[p4switch].register_read("lemon_layer4")
            self.layer5[p4switch] = self.controllers[p4switch].register_read("lemon_layer5")  
            self.counter[p4switch] = self.controllers[p4switch].register_read("counter") #CM-added on

            #finish collecting, merge heavy
            for slot in range(0,self.heavysize):
                if heavy_dip[slot] !=0 and (slot not in self.hh_dip.keys()):
                    self.hh_dip[slot] = heavy_dip[slot]
                    self.hh_hash[slot] = heavy_hash[slot]
                    self.hh_count[slot] = self.counter[p4switch][heavy_hash[slot]%self.size1]
                elif heavy_dip[slot] !=0 and (slot in self.hh_dip.keys()):
                    if self.counter[p4switch][heavy_hash[slot]%self.size1] > self.hh_count[slot]:
                        self.hh_dip[slot] = heavy_dip[slot] #update
                        self.hh_hash[slot] = heavy_hash[slot]
                        self.hh_count[slot] = self.counter[p4switch][heavy_hash[slot]%self.size1]
                    else:
                        continue
                else:
                    continue

            #We used a simple loop for functional testing, which required a longer merge time.
            self.layer1_merge = [a | b for a, b in zip(self.layer1_merge, self.layer1[p4switch])]
            self.layer2_merge = [a | b for a, b in zip(self.layer2_merge, self.layer2[p4switch])]
            self.layer3_merge = [a | b for a, b in zip(self.layer3_merge, self.layer3[p4switch])]
            self.layer4_merge = [a | b for a, b in zip(self.layer4_merge, self.layer4[p4switch])]
            self.layer5_merge = [a | b for a, b in zip(self.layer5_merge, self.layer5[p4switch])]

    def query_with_hash(self,l1_hash):
        layer1 = {}
        layer1_switch = self.layer1_merge
        layer_index = l1_hash % self.size1
        layer1[layer_index] = layer1_switch[layer_index*self.l1_bitmapsize:layer_index*self.l1_bitmapsize+self.l1_bitmapsize]
        
        layer2 = {}
        layer2_switch = self.layer2_merge
        layer_index = l1_hash % self.size2
        layer2[layer_index] = layer2_switch[layer_index*self.l2_bitmapsize:layer_index*self.l2_bitmapsize+self.l2_bitmapsize]

        layer3 = {}
        layer3_switch = self.layer3_merge
        layer_index = l1_hash % self.size3
        layer3[layer_index] = layer3_switch[layer_index*self.l3_bitmapsize:layer_index*self.l3_bitmapsize+self.l3_bitmapsize]

        layer4 = {}
        layer4_switch = self.layer4_merge
        layer_index = l1_hash % self.size4
        layer4[layer_index] = layer4_switch[layer_index*self.l4_bitmapsize:layer_index*self.l4_bitmapsize+self.l4_bitmapsize]

        layer5 = {}
        layer5_switch = self.layer5_merge
        layer_index = l1_hash % self.size5
        layer5[layer_index] = layer5_switch[layer_index*self.l5_bitmapsize:layer_index*self.l5_bitmapsize+self.l5_bitmapsize] 

        l1_count_0 = self.l1_bitmapsize -  sum(layer1[l1_hash % self.size1])
        l2_count_0 = self.l2_bitmapsize -  sum(layer2[l1_hash % self.size2])
        l3_count_0 = self.l3_bitmapsize -  sum(layer3[l1_hash % self.size3])
        l4_count_0 = self.l4_bitmapsize -  sum(layer4[l1_hash % self.size4])
        l5_count_0 = self.l5_bitmapsize -  sum(layer5[l1_hash % self.size5])

        l1_est = lc(l1_count_0, self.l1_bitmapsize)
        l2_est = lc(l2_count_0, self.l2_bitmapsize)
        l3_est = lc(l3_count_0, self.l3_bitmapsize)
        l4_est = lc(l4_count_0, self.l4_bitmapsize)
        l5_est = lc(l5_count_0, self.l5_bitmapsize)

        est1 = l1_est + l2_est + l3_est + l4_est + l5_est 
        est2 = max(l1_est * 65536/(65536 - self.sample1),1)
        est_layer1 = est2

        est1 = l2_est + l3_est + l4_est + l5_est 
        est2 = l2_est * 65536/(65536 - self.sample2) * (65536/self.sample1)
        est1 *= (65536/self.sample1)
        est_layer2 = est2

        est1 = l3_est + l4_est + l5_est  
        est2 = l3_est * 65536/(65536 - self.sample3) * (65536/self.sample2)
        est1 *= (65536/self.sample2)
        est_layer3 = est2

        est1 = l4_est + l5_est 
        est2 = l4_est * 65536/(65536 - self.sample4) * (65536/self.sample3)
        est1 *= (65536/self.sample3)
        est_layer4 = est2

        layer = 0
        if l1_count_0 > self.l1_bitmapsize/5:
            Est = est_layer1
            layer = 1
        elif l2_count_0 > self.l2_bitmapsize/5:
            Est = max(est_layer1,est_layer2)
            layer = 2
        elif l3_count_0 > self.l3_bitmapsize/5:
            Est = max(est_layer2,est_layer3)
            layer = 3
        elif l4_count_0 > self.l4_bitmapsize/5:
            Est = max(est_layer3,est_layer4)
            layer = 4
        else:
            Est = max(l5_est* (65536/self.sample4),est_layer4)
            layer = 5
        return (est,layer)

    def query(self):
        for hh_id in range(0,self.heavysize):
            if hh_id not in self.hh_dip.keys():
                continue
            l1_hash = self.hh_hash[hh_id]
            
            layer1 = {}
            layer1_switch = self.layer1_merge
            layer_index = l1_hash % self.size1
            layer1[layer_index] = layer1_switch[layer_index*self.l1_bitmapsize:layer_index*self.l1_bitmapsize+self.l1_bitmapsize]

            #print(layer1[layer_index])
            #break

            layer2 = {}
            layer2_switch = self.layer2_merge
            layer_index = l1_hash % self.size2
            layer2[layer_index] = layer2_switch[layer_index*self.l2_bitmapsize:layer_index*self.l2_bitmapsize+self.l2_bitmapsize]

            layer3 = {}
            layer3_switch = self.layer3_merge
            layer_index = l1_hash % self.size3
            layer3[layer_index] = layer3_switch[layer_index*self.l3_bitmapsize:layer_index*self.l3_bitmapsize+self.l3_bitmapsize]

            layer4 = {}
            layer4_switch = self.layer4_merge
            layer_index = l1_hash % self.size4
            layer4[layer_index] = layer4_switch[layer_index*self.l4_bitmapsize:layer_index*self.l4_bitmapsize+self.l4_bitmapsize]

            layer5 = {}
            layer5_switch = self.layer5_merge
            layer_index = l1_hash % self.size5
            layer5[layer_index] = layer5_switch[layer_index*self.l5_bitmapsize:layer_index*self.l5_bitmapsize+self.l5_bitmapsize] 

            l1_count_0 = self.l1_bitmapsize -  sum(layer1[l1_hash % self.size1])
            l2_count_0 = self.l2_bitmapsize -  sum(layer2[l1_hash % self.size2])
            l3_count_0 = self.l3_bitmapsize -  sum(layer3[l1_hash % self.size3])
            l4_count_0 = self.l4_bitmapsize -  sum(layer4[l1_hash % self.size4])
            l5_count_0 = self.l5_bitmapsize -  sum(layer5[l1_hash % self.size5])

            l1_est = lc(l1_count_0, self.l1_bitmapsize)
            l2_est = lc(l2_count_0, self.l2_bitmapsize)
            l3_est = lc(l3_count_0, self.l3_bitmapsize)
            l4_est = lc(l4_count_0, self.l4_bitmapsize)
            l5_est = lc(l5_count_0, self.l5_bitmapsize)


            est_layer1 = l1_est * 65536/(65536 - self.sample1)
            est_layer2 = l2_est * 65536/(self.sample1 - self.sample2)
            est_layer3 = l3_est * 65536/(self.sample2 - self.sample3)
            est_layer4 = l4_est * 65536/(self.sample3 - self.sample4)
            est_layer5 = l5_est * 65536/self.sample4

            if l1_count_0 > self.l1_bitmapsize/5:
                Est = est_layer1
            elif l2_count_0 > self.l2_bitmapsize/5:
                for i in range(0, int(self.size1/self.size2)):
                    elimi_hash = l1_hash % self.size2 + i*self.size2
                    layer1[elimi_hash] = layer1_switch[elimi_hash*self.l1_bitmapsize:elimi_hash*self.l1_bitmapsize+self.l1_bitmapsize]
                    l1_count_0 = self.l1_bitmapsize -  sum(layer1[elimi_hash])    
                    l1_est = lc(l1_count_0, self.l1_bitmapsize)
                    if elimi_hash == l1_hash % self.size2 or l1_count_0 < self.l1_bitmapsize/5:
                        continue
                    est_layer2 -= l1_est * 65536/(65536 - self.sample1)
                Est = est_layer2
            elif l3_count_0 > self.l3_bitmapsize/5:
                for i in range(0, int(self.size2/self.size3)):
                    elimi_hash = l1_hash % self.size3 + i*self.size3
                    layer2[elimi_hash] = layer2_switch[elimi_hash*self.l2_bitmapsize:elimi_hash*self.l2_bitmapsize+self.l2_bitmapsize]
                    l2_count_0 = self.l2_bitmapsize -  sum(layer2[elimi_hash])    
                    l2_est = lc(l2_count_0, self.l2_bitmapsize)
                    if elimi_hash == l1_hash % self.size3 or l2_count_0 < self.l2_bitmapsize/5:
                        continue
                    est_layer3 -= l2_est * 65536/(self.sample1 - self.sample2)
                Est = est_layer3
            elif l4_count_0 > self.l4_bitmapsize/5:
                for i in range(0, int(self.size3/self.size4)):
                    elimi_hash = l1_hash % self.size4 + i*self.size4
                    layer3[elimi_hash] = layer3_switch[elimi_hash*self.l3_bitmapsize:elimi_hash*self.l3_bitmapsize+self.l3_bitmapsize]
                    l3_count_0 = self.l3_bitmapsize -  sum(layer3[elimi_hash])    
                    l3_est = lc(l3_count_0, self.l3_bitmapsize)
                    if elimi_hash == l1_hash % self.size4 or l3_count_0 < self.l3_bitmapsize/5:
                        continue
                    est_layer4 -= l3_est * 65536/(self.sample2 - self.sample3)
                Est = est_layer4
            else:
                for i in range(0, int(self.size4/self.size5)):
                    elimi_hash = l1_hash % self.size5 + i*self.size5
                    layer4[elimi_hash] = layer4_switch[elimi_hash*self.l4_bitmapsize:elimi_hash*self.l4_bitmapsize+self.l4_bitmapsize]
                    l4_count_0 = self.l4_bitmapsize -  sum(layer4[elimi_hash])    
                    l4_est = lc(l4_count_0, self.l4_bitmapsize)
                    if elimi_hash == l1_hash % self.size5 or l4_count_0 < self.l4_bitmapsize/5:
                        continue
                    est_layer5 -= l4_est * 65536/(self.sample3 - self.sample4)
                Est = est_layer5

            c = self.counter['s01'][l1_hash % self.size1]
            if(c<1000):
                continue
            ip = int_to_ip(self.hh_dip[hh_id])
            print(f"{ip},{c},{Est}")
            logging.info(f"{ip},{c},{Est}")

    def entropy(self):
        epy_map = []
        for slot in range(0,self.size1):
            l1_hash = slot
            l1_bitmap = self.layer1_merge[slot*self.l1_bitmapsize:slot*self.l1_bitmapsize+self.l1_bitmapsize]
            l1_count_0 = self.l1_bitmapsize - sum(l1_bitmap)
            if l1_count_0 > self.l1_bitmapsize * 0.8:
                epy_map.append(lc(l1_count_0, self.l1_bitmapsize))
                continue

            
            l2_hash = slot % self.size2
            l2_bitmap = self.layer2_merge[l2_hash*self.l2_bitmapsize:l2_hash*self.l2_bitmapsize+self.l2_bitmapsize]
            l2_count_0 = self.l2_bitmapsize - sum(l2_bitmap)
            if l2_count_0 > self.l2_bitmapsize * 0.2:
                l2_est = lc(l2_count_0, self.l2_bitmapsize) * 65536/(65536 - self.sample2) * (65536/self.sample1)
                epy_map.append(l2_est)
                continue

            l3_hash = slot % self.size3
            l3_bitmap = self.layer3_merge[l3_hash*self.l3_bitmapsize:l3_hash*self.l3_bitmapsize+self.l3_bitmapsize]
            l3_count_0 = self.l3_bitmapsize - sum(l3_bitmap)
            if l3_count_0 > self.l3_bitmapsize * 0.2:
                l3_est = lc(l3_count_0, self.l3_bitmapsize)  * 65536/(65536 - self.sample3) * (65536/self.sample2)
                epy_map.append(l3_est)
                continue

            l4_hash = slot % self.size4
            l4_bitmap = self.layer4_merge[l4_hash*self.l4_bitmapsize:l4_hash*self.l4_bitmapsize+self.l4_bitmapsize]
            l4_count_0 = self.l4_bitmapsize - sum(l4_bitmap)
            if l4_count_0 > self.l4_bitmapsize * 0.2:
                l4_est = lc(l4_count_0, self.l4_bitmapsize) * 65536/(65536 - self.sample4) * (65536/self.sample3)
                epy_map.append(l4_est)
                continue

            l5_hash = slot % self.size5
            l5_bitmap = self.layer5_merge[l5_hash*self.l5_bitmapsize:l5_hash*self.l5_bitmapsize+self.l5_bitmapsize]
            l5_count_0 = self.l5_bitmapsize - sum(l5_bitmap)
            l5_est = lc(l5_count_0, self.l5_bitmapsize) * (65536/self.sample4)
            epy_map.append(l5_est)
        entropy = epy(epy_map, self.size1)
        logging.info('entropy_src: %f', entropy)

    def heavyhitter_only(self):
        self.hh_dip={}
        for p4switch in self.topo.get_p4switches():
            if (len(p4switch)==4):
                continue
            if (len(p4switch)>4):
                continue
            print(1)
            heavy_dip = self.controllers[p4switch].register_read("lemon_heavy_id")
            heavy_hash = self.controllers[p4switch].register_read("lemon_heavy_tag")
            self.layer1[p4switch] = self.controllers[p4switch].register_read("lemon_layer1")
            self.layer2[p4switch] = self.controllers[p4switch].register_read("lemon_layer2")
            self.layer3[p4switch] = self.controllers[p4switch].register_read("lemon_layer3")
            self.layer4[p4switch] = self.controllers[p4switch].register_read("lemon_layer4")
            self.layer5[p4switch] = self.controllers[p4switch].register_read("lemon_layer5")  
            self.counter[p4switch] = self.controllers[p4switch].register_read("counter")    

            for slot in range(0,self.heavysize):
                if heavy_dip[slot] !=0:
                    self.hh_dip[slot] = heavy_dip[slot]
                    self.hh_hash[slot] = heavy_hash[slot]

        for hh_id in range(0,self.heavysize):
            if hh_id not in self.hh_dip.keys():
                continue
            l1_hash = self.hh_hash[hh_id]

            c = self.counter['s01'][l1_hash % self.size1]
            if(c<1000):
                continue
            
            print(l1_hash)

            layer1 = {}
            for layer1_swh in self.layer1.keys():
                layer1_switch = self.layer1[layer1_swh]
                layer_index = l1_hash % self.size1
                if layer_index in layer1.keys():
                    list1 = layer1[layer_index]
                    list2 = layer1_switch[layer_index*self.l1_bitmapsize:layer_index*self.l1_bitmapsize+self.l1_bitmapsize]
                    layer1[layer_index] =  [a | b for a, b in zip(list1, list2)]
                else:
                    layer1[layer_index] = layer1_switch[layer_index*self.l1_bitmapsize:layer_index*self.l1_bitmapsize+self.l1_bitmapsize]
            
            layer2 = {}
            for layer2_name in self.layer2.keys():
                layer2_switch = self.layer2[layer2_name]
                layer_index = l1_hash % self.size2
                if layer_index in layer2.keys():
                    list1 = layer2[layer_index]
                    list2 = layer2_switch[layer_index*self.l2_bitmapsize:layer_index*self.l2_bitmapsize+self.l2_bitmapsize]
                    layer2[layer_index] = [a | b for a, b in zip(list1, list2)]
                else:
                    layer2[layer_index] = layer2_switch[layer_index*self.l2_bitmapsize:layer_index*self.l2_bitmapsize+self.l2_bitmapsize]
                #print(sum(layer2[layer_index]))

            layer3 = {}
            for layer3_name in self.layer3.keys():
                layer3_switch = self.layer3[layer3_name]
                layer_index = l1_hash % self.size3
                if layer_index in layer3.keys():
                    list1 = layer3[layer_index]
                    list2 = layer3_switch[layer_index*self.l3_bitmapsize:layer_index*self.l3_bitmapsize+self.l3_bitmapsize]
                    layer3[layer_index] = [a | b for a, b in zip(list1, list2)]
                else:
                    layer3[layer_index] = layer3_switch[layer_index*self.l3_bitmapsize:layer_index*self.l3_bitmapsize+self.l3_bitmapsize]
                
                #print(sum(layer3[layer_index]))

            layer4 = {}
            for layer4_name in self.layer4.keys():
                layer4_switch = self.layer4[layer4_name]
                layer_index = l1_hash % self.size4
                if layer_index in layer4.keys():
                    list1 = layer4[layer_index]
                    list2 = layer4_switch[layer_index*self.l4_bitmapsize:layer_index*self.l4_bitmapsize+self.l4_bitmapsize]
                    layer4[layer_index] = [a | b for a, b in zip(list1, list2)]
                else:
                    layer4[layer_index] = layer4_switch[layer_index*self.l4_bitmapsize:layer_index*self.l4_bitmapsize+self.l4_bitmapsize]
                #print(sum(layer4[layer_index]))

            layer5 = {}
            for layer5_name in self.layer5.keys():
                layer5_switch = self.layer5[layer5_name]
                layer_index = l1_hash % self.size5
                if layer_index in layer5.keys():
                    list1 = layer5[layer_index]
                    list2 = layer5_switch[layer_index*self.l5_bitmapsize:layer_index*self.l5_bitmapsize+self.l5_bitmapsize]
                    layer5[layer_index] = [a | b for a, b in zip(list1, list2)]
                else:
                    layer5[layer_index] = layer5_switch[layer_index*self.l5_bitmapsize:layer_index*self.l5_bitmapsize+self.l5_bitmapsize] 
                #print(sum(layer5[layer_index])) 

            l1_count_0 = self.l1_bitmapsize -  sum(layer1[l1_hash % self.size1])
            l2_count_0 = self.l2_bitmapsize -  sum(layer2[l1_hash % self.size2])
            l3_count_0 = self.l3_bitmapsize -  sum(layer3[l1_hash % self.size3])
            l4_count_0 = self.l4_bitmapsize -  sum(layer4[l1_hash % self.size4])
            l5_count_0 = self.l5_bitmapsize -  sum(layer5[l1_hash % self.size5])
    
            l1_est = lc(l1_count_0, self.l1_bitmapsize)
            l2_est = lc(l2_count_0, self.l2_bitmapsize)
            l3_est = lc(l3_count_0, self.l3_bitmapsize)
            l4_est = lc(l4_count_0, self.l4_bitmapsize)
            l5_est = lc(l5_count_0, self.l5_bitmapsize)

            est1 = l1_est + l2_est + l3_est + l4_est + l5_est 
            est2 = max(l1_est * 65536/(65536 - self.sample1),1)
            est_layer1 = min(est1,est2)

            est1 = l2_est + l3_est + l4_est + l5_est 
            est2 = l2_est * 65536/(65536 - self.sample2) * (65536/self.sample1)
            est1 *= (65536/self.sample1)
            est_layer2 = min(est1,est2)

            est1 = l3_est + l4_est + l5_est  
            est2 = l3_est * 65536/(65536 - self.sample3) * (65536/self.sample2)
            est1 *= (65536/self.sample2)
            est_layer3 = min(est1,est2)

            est1 = l4_est + l5_est 
            est2 = l4_est * 65536/(65536 - self.sample4) * (65536/self.sample3)
            est1 *= (65536/self.sample3)
            est_layer4 = min(est1,est2)

        
            if l1_count_0 > self.l1_bitmapsize/5:
                Est = est_layer1#max(1,min(est1,est2))
            elif l2_count_0 > self.l2_bitmapsize/5:
                Est = max(est_layer1,est_layer2)
            elif l3_count_0 > self.l3_bitmapsize/5:
                Est = max(est_layer2,est_layer3)
            elif l4_count_0 > self.l4_bitmapsize/5:
                Est = max(est_layer3,est_layer4)
            else:
                Est = max(l5_est* (65536/self.sample4),est_layer4)

            c = self.counter['s01'][l1_hash % self.size1]
            if(c<1000):
                continue
            ip = int_to_ip(self.hh_dip[hh_id])
            print(f"{ip},{c},{Est}")
            logging.info(f"{ip},{c},{Est}")

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            #print(self.topo.get_p4switches())
            thrift_port = self.topo.get_thrift_port(p4switch)
            print ("p4switch:", p4switch, "thrift_port:", thrift_port)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port) 
            if (len(p4switch)>=4):
                continue

    def test (self): #for timeing and change T
        self.counter_query(20)


if __name__ == "__main__":
    controller = myController()
    logging.basicConfig(filename='example.log',level=logging.DEBUG) 
    logging.info('start')
    #controller.heavyhitter_only()
    controller.collect_merge()
    controller.query()
    controller.entropy()
