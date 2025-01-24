/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6
#define HEAVY_T 25

#define Lsize 32w524288 // 8*8192 256 bitmap
#define Lsize_bitmap 32w16 //[7:5][4:0]
#define Lsize_totle 32w8388608 // 16*524288 bitmap [15:3][2:0]
#define Hsize 32w1024 //size of heavy part
#define Hsize_hll 32w32 //
#define Hsize_totle 32w524288 //  32*16*1024 size of heavy part [17:8][7:0]

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> VirtualLAN= 0x8100;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;


header cpu_t {
    bit<32> hash;
    bit<32> hash1;
    bit<32> srcip;
    bit<32> dstip;
    bit<16> srcport;
    bit<16> dstport;
    bit<8> protocol;
    bit<32> counter;
    bit<16> epoch;
    bit <8> outputport;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    tos;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
    bit<48> payload;
}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    bit<12> vid;
    bit<16> type;
}

struct metadata {   
    bit<32>  dstip;
    bit<32>  srcip;
    bit<16>  srcport;
    bit<16>  dstport;
    bit<8>   protocol;
    bit<8>   hllflag;
    bit<32>  khash;
    bit<32>  khash1;
    bit<32>  counter;
    bit<16>  epoch;
}


struct headers {
    ethernet_t   ethernet;
    ipv4_t        ipv4;
    cpu_t         cpu;
    udp_t        udp;
    tcp_t          tcp;
    icmp_t      icmp;
    vlan_tag_h vlan;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
 

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
 
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: ipv4;
            VirtualLAN:vlan;
            default: accept;
        }
    }
 
    state vlan{
        packet.extract(hdr.vlan);
        transition select(hdr.vlan.type){
            TYPE_IPV4: ipv4;
            default: accept;
        }
    }

    state ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            IP_PROTOCOLS_ICMP : parse_icmp;
            default : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

 
/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    register<bit<16>>(Lsize) Light_counter1;
    register<bit<1>>(Lsize_totle) Light_1;


    register<bit<16>>(Hsize_totle) Heavy;
    register<bit<32>>(Hsize) Heavy_sip;
    register<bit<32>>(Hsize) Heavy_dip;
    register<bit<16>>(Hsize) Heavy_sp;
    register<bit<16>>(Hsize) Heavy_dp;
    register<bit<8>>(Hsize) Heavy_prot;
    register<bit<32>>(Hsize) Heavy_lhash1;
    register<bit<32>>(Hsize) Heavy_lhash2;

    register<bit<32>>(1) pkgcounter;
    register<bit<16>>(1) epoch;

    action bloom_hash(in bit<32> ipv4_src, in bit<32> ipv4_dst, in bit<16> srcport, in bit<16> dstport, in bit<8> protocol, in bit<16> checksum, in bit<32> seq_no, in bit<16> hdlen, in bit<48> payload, out bit<32> h1, out bit<32> h2, out bit<32> h3) {
        hash(h1, HashAlgorithm.crc32_custom, 32w0, {ipv4_src, ipv4_dst,srcport,dstport,checksum,seq_no,hdlen,payload}, 32w0x0003ffff);
        hash(h2, HashAlgorithm.crc32_custom, 32w0, {ipv4_src, ipv4_dst,srcport,dstport,checksum,seq_no,hdlen,payload}, 32w0x0003ffff);
        hash(h3, HashAlgorithm.crc32_custom, 32w0, {ipv4_src, ipv4_dst,srcport,dstport,checksum,seq_no,hdlen,payload}, 32w0x0003ffff);
    }
 
    action light_slot_hash1(in bit<32> ipv4_src, in bit<32> ipv4_dst, in bit<16> srcport, in bit<16> dstport, in bit<8> protocol, out bit<32> khash) {
        hash(khash, HashAlgorithm.crc32, 32w0, {ipv4_src, ipv4_dst,srcport,dstport,protocol}, Lsize);
    }
    action light_slot_hash2(in bit<32> ipv4_src, in bit<32> ipv4_dst, in bit<16> srcport, in bit<16> dstport, in bit<8> protocol, out bit<32> khash) {
        hash(khash, HashAlgorithm.identity, 32w0, {ipv4_src, ipv4_dst,srcport,dstport,protocol}, Lsize);
    }
    action bitmap_hash(in bit<32> ipv4_src, in bit<32> ipv4_dst, in bit<16> srcport, in bit<16> dstport, in bit<8> protocol, in bit<16> checksum, in bit<32> seq_no, in bit<16> hdlen, in bit<48> payload,out bit<32> khash) {
        hash(khash, HashAlgorithm.crc32, 32w0, {ipv4_src, ipv4_dst,srcport,dstport,protocol,checksum,seq_no,hdlen,payload}, Lsize_bitmap);
    }

    action heavy_slot_hash(in bit<32> ipv4_src, in bit<32> ipv4_dst, in bit<16> srcport, in bit<16> dstport, in bit<8> protocol, out bit<32> khash) {
        hash(khash, HashAlgorithm.crc32, 32w0, {ipv4_src, ipv4_dst,srcport,dstport,protocol}, Hsize);
    }
    action heavy_slot_armoma_hash(in bit<32> ipv4_src, in bit<32> ipv4_dst, in bit<16> srcport, in bit<16> dstport, in bit<8> protocol, in bit<16> checksum, in bit<32> seq_no, in bit<16> hdlen, in bit<48> payload, out bit<32> khash) {
        hash(khash, HashAlgorithm.crc32, 32w0, {ipv4_src, ipv4_dst,srcport,dstport,protocol,checksum,seq_no,hdlen,payload}, Hsize_hll);
    }
    action hll_hash1(in bit<32> ipv4_src, in bit<32> ipv4_dst, in bit<16> srcport, in bit<16> dstport, in bit<8> protocol, in bit<16> checksum, in bit<32> seq_no, in bit<16> hdlen, in bit<48> payload, out bit<16> khash) {
        hash(khash, HashAlgorithm.crc32_custom, 16w0, {ipv4_src, ipv4_dst,srcport,dstport,protocol,checksum,seq_no,hdlen,payload}, 16w0xffff);
    }
    action hll_hash2(in bit<32> ipv4_src, in bit<32> ipv4_dst, in bit<16> srcport, in bit<16> dstport, in bit<8> protocol, in bit<16> checksum, in bit<32> seq_no, in bit<16> hdlen, in bit<48> payload, out bit<16> khash) {
        hash(khash, HashAlgorithm.crc32_custom, 16w0, {ipv4_src, ipv4_dst,srcport,dstport,protocol,checksum,seq_no,hdlen,payload}, 16w0xffff);
    }


    action routehash(in bit<32> ipv4_src, in bit<32> ipv4_dst, in bit<16> srcport, in bit<16> dstport, in bit<8> protocol, out bit<32> rhash) {
        hash(rhash, HashAlgorithm.crc32, 32w00000000, {ipv4_src, ipv4_dst,srcport,dstport,protocol}, 32w3);
    }

    action forward(in bit<32> rhash){
        bit<9> finalport = 1;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        if(hdr.ipv4.ttl == 0)
            finalport = 10;
        standard_metadata.egress_spec = finalport+1; 
    }

    apply {
        //standard_metadata.egress_spec = 4;
        bit<32> rhash;
        //only if IPV4 the rule is applied. Therefore other packets will not be forwarded.
        if (hdr.ipv4.isValid()){
            meta.srcip=hdr.ipv4.srcAddr;
            meta.dstip=hdr.ipv4.dstAddr;
            meta.protocol=hdr.ipv4.protocol;
        }


        bit<32> h1=0;
        bit<32> h2=0;
        bit<32> h3=0;

	    bit<32> light_slot_h1=0;
        bit<32> bitmap_h=0;

        bit<32> heavy_slot_h=0;
        bit<32> heavy_slot_armoma_h=0;
        bit<16> khash1=0;
        bit<16> khash2=0;

        if (hdr.tcp.isValid()) {
            bloom_hash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.src_port, hdr.tcp.dst_port,hdr.ipv4.protocol, hdr.tcp.checksum,hdr.tcp.seq_no,0,0, h1, h2, h3);
            
            light_slot_hash1(0, hdr.ipv4.dstAddr, 0, 0, 0, light_slot_h1);
            //light_slot_hash2(0, hdr.ipv4.dstAddr, 0, hdr.tcp.dst_port, 0, light_slot_h2);
	        bitmap_hash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.src_port, hdr.tcp.dst_port,hdr.ipv4.protocol, hdr.tcp.checksum,hdr.tcp.seq_no , 0,0 , bitmap_h);
            
            heavy_slot_hash(0, hdr.ipv4.dstAddr, 0, 0, 0, heavy_slot_h);
            heavy_slot_armoma_hash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.src_port, hdr.tcp.dst_port,hdr.ipv4.protocol, hdr.tcp.checksum,hdr.tcp.seq_no,0,0, heavy_slot_armoma_h);
            hll_hash1(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.src_port, hdr.tcp.dst_port,hdr.ipv4.protocol, hdr.tcp.checksum,hdr.tcp.seq_no,0,0, khash1);
            hll_hash2(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.src_port, hdr.tcp.dst_port,hdr.ipv4.protocol, hdr.tcp.checksum,hdr.tcp.seq_no,0,0, khash2);
            routehash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.src_port, hdr.tcp.dst_port,hdr.ipv4.protocol, rhash);

	        khash1[7:4]=khash2[7:4];
            forward(rhash);
        }
        else if (hdr.udp.isValid()) {
            bloom_hash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.src_port, hdr.udp.dst_port,hdr.ipv4.protocol, hdr.udp.checksum, 0,hdr.udp.hdr_length,hdr.udp.payload,h1, h2, h3);
            
            light_slot_hash1(0, hdr.ipv4.dstAddr, 0, 0, 0, light_slot_h1);
            //light_slot_hash2(0, hdr.ipv4.dstAddr, 0, hdr.udp.dst_port, 0, light_slot_h2);
	        bitmap_hash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.src_port, hdr.udp.dst_port, hdr.ipv4.protocol, hdr.udp.checksum, 0,hdr.udp.hdr_length,hdr.udp.payload, bitmap_h);
            
            heavy_slot_hash(0, hdr.ipv4.dstAddr, 0, 0, 0, heavy_slot_h);
            heavy_slot_armoma_hash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.src_port, hdr.udp.dst_port, hdr.ipv4.protocol, hdr.udp.checksum, 0,hdr.udp.hdr_length,hdr.udp.payload, heavy_slot_armoma_h);
            hll_hash1(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.src_port, hdr.udp.dst_port,hdr.ipv4.protocol, hdr.udp.checksum, 0,hdr.udp.hdr_length,hdr.udp.payload, khash1);
            hll_hash2(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.src_port, hdr.udp.dst_port,hdr.ipv4.protocol, hdr.udp.checksum, 0,hdr.udp.hdr_length,hdr.udp.payload, khash2);
            routehash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.src_port, hdr.udp.dst_port,hdr.ipv4.protocol, rhash);

	        khash1[7:4]=khash2[7:4];
            forward(rhash);
        }else{
            standard_metadata.egress_spec =0;
        }


        bit<16> counternow1 = 0;
        bit<16> counternow2 = 0;
        bit<16> heavy_flag = 0;
        Light_counter1.read(counternow1,light_slot_h1);
        counternow1 = counternow1 +1;
        Light_counter1.write(light_slot_h1,counternow1);
        
        if(counternow1 >= HEAVY_T) 
            heavy_flag = 1;

        if(heavy_flag == 0){
            bit<32> l_index = 0;
            bit<32> bitmap1 = 0;
            bit<8> roll = 0; //for bitmap
            l_index[22:4] = light_slot_h1[18:0];
            l_index[3:0] = bitmap_h[3:0];
            Light_1.write(l_index,1);
        }

        bit<16> hashnow;
        bit<32> h_index;
        h_index[14:5]=heavy_slot_h[9:0];
        h_index[4:0]=heavy_slot_armoma_h[4:0];
        if(heavy_flag == 1){
            Heavy.read(hashnow,h_index);
            if((hashnow > khash1 || hashnow==0)){
                Heavy.write(h_index,khash1);
            }
            Heavy_sip.write(heavy_slot_h,hdr.ipv4.srcAddr);
            Heavy_dip.write(heavy_slot_h,hdr.ipv4.dstAddr);
            Heavy_prot.write(heavy_slot_h,hdr.ipv4.protocol);
            Heavy_lhash1.write(heavy_slot_h, light_slot_h1);
            if(hdr.tcp.isValid()){
                Heavy_sp.write(heavy_slot_h,hdr.tcp.src_port);        
                Heavy_dp.write(heavy_slot_h,hdr.tcp.dst_port);                           
            }
            if(hdr.udp.isValid()){
                Heavy_sp.write(heavy_slot_h,hdr.udp.src_port);        
                Heavy_dp.write(heavy_slot_h,hdr.udp.dst_port);               
            }
        }
    }
}

 

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
     //handle the cloned packet   meta.hllflag   standard_metadata.instance_type != 0
     if (standard_metadata.instance_type != 0){
        hdr.ethernet.etherType =0x1234;       
        hdr.cpu.setValid();                                       
        hdr.vlan.setInvalid();                                       
        hdr.cpu.hash = meta.khash;
        hdr.cpu.hash1 = meta.khash1;
        hdr.cpu.srcip = meta.srcip;  
        hdr.cpu.dstip = meta.dstip;
        hdr.cpu.srcport = meta.srcport;
        hdr.cpu.dstport = meta.dstport;
        hdr.cpu.protocol = meta.protocol;
        hdr.cpu.counter = meta.counter;
        hdr.cpu.epoch= meta.epoch;
        hdr.cpu.outputport = standard_metadata.egress_spec[7:0];
     }
    }

}
 

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.tos,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

 
/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);    
        packet.emit(hdr.vlan);    
        packet.emit(hdr.cpu);   
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
    }
}


/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
