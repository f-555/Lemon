/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define HASH_THRESHOLD 1288490189  //threshold=0.3 for kmv hash，Replace floating with integer in the range 0 to 4294967295 （32 bits）
#define BLOOM_SIZE 65536
#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

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
    bit<8>     protocol;
    bit<8>     kmvflag;
    bit<32>  khash;
    bit<32>  counter;
    bit<16>  epoch;
}


struct headers {
    ethernet_t   ethernet;
    ipv4_t        ipv4;
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


    action routehash(in bit<32> ipv4_src, in bit<32> ipv4_dst, in bit<16> srcport, in bit<16> dstport, in bit<8> protocol, out bit<32> rhash) {
        hash(rhash, HashAlgorithm.crc16, 32w00000000, {ipv4_src, ipv4_dst,srcport,dstport,protocol}, 32w12);
    }
    
    action forward(in bit<32> rhash){
       bit<9> finalport = 1;
       finalport=rhash[8:0] +1;
       if( finalport >= 12) 
           finalport = 12;
       if( finalport < 1) 
           finalport = 1;
       if(standard_metadata.ingress_port != 14) {
           finalport = 0;
       }
       standard_metadata.egress_spec = finalport;
    }

    apply {
        bit<32> rhash=1;
        if (hdr.tcp.isValid()) {
            routehash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.src_port, hdr.tcp.dst_port,hdr.ipv4.protocol, rhash);
            forward(rhash);
        }
        else if (hdr.udp.isValid()) {
            routehash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.src_port, hdr.udp.dst_port,hdr.ipv4.protocol, rhash);
            forward(rhash);
        }else{
            standard_metadata.egress_spec = 0;
        }
       //standard_metadata.egress_spec = 1;
       if(standard_metadata.ingress_port != 14) {
           standard_metadata.egress_spec = 0;
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
