/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_VPLS = 0x100;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> tunnel_id_t;
typedef bit<32> pw_id_t;
typedef bit<14> ecmp_group_id_t;
typedef bit<14> ecmp_hash_t;
const bit<8> MAC_LEARN = 0x1;
const bit<8> VPLS_LEARN = 0x2;


header ethernet_t { 
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header cpu_t{   
    bit<48> srcAddr; 
    bit<16> ingress_port; 
    bit<8> learnType; 
    tunnel_id_t tunnel_id; 
    pw_id_t pw_id; 
}

header vpls_t{
    tunnel_id_t tunnel_id;
    pw_id_t     pw_id;
}
header rtt_t{
    bit<16> pw_id;
    bit<32> ip_src;
    bit<32> ip_dst;
    bit<48> rtt;
}

struct metadata {
    bit<8> is_ingress_border;
    bit<8> is_egress_border;
    ecmp_group_id_t ecmp_group_id;
    ecmp_hash_t ecmp_hash;
    bit<16> ingress_port;
    bit<8> learnType;
    vpls_t  vpls;
}

struct headers {
    ethernet_t   ethernet;
    vpls_t       vpls;
    ethernet_t   in_ethernet;
    ipv4_t 		 ipv4; 
    tcp_t        tcp;
    cpu_t        cpu;
    rtt_t        rtt;
}

