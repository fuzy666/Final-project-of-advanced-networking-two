/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

const bit<16> L2_LEARN_ETHER_TYPE = 0x1234;
const bit<16> RTT_ETHER_TYPE = 0x5678;
#define CONST_MAX_LABELS 	30
#define CONST_MAX_PORTS     40

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
        // mark_to_drop();
    }


    //set the start of tunnel with the peswitch
    action set_is_ingress_border(){
        meta.is_ingress_border = (bit<8>)1;
    }

    table check_is_ingress_border {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            NoAction;
            set_is_ingress_border;
        }
        default_action = NoAction;
        size = CONST_MAX_PORTS;
    }


    //clone packets formulticast and maclearn the src addr
    action mac_learn() {
        meta.ingress_port = (bit<16>)standard_metadata.ingress_port;
        meta.learnType = MAC_LEARN;
        clone3(CloneType.I2E, 100, meta);
    }

    table smac {
        key = {
            hdr.ethernet.srcAddr: exact;
            standard_metadata.ingress_port: exact;
        }
        actions = {
            mac_learn;
            NoAction;
        }
        size = 256;
        default_action = mac_learn;
    }


    //add vpls header for the packets or clone packets to go through the tunnel at the start peswitch
    action add_vpls_header_set_outport(bit<32> tunnel_tag, bit<32> pw_tag, egressSpec_t port) {
        hdr.vpls.setValid();
        hdr.vpls.tunnel_id = tunnel_tag;
        hdr.vpls.pw_id = pw_tag;
        hdr.in_ethernet.setValid();
        hdr.in_ethernet.srcAddr = hdr.ethernet.srcAddr;
        hdr.in_ethernet.dstAddr = hdr.ethernet.dstAddr;
        hdr.in_ethernet.etherType = hdr.ethernet.etherType;
        hdr.ethernet.etherType = TYPE_VPLS;
        standard_metadata.egress_spec = port;
    }


    //when shortest path is more than one or one
    //compute the ecmp path to route the packets
    action ecmp_group(bit<14> ecmp_group_id, bit<16> num_nhops){
        hash(meta.ecmp_hash,
	    HashAlgorithm.crc16,
	    (bit<1>)0,
	    { hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol},
	    num_nhops);
	    meta.ecmp_group_id = ecmp_group_id;
    }
    

    //when there is only one path only to do the add_vpls_header_set_outport
    //when there is more than one path to do ecmp_group first then do ecmp_group_to_label to do the add_vpls_header_set_outport
    table addr_to_label {
        key = {
            hdr.ethernet.dstAddr: exact;  
            standard_metadata.ingress_port: exact;
        }
        actions = {
            NoAction;
            add_vpls_header_set_outport;
            ecmp_group;
        }
        default_action = NoAction;
        size = CONST_MAX_LABELS;
    }

    table ecmp_group_to_label {
        key = {
            meta.ecmp_group_id:    exact;
            meta.ecmp_hash: exact;
            hdr.ethernet.dstAddr: exact;  
            standard_metadata.ingress_port: exact; 
        }
        actions = {
            drop;
            add_vpls_header_set_outport;
        }
        size = 1024;
    }


    //inner the tunnel switch to forward packets from one hop to next hop
    action vpls_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table vpls_tbl {
        key = {
            hdr.vpls.tunnel_id: exact;
            standard_metadata.ingress_port: exact;
        }
        actions = {
            vpls_forward;
            drop;
        }
        default_action = drop;
        size = CONST_MAX_LABELS;
    }


    //after the tunnel at the dst switch to forward packets to dst host 
    action mac_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table vpls_dmac {
        key = {
            hdr.vpls.tunnel_id : exact;
            hdr.vpls.pw_id : exact;
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            mac_forward;
            drop;
        }
        default_action = drop;
        size = 128;
    }


    //with no need tunnel and pe switch direct connect host
    table dmac{
        key = {
            hdr.ethernet.dstAddr: exact;
            standard_metadata.ingress_port:exact;
        }
        actions = {
            mac_forward;
            NoAction;
        }
        default_action = NoAction;
        size = 128;
    }


    //at the dst switch broadcast to the dst host
    action add_mcast_grpid(bit<16> grpid) {
        standard_metadata.mcast_grp = grpid;
    }

    table vpls_dmac_broadcast{
        actions = {
            add_mcast_grpid;
            NoAction;
        }
        key = {
            hdr.vpls.tunnel_id:   exact;
            hdr.vpls.pw_id:   exact;
        }
        size = 1024;
        default_action = NoAction;
    }

    //at the src switch broadcast to the dst host
    table add_mcast_grp {
        actions = {
            add_mcast_grpid;
            NoAction;
        }
        key = {
            standard_metadata.ingress_port: exact;
        }
        size = 256;
        default_action = NoAction;
    }



    apply {
        check_is_ingress_border.apply();
        if (meta.is_ingress_border == 1) {
            // at src peswitch learn the src host addr and copy packets for broadcast
            smac.apply();
            // check if it is already known how to route packets to dst host
            switch(addr_to_label.apply().action_run){
                ecmp_group:{
                    ecmp_group_to_label.apply(); 
                }
                //if not known first check the host at the src peswitch with dmac or broadcast to the host at the src peswitch
                NoAction: {
                    if (dmac.apply().hit){
                    }
                    else {
                        add_mcast_grp.apply();
                    }                        
                }
            }
        }
        //the vpls header already covered includes the middle sw in the tunnel and the dst peswitch
        else if (hdr.vpls.isValid()) { 
            if (vpls_tbl.apply().hit) {
                //the middle sw in the tunnel to forward packets
            }
            else if (vpls_dmac.apply().hit) {
                //at the dst peswitch with known dst addr to forward packets
            }
            else {
                //at the dst peswitch with unknown dst mac addr to broadcast
                vpls_dmac_broadcast.apply();         
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
    
    action drop_2(){
        // mark_to_drop();
    }
    

    //at the src pe switch add vpls header for the broadcast cpu packet 
    action add_vpls_header(bit<32> tunnel_tag, bit<32> pw_tag) {
        hdr.vpls.setValid();
        hdr.vpls.tunnel_id = tunnel_tag;
        hdr.vpls.pw_id = pw_tag;
        hdr.in_ethernet.setValid();
        hdr.in_ethernet.srcAddr = hdr.ethernet.srcAddr;
        hdr.in_ethernet.dstAddr = hdr.ethernet.dstAddr;
        hdr.in_ethernet.etherType = hdr.ethernet.etherType;
        hdr.ethernet.etherType = TYPE_VPLS;
    }

    table egress_broadcast_add_vpls{
        actions = {
            add_vpls_header;
            NoAction;
        }
        key = {
            standard_metadata.mcast_grp: exact; 
            standard_metadata.egress_rid:   exact;
        }
        size = 1024;
        default_action = NoAction;
    }


    //check if is the dst peswitch to vpls learn 
    action is_egress_border(){
        hdr.ethernet.etherType = hdr.in_ethernet.etherType;
    }

    table check_is_egress_border {
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            NoAction;
            is_egress_border;
        }
        default_action = NoAction;
        size = CONST_MAX_PORTS;
    }


    //at dst peswitch, learn the src mac addr and learn the dst host
    action vpls_learn() {
        meta.ingress_port = (bit<16>)standard_metadata.ingress_port;
        meta.learnType = VPLS_LEARN;
        meta.vpls.tunnel_id = hdr.vpls.tunnel_id;
        meta.vpls.pw_id = hdr.vpls.pw_id;
        clone3(CloneType.E2E, 100, meta);
    }
    
    table vpls_learn_tbl{
        actions = {
            vpls_learn;
            NoAction;
        }
        key = {
            hdr.ethernet.srcAddr: exact;
            hdr.vpls.pw_id: exact;
        }
        size = 1024;
        default_action = vpls_learn;
    }


    apply { 
        if ((standard_metadata.instance_type == 1) || (standard_metadata.instance_type == 2)){
            //at src pe and dst pe for the broadcast cloned meta packet
            // create a cpu header 
            hdr.cpu.setValid();
            hdr.cpu.srcAddr = hdr.ethernet.srcAddr;
            hdr.cpu.ingress_port = (bit<16>)meta.ingress_port;
            hdr.cpu.learnType = meta.learnType;
            hdr.cpu.tunnel_id = meta.vpls.tunnel_id;
            hdr.cpu.pw_id = meta.vpls.pw_id;
            hdr.ethernet.etherType = L2_LEARN_ETHER_TYPE;
            hdr.vpls.setInvalid();
            hdr.tcp.setInvalid();
            hdr.ipv4.setInvalid();
            hdr.in_ethernet.setInvalid();
            truncate((bit<32>)31); //ether+cpu header
        }
        else if (!hdr.vpls.isValid()) {
            //at src peswitch add vpls header for the broadcast cloned meta packet
            egress_broadcast_add_vpls.apply();
        }
        //check if it is an egress dst peswitch
        else {
            if (check_is_egress_border.apply().hit) {
                //at dsr peswitch learn the src host mac addr and learn the dst host
                vpls_learn_tbl.apply();
                hdr.vpls.setInvalid();
                hdr.in_ethernet.setInvalid();
            }
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
               hdr.ipv4.dscp,
               hdr.ipv4.ecn,
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
