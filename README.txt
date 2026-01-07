##The skeleton code of this project is from IK2217 Advanced networking 2, Communication System program, KTH.


#Main file description:

\projectcode2026-1-1\p4src\include\headers.p4
Define the headers for the parser to parse the headers and extract data.
We define the vpls header to save tunnel information(tunnel id and pw id) and metadata header(the information carried by the packets) 

\projectcode2026-1-1\p4src\include\parsers.p4
Define the parser to parse the headers in sequence. 
Two sequence parser: parse_ethernet-parse_ipv4-parse_tcp and parse_ethernet-parse_vpls-parse_inEthernet-parse_ipv4-parse_tcp
The second sequence is designed for the process of vpls tunnel.

\projectcode2026-1-1\p4src\p4_pipeline.p4
Define the pipeline logic to process the packets in the network.
Define the table-action match in the pipleline logic. We will decribe the logic in details later.

\projectcode2026-1-1\routing-controller.py
The initialization of the routing rules based on the topology and the pipeline and it continues learning and computing routing rules through prcessing new packets. We will decribe this part further later.

\projectcode2026-1-1\log
Record the working process of the whole system. Initialization and working...

\projectcode2026-1-1\pcap
Record the packets information on single swith port.

\projectcode2026-1-1\results
The results of running the test files of all 6 topologies.

\projectcode2026-1-1\0x-xxx-p4app.json
The topology configuration file. The "auto_arp_tables" is false.

\projectcode2026-1-1\0x-xxx-vpls.conf
The host configuration file.

\projectcode2026-1-1\test_topology_0X.sh
The test files for all 6 topologies.

\projectcode2026-1-1\TASK_TEST.txt
The description of how to test the project code and why it fufills the requirement of this project.



#Pipeline logic:

We write the notes about the function of each table-action match in \projectcode2026-1-1\p4src\p4_pipeline.p4.
Here we decribe the pipeline logic of how we process the packets in the network.

The pipeline can be divided into two parts which are Ingress processing and Egress processing. 

Ingress processing:

We take two situations into considerations in the ingress processing. 

First, when the packets arrives at the pe switch from its adjacent host. We name this pe as src peswitch.
The ingress will clone the packets with smac for future broadcast (egress part). It will check if the src peswitch knows how to route the packets. 
If so, it will do the addr_to_label table (add vpls hdr) and decide to ecmp forward (multipaths) or single forward(one shortest path). 
Else, it will check if the dst host is on the same pe switch.
That means the dst peswitch is the src peswitch. It uses the dmac forward to 'dst host' or broadcast to 'dst host'. 
(why is 'dst host' because the dst host may not exit at this src peswitch, maybe at another pe switch)

Second, when the packets have a vpls header. That means the packets have been encapsulated with the vpls header at the src peswitch.
So the packets may be in the tunnel or at the dst peswitch. If it is in the tunnel, it will do the vpls_tbl forward from one hop to next hop.
If it is at the dst peswitch, it will do the vpls_dmac forward (know the dst host) or vpls_dmac_broadcast (unknown).


Egress processing:

We also take two situations into considerations in the egress processing.

First, when the packets are cloned packets. We actually clone the packets at the src peswitch for broadcast into the tunnel and src 'dsthost'(in ingress process)
and at the dst peswitch for broadcast to the 'dst host'. At the src peswitch, we use egress_broadcast_add_vpls to add vpls hdr for cloned packets and broadcast.

Second, at the dst peswitch, we uses the vpls_learn_tbl to clone packets for vpls_dmac_broadcast in the ingress processing.



#Controller logic:

We write some notes about the parameters and processing logic in \projectcode2026-1-1\routing-controller.py.

It mainly includes two parts: the process packet and the process network.

The process network part includes the definition of the tunnel_id and pw_id. pw_id is defined by the type of hosts. tunnel_id is defined by the shortest path
between diff peswitches which have same pw_id host. We record the ports between the src host and the src peswitch with pw_id, 
the ports between the src peswitch and the next hop switch in tunnel in dict. We also classify these ports into diff groups for broadcast or ecmpgroup. 
The peswitch has connected hosts. At the peswitch,  we add the "check_is_ingress_border", "check_is_egress_border" to point out that this is a peswitch.
We add "vpls_tbl" at the hop switch in tunnels to forward packets through the tunnel. At the src peswitch, the "egress_broadcast_add_vpls" is for broadcasting clone packets
from src peswitch to tunnels. The add_mcast_grp is for broadcasting clone packets to the host with same pwid at the src peswitch. 
The "vpls_dmac_broadcast" is used to broadcast clone packets to dst host with same pw_id at the dst peswitch.

The process packet part is used to learn the packets. There are two conditions trigger the learning process. First, the packets arrives the src peswitch from the host. 
The src peswitch will learn the src addr and the input port and write the dmac and vpls_dmac rule in this peswitch. Second, the packets arrives the dst peswitch from the tunnels.
The dst peswitch will learn the src addr and write the rule of "addr_to_label" plus "ecmp_group" (multipaths) or "addr_to_label" (single path) using this src addr as the dst addr.



#The \projectcode2026-1-1\TASK_TEST.txt is a description of how to test the code and explain why it fulfills the requirement of this project.

#The results of running the \projectcode2026-1-1\test_topology_0X.sh testing files of 6 topologies are in this \projectcode2026-1-1\results file.