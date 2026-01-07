from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
from multiprocessing import Pool
import threading
import json
import ipaddress

TYPE_MAC_LEARN = 0x1
TYPE_VPLS_LEARN = 0x2

# given host name, return the pw_id
hosts_2_pwid = {}
# 

class CpuHeader(Packet):
    name = 'CpuPacket'
    ### define your own CPU header
#     header cpu_t{ // 17B
#     bit<48> srcAddr; // 6B
#     bit<16> ingress_port; // 2B
#     bit<8> learnType; // 1B
#     tunnel_id_t tunnel_id; // 4B
#     pw_id_t pw_id; // 4B
# }
    fields_desc = [BitField('macAddr',0,48), BitField('ingress_port', 0, 16), BitField('learnType',0,8),
        BitField('tunnel_id', 0, 32), BitField('pw_id', 0, 32)]


class RttHeader(Packet):
    name = 'RttPacket'
    fields_desc = [BitField('customer_id',0,16), BitField('ip_addr_src', 0, 32), BitField('ip_addr_dst', 0, 32), BitField('rtt',0,48)]

class EventBasedController(threading.Thread):
    def __init__(self, params):
        super(EventBasedController, self).__init__()
        self.topo = Topology(db="topology.db")
        self.sw_name = params["sw_name"]
        self.cpu_port_intf = params["cpu_port_intf"]
        self.thrift_port = params["thrift_port"]
        self.id_to_switch = params["id_to_switch"]
        self.controller = SimpleSwitchAPI(thrift_port)
        #port list from srcpe to tunnel with sw and pwid
        self.sw_pw_connectedTunnels = params["sw_pw_connectedTunnels"]
        #port list from srcpe to srchost with sw and pwid
        self.sw_pw_connectedHostPorts = params["sw_pw_connectedHostPorts"]
        #the pwid of the port from srcpe to srchost with sw and pwid
        self.sw_port2pwid = params["sw_port2pwid"]
        # given tunnel id, return the ecmp_group_id and the ecmp_hash tuple
        self.sw_tunnel2ecmp_grpid = params["sw_tunnel2ecmp_grpid"]
        # given the ecmp_group id, returns the corresponding tunnel_id and outport
        self.sw_ecmp_grpid2tunnel_port = params["sw_ecmp_grpid2tunnel_port"]

    def run(self):
        sniff(iface=self.cpu_port_intf, prn=self.recv_msg_cpu)

    def recv_msg_cpu(self, pkt):
        print "received packet at " + str(self.sw_name) + " controller"

        packet = Ether(str(pkt))

        if packet.type == 0x1234:
            cpu_header = CpuHeader(packet.payload)
            ### change None with the list of fields from the CPUHeader that you defined
            self.process_packet([(cpu_header.macAddr, cpu_header.ingress_port, cpu_header.learnType, cpu_header.tunnel_id, cpu_header.pw_id)]) ### change None with the list of fields from the CPUHeader that you defined

        elif packet.type == 0x5678:
            rtt_header = RttHeader(packet.payload)
            self.process_packet_rtt([(rtt_header.customer_id,rtt_header.ip_addr_src,rtt_header.ip_addr_dst,rtt_header.rtt)])

    def process_packet(self, packet_data):
        ### write your learning logic here
        ### use exercise 04-Learning as a reference point

        for mac_addr, ingress_port, learnType, tunnel_id, pw_id in  packet_data:
            print "mac: %012X ingress_port: %s " % (mac_addr, ingress_port)

            # Add an entry to vpls_dmac
            # get the pw_id
            if (learnType == TYPE_MAC_LEARN):
                # Add an entry to smac
                print "type MAC learn at " + str(self.sw_name) + " controller"
                self.controller.table_add("smac", "NoAction", [str(mac_addr), str(ingress_port)])
                # pw_id of the incoming packet
                pw_id_inport = self.sw_port2pwid[ingress_port]
                # learn this srchost as the dst host, packets from tunnel arrive and forward to dst host 
                for tunnel_connected in self.sw_pw_connectedTunnels.get(pw_id_inport,[]):
                    self.controller.table_add("vpls_dmac", "mac_forward",
                            [str(tunnel_connected), str(pw_id_inport), str(mac_addr)], [str(ingress_port)])
                # e.g. topology 1 have no tunnel and direct forward
                for sw_ingress_port in self.sw_pw_connectedHostPorts.get(pw_id,[]):
                    self.controller.table_add("dmac", "mac_forward", [str(mac_addr), str(sw_ingress_port)], [str(ingress_port)])

            elif (learnType == TYPE_VPLS_LEARN):
                # Add an entry to smac
                print "type vpls learn at " + str(self.sw_name) + " controller"
                self.controller.table_add("vpls_learn_tbl", "NoAction", [str(mac_addr), str(pw_id)])
                # possible return [], e.g. topology 6, s5,s6 same customer connected s5                            
                for sw_ingress_port in self.sw_pw_connectedHostPorts.get(pw_id, []):
                    # convention if a group_id is 0 then it means no ecmp, learn how to reach the srchost single path/ecmp paths
                    if (self.sw_tunnel2ecmp_grpid[tunnel_id] == 0):
                        self.controller.table_add("addr_to_label", "MyIngress.add_vpls_header_set_outport", [str(mac_addr), str(sw_ingress_port)],
                            [str(tunnel_id), str(pw_id), str(ingress_port)])
                    else:
                        # ecmp group
                        ecmp_group_id = self.sw_tunnel2ecmp_grpid[tunnel_id]
                        # if not ecmp_group_id in self.registered_ecmp_group:
                        #     # new ecmp group
                        #     self.registered_ecmp_group.add(ecmp_group_id)
                        tunnel_ports = self.sw_ecmp_grpid2tunnel_port[ecmp_group_id]
                        for i, (tunnel_id, port) in enumerate(tunnel_ports):
                            print "table_add at {}:".format(self.sw_name)
                            self.controller.table_add("ecmp_group_to_label", "add_vpls_header_set_outport",
                                [str(ecmp_group_id), str(i), str(mac_addr),str(sw_ingress_port)],
                                [str(tunnel_id), str(pw_id), str(port)])

                        #add forwarding rule
                        print "table_add at {}:".format(self.sw_name)
                        self.controller.table_add("addr_to_label", "ecmp_group", 
                            [str(mac_addr), str(sw_ingress_port)],
                            [str(ecmp_group_id), str(len(tunnel_ports))])                                            

    def process_packet_rtt(self, packet_data):
        for customer_id, ip_addr_src, ip_addr_dst, rtt in packet_data:
            print("Customer_id: " + str(customer_id))
            print("SourceIP: " +  str(ipaddress.IPv4Address(ip_addr_src)))
            print("DestinationIP: " + str(ipaddress.IPv4Address(ip_addr_dst)))
            print("RTT: " + str(rtt))

class RoutingController(object): 

    def __init__(self, vpls_conf_file):

        self.topo = Topology(db="topology.db")
        self.cpu_ports = {x:self.topo.get_cpu_port_index(x) for x in self.topo.get_p4switches().keys()}
        self.controllers = {}
        self.vpls_conf_file = vpls_conf_file
        self.init()

    def init(self):
        self.connect_to_switches()
        self.reset_states()
        self.add_mirror()
        self.extract_customers_information()
        self.switch_to_id = {sw_name:self.get_switch_id(sw_name) for sw_name in self.topo.get_p4switches().keys()}
        self.id_to_switch = {self.get_switch_id(sw_name):sw_name for sw_name in self.topo.get_p4switches().keys()}


    def add_mirror(self):
        for sw_name in self.topo.get_p4switches().keys():
            self.controllers[sw_name].mirroring_add(100, self.cpu_ports[sw_name])    
        
    def extract_customers_information(self):
        with open(self.vpls_conf_file) as json_file:
            self.vpls_conf = json.load(json_file)

    def reset_states(self):
        [controller.reset_state() for controller in self.controllers.values()]

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchAPI(thrift_port)

    def get_switch_id(self, sw_name):
        return "{:02x}".format(self.topo.get_p4switches()[sw_name]["sw_id"])

    def reverseTuple(self, oneTup):
        ''' reverse a tuple '''
        newtuple = oneTup[::-1]
        return newtuple

    def process_network(self):
        ### logic to be executed at the start-up of the topology
        ### hint: compute ECMP paths here
        ### use exercise 08-Simple Routing as a reference

        # switch-based ecmp_group_id, use tuple tunnel_ids as key
        switch_ecmp_groups = {sw_name:{} for sw_name in self.topo.get_p4switches().keys()}
        # construct the pw_id mapping the type of host
        char_2_pwid = {}
        for count, value in enumerate(self.vpls_conf["customers"]):
            char_2_pwid[value] = count

        # host 2 pwid dict
        hosts_2_pwid = {}
        for host in self.vpls_conf["hosts"].keys():
            hosts_2_pwid[host] = char_2_pwid[self.vpls_conf["hosts"][host]]

        # get the PEs
        PEs = set()
        # dictionary key PE switch, value the set of pw_ids it connects to
        sw_pwids = {}
        for key, value in self.vpls_conf["customer_sites"].items():
            PEs = PEs.union(set(value))
            for sw in value:
                if sw not in sw_pwids:
                    sw_pwids[sw] = set(key)
                else:
                    sw_pwids[sw].add(key)
        # path to tunnel_id
        path_2_tunnelId = {}
        total_tunnel_registered = 0

        def __checkPathRegistered(path_tuple):
            ''' check whether a path_tuple is already visited 
            -----
            return: boolean, correct_key

            response{
                'registered' : True,
                'path' : path,
                'tunnel_id' : 1
            }
            ----
            '''

            response = {}

            if path_tuple in path_2_tunnelId:
                response["registered"] = True
                response["path"] = path_tuple
                response["tunnel_id"] = path_2_tunnelId[path_tuple]
            elif self.reverseTuple(tuple(path_tuple)) in path_2_tunnelId:
                response["registered"] = True
                response["path"] = self.reverseTuple(path_tuple)
                response["tunnel_id"] = path_2_tunnelId[self.reverseTuple(path_tuple)]
            else:
                response["registered"] = False
            return response

        # per-switch, given pw_id, returns the tunnel_id related to this pw_id used for multicast
        self.sw_pw_connectedTunnels = {}
        self.sw_pw_connectedHostPorts = {}
        self.sw_port2pwid = {}
        
        # per-switch given tunnel_id, returns the ecmp group id
        self.sw_tunnel2ecmp_grpid = {}
        # per-switch given ecmp_groupid, returns all the tunnel,port tuples assigned to this group
        self.sw_ecmp_grpid2tunnel_port = {}
        for sw_src, controller in self.controllers.items():
            # for sw_dst in self.topo.get_p4switches():
            if (sw_src in PEs):
                # get the host connected to sw_src
                src_hosts = self.topo.get_hosts_connected_to(sw_src)
                # list storing the tunnel_ids and outport port that the sw_src connected to, needed for vpls_dmac
                src_connected_tunnel_ports = []
                # # list storing port that connects to PEs
                # src_hop_ports = []
                # dictionary that stores as key the source pw_id and value array of tuples (tunnel_id, outport)
                # used in multicast group
                pw_id_connectedTunnel_ports = {}
                # dictionary, that stores as key pw_id, value the list of ports that it connected to
                pw_id_ports = {}
                
                # given ingress_port, find the pw_id
                self.sw_pw_connectedTunnels[sw_src] = {}
                self.sw_port2pwid[sw_src] = {}
                self.sw_pw_connectedHostPorts[sw_src] = {}
                self.sw_tunnel2ecmp_grpid[sw_src] = {}
                self.sw_ecmp_grpid2tunnel_port[sw_src] = {}
                for src_host in src_hosts:
                    host_pw_id = hosts_2_pwid[src_host]
                    host_port_num = self.topo.node_to_node_port_num(sw_src, src_host)
                    if not host_pw_id in pw_id_ports:
                        # add new pw_id, save the port num connected to that host
                        pw_id_ports[host_pw_id] = [host_port_num]
                    else:
                        pw_id_ports[host_pw_id].append(host_port_num)

                    self.sw_port2pwid[sw_src][host_port_num] = host_pw_id
                for pw_id, ports in pw_id_ports.items():
                    self.sw_pw_connectedHostPorts[sw_src][pw_id] = ports[:]

                for sw_dst in PEs:
                    #if its ourselves we create direct connections when srcpe is equal to dstpe
                    if sw_src == sw_dst:
                        for host in self.topo.get_hosts_connected_to(sw_src):
                            sw_port = self.topo.node_to_node_port_num(sw_src, host)
                            print "table_add at {}:".format(sw_src)
                            # add check ingress border
                            self.controllers[sw_src].table_add("check_is_ingress_border", "set_is_ingress_border", [str(sw_port)])
                            self.controllers[sw_src].table_add("check_is_egress_border", "is_egress_border", [str(sw_port)])

                    #check if there are directly connected hosts and they have same customers
                    elif sw_pwids[sw_src] & sw_pwids[sw_dst]:
                        # if self.topo.get_hosts_connected_to(sw_dst):
                        paths = self.topo.get_shortest_paths_between_nodes(sw_src, sw_dst)
                        # for the ecmp, register the same-cost path
                        ecmp_tunnel_id_next_hop_ports = []
                        paths_copy = paths[:]
                        for path in paths_copy: # copy because will delete dynamically so use the original copy to make sure for-loop work correctly
                            if (u"sw-cpu" in path):
                                # dunno why, but in topology 6 s1 s5 will lead it to this
                                paths.remove(path)
                                continue
                            response = __checkPathRegistered(path)
                            next_hop = path[1]
                            # register new tunnel
                            if (not response["registered"]):
                                total_tunnel_registered += 1
                                path_2_tunnelId[path] = total_tunnel_registered
                                path_tunnel_id = total_tunnel_registered
                                # also add PE rule
                                for index, hop_sw in enumerate(path):
                                    if (index > 0) and (index < len(path) - 1):
                                        upstream_port = self.topo.node_to_node_port_num(hop_sw, path[index-1])
                                        downstream_port = self.topo.node_to_node_port_num(hop_sw, path[index+1])
                                        
                                        print "table_add at {}:".format(hop_sw)
                                        self.controllers[hop_sw].table_add("vpls_tbl", "vpls_forward",
                                            [str(path_tunnel_id), str(upstream_port)],[str(downstream_port)])
                                        self.controllers[hop_sw].table_add("vpls_tbl", "vpls_forward",
                                            [str(path_tunnel_id), str(downstream_port)],[str(upstream_port)])
                            else:
                                path_tunnel_id = response["tunnel_id"]
                            outport = self.topo.node_to_node_port_num(sw_src, next_hop)
                            ecmp_tunnel_id_next_hop_ports.append((path_tunnel_id, outport))
                            # note that the ecmp_tunnel_id_next_hop_ports is for ecmp,
                            # src_connect... is for vpls_dmac  which registers all tunnels connected to the host
                            # tunnel_id  only registers the equal-cost path
                            src_connected_tunnel_ports.append((path_tunnel_id, outport))
                        
                        #ecmp group configuartion
                        for host in self.topo.get_hosts_connected_to(sw_dst):
                            dest_host_pw_id = hosts_2_pwid[host]
                            for src_host in src_hosts:
                                if (hosts_2_pwid[src_host] == dest_host_pw_id):
                                    for path in paths:
                                        response = __checkPathRegistered(path)
                                        tunnel_id = response["tunnel_id"]
                                        sw_src_egress_port = self.topo.node_to_node_port_num(sw_src, path[1])
                                        if pw_id_connectedTunnel_ports.get(dest_host_pw_id, None) is None:
                                            pw_id_connectedTunnel_ports[dest_host_pw_id] = set([(tunnel_id, sw_src_egress_port)])
                                        else:
                                            pw_id_connectedTunnel_ports[dest_host_pw_id].add((tunnel_id, sw_src_egress_port))
                                        
                                    if len(paths) == 1:
                                        next_hop = paths[0][1]
                                        # to test if there are hosts with the same pw_id
                                        # other wise makes no sense to add a tunnel id for it
                                        # assign 0 to ecmp_group id to indicate it is a single path
                                        self.sw_tunnel2ecmp_grpid[sw_src][tunnel_id] = 0

                                    elif len(paths) > 1:
                                        next_hops = [x[1] for x in paths]    
                                        tunnel_ids = [tunnel_tup[0] for tunnel_tup in ecmp_tunnel_id_next_hop_ports]
                                        #check if the ecmp group already exists. The ecmp group is uniquely defined by set of tunnel_ids
                                        if switch_ecmp_groups[sw_src].get(tuple(tunnel_ids), None):
                                            ecmp_group_id = switch_ecmp_groups[sw_src].get(tuple(tunnel_ids), None)

                                        #new ecmp group for this switch
                                        else:
                                            # new_ecmp_group_id = len(switch_ecmp_groups[sw_src]) + 1
                                            # switch_ecmp_groups[sw_src][tuple(tunnel_ids)] = new_ecmp_group_id
                                            ecmp_group_id = len(switch_ecmp_groups[sw_src]) + 1
                                            switch_ecmp_groups[sw_src][tuple(tunnel_ids)] = ecmp_group_id                                            
                                        for tunnel_id in tunnel_ids:
                                            self.sw_tunnel2ecmp_grpid[sw_src][tunnel_id] = ecmp_group_id
                                        self.sw_ecmp_grpid2tunnel_port[sw_src][ecmp_group_id] = ecmp_tunnel_id_next_hop_ports[:]

                # add multicast group multicast grpid based on the ingress_port
                # mc_grp_id = sw_mcast_grpids.get(sw_src, 1)
                mc_grp_id = 1

                for pw_id, ports in pw_id_ports.items():
                # for host in src_hosts:
                    # possible the dictionary is empty like topology 1, because no paths
                    if pw_id in pw_id_connectedTunnel_ports:
                        current_host_tunnel_ports = pw_id_connectedTunnel_ports[pw_id]
                    else:
                        current_host_tunnel_ports = []
                        
                    for host_port_num in ports:
                        # list of ports that is from the same customer as the current host, and connected to the same switch, in A and not in B
                        local_sw_sameCustomer_ports = list(set(ports).difference(set([host_port_num])))

                        self.controllers[sw_src].mc_mgrp_create(mc_grp_id)

                        #add multicast node group, each port a different rid, add vpls header to the cloned packets and broadcast into the tunnels
                        rid = 0
                        
                        #allports = []
                        #for tunnel_id_port in current_host_tunnel_ports:
                        #    port = tunnel_id_port[1]
                        #    allports.append(port)

                        #handle = self.controllers[sw_src].mc_node_create(rid, allports)
                        #self.controllers[sw_src].mc_node_associate(mc_grp_id, handle)  

                        for tunnel_id_port in current_host_tunnel_ports:
                            tunnel_id = tunnel_id_port[0]
                            port = tunnel_id_port[1]
                            handle = self.controllers[sw_src].mc_node_create(rid, [port])
                            self.controllers[sw_src].mc_node_associate(mc_grp_id, handle)         
                            # mcast_grp_id, egress_rid => tunnel, pw
                            #handle = self.controllers[sw_src].mc_node_create(rid, allports)
                            #self.controllers[sw_src].mc_node_associate(mc_grp_id, handle)  
                            self.controllers[sw_src].table_add("egress_broadcast_add_vpls", "add_vpls_header", 
                                [str(mc_grp_id), str(rid)], [str(tunnel_id), str(pw_id)])
                            rid += 1

                        #at the src peswitch broadcast to the host the src peswitch connected    
                        for port in local_sw_sameCustomer_ports:
                            # simply assign the port to the same multicast group
                            handle = self.controllers[sw_src].mc_node_create(rid, [port])
                            self.controllers[sw_src].mc_node_associate(mc_grp_id, handle)         

                        self.controllers[sw_src].table_add("add_mcast_grp", "add_mcast_grpid", 
                            [str(host_port_num)], [str(mc_grp_id)])
                        
                        mc_grp_id += 1
                        #rid += 1
                        

                # add vpls_dmac_broadcast rule(at the dst peswitch broadcast to the dsthost)
                for pw_id, ports in pw_id_ports.items():
                    # only create multicast group for vpls_dmac if there is actually tunnel connected to it
                    # e.g. topolgoy 1 no need
                    if (len(src_connected_tunnel_ports) > 0):
                        self.controllers[sw_src].mc_mgrp_create(mc_grp_id)
                        handle = self.controllers[sw_src].mc_node_create(rid, ports)
                        self.controllers[sw_src].mc_node_associate(mc_grp_id, handle)
                        # outport in the sense to send the packet out from PE through tunnel
                        # here is actually the ingress_port (because direct to hosts)
                        for (tunnel_id, outport) in src_connected_tunnel_ports:
                            # self.controllers[sw_src].table_add("vpls_dmac_broadcast","add_mcast_grpid", 
                            # [str(tunnel_id), str(pw_id), str(outport)], [str(mc_grp_id)])
                            self.controllers[sw_src].table_add("vpls_dmac_broadcast","add_mcast_grpid", 
                            [str(tunnel_id), str(pw_id)], [str(mc_grp_id)])
                        mc_grp_id += 1

                for pw_id, tunnel_ports in pw_id_connectedTunnel_ports.items():
                    self.sw_pw_connectedTunnels[sw_src][pw_id] = [tunnel_port[0] for tunnel_port in tunnel_ports]

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print "Error: vpls.conf file missing"
        sys.exit()
    vpls_conf_file = sys.argv[1]
    controller = RoutingController(vpls_conf_file)
    controller.process_network()
    thread_list = []
    for sw_name in controller.topo.get_p4switches().keys():
        cpu_port_intf = str(controller.topo.get_cpu_port_intf(sw_name).replace("eth0", "eth1"))
        thrift_port = controller.topo.get_thrift_port(sw_name)
        id_to_switch = controller.id_to_switch
        params ={}
        params["sw_name"] = sw_name
        params["cpu_port_intf"]= cpu_port_intf 
        params["thrift_port"]= thrift_port
        params["id_to_switch"]= id_to_switch
        # added  data structure
        params["sw_pw_connectedTunnels"] = controller.sw_pw_connectedTunnels.get(sw_name,None)
        # given pw_id, get the port which connect to host from this pw_id
        params["sw_pw_connectedHostPorts"] = controller.sw_pw_connectedHostPorts.get(sw_name,None)
        params["sw_port2pwid"] = controller.sw_port2pwid.get(sw_name,None)
        params["sw_tunnel2ecmp_grpid"] = controller.sw_tunnel2ecmp_grpid.get(sw_name,None)
        # given the ecmp_group id, returns the corresponding tunnel_id and outport
        params["sw_ecmp_grpid2tunnel_port"] = controller.sw_ecmp_grpid2tunnel_port.get(sw_name,None)
        thread = EventBasedController(params )
        thread.setName('MyThread ' + str(sw_name))
        thread.daemon = True
        thread_list.append(thread)
        thread.start()
    for thread in thread_list:
        thread.join()
    print ("Thread has finished")
