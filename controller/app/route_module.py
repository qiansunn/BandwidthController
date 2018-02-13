import itertools
import networkx
import time
import re

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.base.app_manager import lookup_service_brick
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, arp, tcp, ether_types

from controller.lib import path, flow

__author__ = 'Qian SUN'

ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ETHERNET = ethernet.ethernet.__name__
ARP = arp.arp.__name__
TCP = tcp.tcp.__name__
RE_PATH = re.compile(r'(\d+)-eth(\d+)')

class RouteModule(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RouteModule, self).__init__(*args, **kwargs)
        self._topo_module = None
        self.mac_to_port = {}
        self.datapaths = {}
        self.arp_table = {}
        self.graph=networkx.DiGraph()
        #self.bandwidth_controller = BandwidthController(self)
        #self.bandwidth_controller.start()
        self.threads.append(hub.spawn(self._preinstall_path))

    @property
    def topo_module(self):
        if not self._topo_module:
            self._topo_module = lookup_service_brick('TopoModule')
        return self._topo_module

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, CONFIG_DISPATCHER)
    def desc_stats_reply_handler(self,ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        msg = ev.msg
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.debug('OFPSwitchFeatures received: '
                          'datapath_id=0x%016x n_buffers=%d '
                          'n_tables=%d auxiliary_id=%d '
                          'capabilities=0x%08x',
                          msg.datapath_id, msg.n_buffers, msg.n_tables,
                          msg.auxiliary_id, msg.capabilities)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst_eth = eth.dst
        src_eth = eth.src
        dpid = datapath.id
        self.logger.info("packet in %s %s %s %s", dpid, src_eth, dst_eth, in_port)
        
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_eth] = in_port
     
        # learn a mac address to avoid FLOOD next time.
        header_list = dict((p.protocol_name, p) for p in pkt.protocols if type(p) != str)
        if ARP in header_list:
            self.arp_table[header_list[ARP].src_ip] = src_eth  # ARP learning
        
        if dst_eth in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_eth]
        else:
            if self.arp_handler(header_list, datapath, in_port):
                # 1:reply or drop;  0: flood
                return None
            else:
                out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if TCP in header_list:
                tcp = pkt.get_protocol(tcp.tcp)
                self.bandwidth_controller.update_bandwidth(ip, tcp, datapath, out_port)
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_eth)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def arp_handler(self, header_list, datapath, in_port):
        if ETHERNET in header_list:
            eth_dst = header_list[ETHERNET].dst
            eth_src = header_list[ETHERNET].src

        if eth_dst == ETHERNET_MULTICAST and ARP in header_list:
            arp_dst_ip = header_list[ARP].dst_ip
            if (datapath.id, eth_src, arp_dst_ip) in self.sw:  # Break the loop
                if self.sw[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=in_port,
                        actions=[], data=None)
                    datapath.send_msg(out)
                    return True
            else:
                self.sw[(datapath.id, eth_src, arp_dst_ip)] = in_port

        if ARP in header_list:
            opcode = header_list[ARP].opcode
            arp_src_ip = header_list[ARP].src_ip
            arp_dst_ip = header_list[ARP].dst_ip
            actions = []
            if opcode == arp.ARP_REQUEST:
                if arp_dst_ip in self.arp_table:  # arp reply
                    actions.append(datapath.ofproto_parser.OFPActionOutput(in_port))
                    ARP_Reply = packet.Packet()
                    ARP_Reply.add_protocol(ethernet.ethernet(
                        ethertype=header_list[ETHERNET].ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    ARP_Reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))
                    ARP_Reply.serialize()
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data=ARP_Reply.data)
                    datapath.send_msg(out)
                    return True
        return False

    #def install_path(self, nodes, src_host, dst_host):

    #def install_path_by_ip(self, nodes, src_ip, dst_ip):
        
    #def install_path_by_mac(self, nodes, src_mac, dst_mac):

    #def processing request from zmq

    def install_path(self, flow, path=None):
        if not path:
            path = self._get_init_path_by_ip(flow)
        if path:
            if flow.path:
                flow.path.flow_remove(flow)
            flow.set_path(path)
        else:
            #TODO:handle if without path
            return

    def _get_init_path_by_ip(self, flow):
        graph = self.topo_module.graph
        nodes = networkx.shortest_path(graph, source=flow.src_dpid, target=flow.dst_dpid)
        return path.Path(graph, nodes)
    
    def create_flow(self, src_host, dst_host):
        return flow.Flow(src_host.dpid, dst_host.dpid, src_host.ipv4, dst_host.ipv4, src_host.mac, dst_host.mac)


    def _preinstall_path(self):
        time.sleep(5)
        host_list = self.topo_module.get_all_host()
        for src_host, dst_host in itertools.combinations(host_list, 2):
            flow = self.create_flow(src_host, dst_host)
            self.install_path(flow)
            flow = self.create_flow(src_host, dst_host)
            self.install_path(flow)
"""
        out_port = 5
        dp = self.datapaths.get(int(core_switch["id"]))
        if dp:
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            actions = [parser.OFPActionOutput(out_port,
                                      ofproto.OFPCML_NO_BUFFER)]
            match = parser.OFPMatch(eth_type = 0x0800 , ipv4_dst = core_switch["ip"])
            #match = parser.OFPMatch(eth_type = (0x0800 | 0x806) , ipv4_dst = core_switch["ip"], eth_dst = core_switch["mac"])
            #match = parser.OFPMatch(ipv4_dst = core_switch["ip"])
            self.add_flow(dp, 2, match, actions)
        print("pre install finished")
    # sink_nodes = [node for node, outdegree in list(self.net.out_degree(self.net.nodes()))]
    #        source_nodes = [node for node, indegree in list(self.net.in_degree(self.net.nodes()))]
    #        for source in source_nodes:
    #            for sink in sink_nodes:
    #                if sink != source:
    #                    for path in nx.all_simple_paths(self.net, source=source, target=sink):
    #        self.logger.debug("List of paths")
    #        self.logger.debug(switch_paths)


"""
"""
    def install_path(self, nodes, src_ip, dst_ip):
        print("Install path start")
        path_array = RE_PATH.findall(path)
        nodes = [int(i[0]) for i in path_array]
        nodes = [src_id] + nodes + [dst_id]
        src_ip = "10.0.0." + str(src_id)
        dst_ip = "10.0.0." + str(dst_id)
        print(str(nodes) + ' ' + src_ip + ' ' + dst_ip)

"""

"""
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        match = msg.match
        dp = msg.datapath
        ofp = dp.ofproto
        #self.bandwidth_controller.delete_bandwidth()
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

        self.logger.debug('OFPFlowRemoved received: '
                          'cookie=%d priority=%d reason=%s table_id=%d '
                          'duration_sec=%d duration_nsec=%d '
                          'idle_timeout=%d hard_timeout=%d '
                          'packet_count=%d byte_count=%d match.fields=%s',
                          msg.cookie, msg.priority, reason, msg.table_id,
                          msg.duration_sec, msg.duration_nsec,
                          msg.idle_timeout, msg.hard_timeout,
                          msg.packet_count, msg.byte_count, msg.match)

    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

"""
