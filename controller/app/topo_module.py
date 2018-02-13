import networkx
import logging
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.controller.handler import set_ev_cls
from ryu.topology.api import get_all_switch, get_all_host

LOG = logging.getLogger(__name__)


class TopoModule(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(TopoModule, self).__init__(*args, **kwargs)
        self.name = "TopoModule"
        self.ipv4_to_host = {} # ip -> host
        self.mac_to_host = {} # mac -> host
        self.datapaths = {}
        self.graph=networkx.DiGraph()

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        link = ev.link
        src = link.src.dpid
        dst = link.dst.dpid
        
        if not self.graph.has_node(src):
            self.graph.add_node(src)
        if not self.graph.has_node(dst):
            self.graph.add_node(dst)
        self.graph.add_edge(src, dst, src_port=link.src.port_no, dst_port=link.dst.port_no)
        LOG.debug('link added. src=%d, dst=%d, src_port=%d, dst_port=%d', src, dst, link.src.port_no, link.dst.port_no)

    @set_ev_cls(event.EventLinkDelete)
    def link_del_handler(self, ev):
        link = ev.link
        src = link.src.dpid
        dst = link.dst.dpid
        if self.graph.has_edge(src,dst):
            self.graph.remove_edge(src,dst)
        LOG.debug('link deleted. src=%d, dst=%d, src_port=%d, dst_port=%d', src, dst, link.src.port_no, link.dst.port_no)

    def get_all_host(self):
        return get_all_host(self)
    
    def get_all_switch(self):
        return get_all_switch(self)

    @set_ev_cls(event.EventHostAdd)
    def _host_add_handler(self, ev):
        host = ev.host
        mac = host.mac
        ipv4 = host.ipv4
        if mac not in self.mac_to_host:
            self.mac_to_host[mac] = host
        if ipv4 not in self.ipv4_to_host:
            self.ipv4_to_host[ipv4] = host

    @set_ev_cls(event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        switch = ev.switch
        dp = switch.dp
        if dp.id not in self.datapaths:
            self.datapaths[dp.id] = dp
