import sys
import logging

from lib import flow

LOG = logging.getLogger(__name__)

class Path(object):
    """
    Path for the source host to end host
    """
    def __init__(self, graph, nodes):
        self.graph = graph
        self.edges = []
        self.nodes = nodes
        self.source = nodes[0]
        self.target = nodes[-1]
        self.latency = 0
        self.flows = {}
        self.min_rate = sys.maxsize

    def install(self, flow):
        if isinstance(flow,Flow) :
            for i in range(1, len(self.nodes) - 1):
                node = self.nodes[i]
                next_node = self.nodes[i + 1]
                self._install_flow_entry(node, next_node)

    def _install_flow_entry(self, flow, node, next_node):
        cur_edge = self.graph[node][next_node]
        out_port = cur_edge['src_port']
        dp = self._get_dp(flow.app, node)
        if dp:
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            actions = [parser.OFPActionOutput(out_port, ofproto.OFPCML_NO_BUFFER)]
            match = parser.OFPMatch(eth_type = 0x0800, ipv4_dst = flow.dst_ip)
            self.app.add_flow(dp, 2, match, actions)

    def _get_datapaths(self, app, node):
        datapaths = app.topo_module.datapaths
        dp = datapaths[node] 
        return dp



