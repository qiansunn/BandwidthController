from lib import path

class Flow(object):
    def __init__(self, app, src_dpid, dst_dpid, src_ip, dst_ip, src_eth, dst_eth):
        self.src_dpid = src_dpid
        self,dst_dpid = dst_dpid
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_eth = src_eth
        self.dst_eth = dst_eth
        self.path = None

    def set_path(self, path):
        if path:
            self.path = path
            self.path.install(self)
