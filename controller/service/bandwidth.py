import logging
import socket
import sqlite3
import struct
import sys
import csv
from ctypes import create_string_buffer
from threading import Thread
import zmq
from zmq.error import ZMQError
import time
#from nanomsg import PAIR, Socket, create_message_buffer
#from nanomsg.wrapper import nn_recv, nn_send
from scapy.utils import checksum
#from nanomsg_wrappers import get_default_for_platform, set_wrapper_choice

__author__ = 'Sun Qian'
__version__  = '0.1'

PACKER_FORMAT = '!BBHHHBBH4s4s'
REQUEST_FORMAT = '!H4s4sHHI'
SOCKET_ADDRESS = 'ipc:///tmp/temodule.ipc'

RECV_BUF_SIZE = 2048
BANDWIDTH_REQUEST = 2
BANDWIDTH_REPLY = 3
BANDWIDTH_DELETE = 4

MIN_PAY = 1000
MAX_PAY = 100000


#class request

class IPDatagram:
    def __init__(self, ip_src_addr=None, ip_dst_addr=None, ip_ver=4, ip_ihl=5, ip_tos=0, ip_id=0, ip_frag_off=0, ip_ttl=255,
                 ip_proto=socket.IPPROTO_RAW, ip_opts=None, data=''):
        self.ip_hdr_cksum = 0
        self.ip_ver = ip_ver
        self.ip_ihl = ip_ihl
        self.ip_tos = ip_tos
        self.ip_tlen = 0
        self.ip_id = ip_id
        self.ip_frag_off = ip_frag_off
        self.ip_ttl = ip_ttl
        self.ip_proto = ip_proto
        self.ip_src_addr = ip_src_addr
        self.ip_dst_addr = ip_dst_addr
        self.ip_opts = ip_opts
        # bandwidth stored in data
        self.data = data
        self.ip_tlen = 4 * self.ip_ihl + len(self.data)

    def __repr__(self):
        data = ":".join("{:02x}".format(c) for c in self.data)
        repr = ('[ver: %d, ihl: %d, tos: %d, tlen: %d, id: %d, ' +
                ' frag_off: %d, ttl: %d, proto: %d' +
                ' src_addr: %s, dst_addr: %s, options: %s, data:%s]') \
            % (self.ip_ver, self.ip_ihl, self.ip_tos, self.ip_tlen,
               self.ip_id, self.ip_frag_off, self.ip_ttl, self.ip_proto,
               socket.inet_ntoa(self.ip_src_addr), socket.inet_ntoa(
                   self.ip_dst_addr),
               'Yes' if self.ip_opts else None, data)

        return repr

    def pack(self):
        ip_hdr_buf = create_string_buffer(struct.calcsize(PACKER_FORMAT))
        ip_ver_ihl = (self.ip_ver << 4) + self.ip_ihl
        self.ip_tlen = struct.calcsize(PACKER_FORMAT) + len(self.data)

        struct.pack_into(PACKER_FORMAT, ip_hdr_buf, 0,
                         ip_ver_ihl, self.ip_tos, self.ip_tlen,
                         self.ip_id, self.ip_frag_off,
                         self.ip_ttl, self.ip_proto,
                         self.ip_hdr_cksum,
                         self.ip_src_addr, self.ip_dst_addr)
        self.ip_hdr_cksum = checksum(ip_hdr_buf.raw)
        struct.pack_into('!H', ip_hdr_buf, struct.calcsize(PACKER_FORMAT[:8]),
                         self.ip_hdr_cksum)
        ip_datagram = ''.join([ip_hdr_buf.raw, ''])
        return ip_datagram

    def unpack(self, ip_datagram):
        # get the basic IP headers without opts field
        ip_hdr_sz = struct.calcsize(PACKER_FORMAT)
        ip_hdr = ip_datagram[0][:ip_hdr_sz]
        hdr_fields = struct.unpack(PACKER_FORMAT, ip_hdr)
        self.ip_tos = hdr_fields[1]
        self.ip_tlen = hdr_fields[2]
        self.ip_id = hdr_fields[3]
        self.ip_frag_off = hdr_fields[4]
        self.ip_ttl = hdr_fields[5]
        self.ip_proto = hdr_fields[6]
        self.ip_src_addr = hdr_fields[8]
        self.ip_dst_addr = hdr_fields[9]
        # dont process the IP opts fields
        ip_ver_ihl = hdr_fields[0]
        self.ip_ver = ip_ver_ihl >> 4
        self.ip_ihl = ip_ver_ihl & 0xF
        self.data = ip_datagram[0][ip_hdr_sz:]


class BandwidthController():
    def __init__(self, app):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.paths = set()
        self.app = app
        try:
            # Can't use the same socket in raw mode
            self.rsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, 253)
            self.ssocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, 254)
            self.ssocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)
            self.rsocket.setblocking(1)
        except socket.error as msg:
            self.logger.error('Socket could not be created. Error Code : ' +
                              str(msg[0]) + ' Message ' + str(msg[1]))
            sys.exit()

        #self.conn = sqlite3.connect('test.db', check_same_thread=False)
        self.conn = sqlite3.connect(':memory:', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('PRAGMA foreign_keys= ON')
        self.zmq_context = zmq.Context()

    def _find_occurences(self, s, ch):
        return [i for i, letter in enumerate(s) if letter == ch] 
   
    def _send_reply(self, data, client_addr):
        request = struct.unpack(REQUEST_FORMAT, data)
        src_ip = socket.inet_ntoa(request[1])
        dst_ip = socket.inet_ntoa(request[2])
        src_port = request[3]
        dst_port = request[4]
        if request[0] == BANDWIDTH_REQUEST:
            data_out = IPDatagram()
            data_out.ip_dst_addr = socket.inet_aton(client_addr)
            #self._display_table('tbl_path')
            self.cursor.execute(
                'SELECT * FROM tbl_flow WHERE src_ip = ? AND dst_ip = ? AND src_port = ? AND dst_port = ?',
                (src_ip, dst_ip, src_port, dst_port))
            alloc_rate = self.cursor.fetchone()[6]
            self.cursor.execute(
                'SELECT * FROM tbl_path WHERE src_ip = ? AND dst_ip = ?',
                (src_ip, dst_ip))
            path_nodes = []
            path_str = ''
            entrys = self.cursor.fetchall()
            for entry in entrys:
                path_nodes.append(entry[0])
                print(entry[3])
                path_nodes.append(len(self._find_occurences(entry[3], ','))*2)
                path_nodes.append(alloc_rate)
            data_out.ip_src_addr = socket.inet_aton('0.0.0.0')
            reply_format = '!H4s4sHHI' + 'I'*len(path_nodes)
            data_out.data = struct.pack(reply_format, BANDWIDTH_REPLY, socket.inet_aton(src_ip), socket.inet_aton(dst_ip), src_port, dst_port, len(entrys), *path_nodes)
            self._display_table('tbl_path')
            self.cursor.execute('SELECT src_ip, dst_ip, alloc_rate FROM tbl_flow')
            entrys = self.cursor.fetchall()
            print(entrys)
            entrys = [(entry[0], entry[1]/1000) for entry in entrys]
            with open('run-0.csv', 'w') as csvfile:
                #for entry in entrys:
                writer = csv.writer(csvfile)
                writer.writerows(entrys)
            try:
                self.ssocket.sendto(data_out.data, (client_addr, 0))
                self.logger.debug('DEBUG: Packet out ' + str(data_out))
            except socket.error as msg:
                self.logger.error(
                    'ERROR: Could not send packet out. Error Code: ' + str(msg[0]) + ' Message ' + str(msg[1]))

    def _process_request(self):
        while True:
            packet = self.rsocket.recvfrom(RECV_BUF_SIZE)
            data_in = IPDatagram()
            data_in.unpack(packet)
            self.logger.debug('DEBUG: Packet in ' + str(data_in))
            # Validate and prepare the bandwidth
            self.update_flow(data_in.data)
            self._send_reply(data_in.data, socket.inet_ntoa(data_in.ip_src_addr))


    def _process_flood(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.bind(('',9000))
        while True:
            data, address = s.recvfrom(RECV_BUF_SIZE)
            self.update_flow(data)
            s.sendto(data, address)

    def _excute_sql(self, sql):
        try:
            self.cursor.execute(sql)
        except sqlite3.Error as e:
            self.logger.error(e)
        finally:
            self.conn.commit()

    def _display_table(self, table_name):
        try:
            self.cursor.execute('SELECT * from %s' % table_name)
            #self.cursor.execute('SELECT * FROM ?;', (table_name,))
        except sqlite3.Error as e:
            self.logger.error(e)
        finally:
            self.conn.commit()
            self.logger.debug(table_name + ' content:')
            self.logger.debug(self.cursor.fetchall())

    def update_flow(self, data):
        request = struct.unpack(REQUEST_FORMAT, data)
        src_ip = socket.inet_ntoa(request[1])
        dst_ip = socket.inet_ntoa(request[2])
        src_port = request[3]
        dst_port = request[4]
        if request[0] == BANDWIDTH_REQUEST:
            willingness = request[5]
            print("willingness" + str(willingness))
            demand_rate = self._process_zmq(src_ip, dst_ip, int(willingness))
            params_check = (src_ip, dst_ip)
            # Check the tbl_flow to find the bandwidth request
            self.cursor.execute('SELECT * FROM tbl_path WHERE src_ip = ? AND dst_ip = ?', params_check)
            entrys = self.cursor.fetchall()
            avail_rate = entrys[0][5]
            path_rate = entrys[0][4]
            path_id = entrys[0][0]
            alloc_rate = 0
            if avail_rate > demand_rate:
                alloc_rate = demand_rate
                avail_rate = avail_rate - demand_rate
            else:
                alloc_rate = path_rate
                avail_rate = 0
            sql_insert = """ INSERT OR IGNORE INTO tbl_flow(src_ip, dst_ip, src_port, dst_port, fk_path_id, alloc_rate, demand_rate) 
                             VALUES(?, ?, ?, ?, ?, ?, ?);
                         """
            sql_update = """ UPDATE tbl_flow SET alloc_rate=?, demand_rate = ?
                             WHERE changes() = 0 and src_ip = ? AND dst_ip = ? AND src_port = ? AND dst_port = ?;
                         """
            params_insert = (src_ip, dst_ip, src_port, dst_port, path_id, alloc_rate, demand_rate)
            # Set 0 as default rate
            params_update = (alloc_rate, demand_rate, src_ip, dst_ip, src_port, dst_port)
            self.update_path(src_ip, dst_ip, [], 0, avail_rate)
            try:
                self.cursor.execute(sql_insert, params_insert)
                self.cursor.execute(sql_update, params_update)
            except sqlite3.Error as e:
                self.logger.error(e)
            finally:
                self.conn.commit()
            # Only use for debug
            #self._display_table('tbl_flow')

        elif request[0] == BANDWIDTH_DELETE:
            self._process_zmq(src_ip, dst_ip, 0)
            params_check = (src_ip, dst_ip, src_port, dst_port)
            self.cursor.execute(
                'SELECT * FROM tbl_flow WHERE src_ip = ? AND dst_ip = ? AND src_port = ? AND dst_port = ?',
                params_check)
            entry = self.cursor.fetchone()
            if entry is not None:
                flow_id = entry[0]
                path_id = entry[5]
                alloc_rate = entry[6]
                sql_delete_flow = """ DELETE FROM tbl_flow WHERE flow_id = ?;
                                    """
                sql_delete_bandwidth = """ DELETE FROM tbl_bandwidth WHERE fk_flow_id = ?;
                                """
                sql_update_path = """ UPDATE tbl_path SET avail_rate = avail_rate + ?
                                 WHERE path_id = ?;
                             """
                try:
                    self.cursor.execute(sql_delete_bandwidth, (flow_id,))
                    self.cursor.execute(sql_delete_flow, (flow_id,))
                    self.cursor.execute(sql_update_path, (alloc_rate, path_id))
                except sqlite3.Error as e:
                    self.logger.error(e)
                finally:
                    self.conn.commit()
                # Only use for debug
                #self._display_table('tbl_flow')
                #self._dispaly_table('tbl_bandwidth')
                #self._display_table('tbl_path')

    def _process_nanomsg(self):
        WRAPPER = get_default_for_platform()
        set_wrapper_choice(WRAPPER)
        msg = create_message_buffer(RECV_BUF_SIZE, 0)
        with Socket(PAIR) as socket:
            socket.bind(SOCKET_ADDRESS)
            while True:
                nbytes = nn_recv(socket.fd, msg, 0)
                print("IPC:", nbytes)
                #if nbytes != 0:


    def _process_zmq(self, src_ip, dst_ip, willingness):
        """ Definition of the request socket.
        It sends requests to the the response socket.
        """
        req_sock = self.zmq_context.socket(zmq.REQ)
        req_sock.connect(SOCKET_ADDRESS)
        fid = 0
        src_id = int(src_ip.split('.')[3])
        dst_id = int(dst_ip.split('.')[3])
        message = str(fid) + '-' + str(src_id-1) + '-' + str(dst_id-1) + '-' + str(max(1000, min(100000, willingness*1000)))
        req_sock.send(message.encode('ascii'))
        print("ZMQ send message:" + message)
        bytes = req_sock.recv()
        reply = bytes.decode("ascii")
        req_sock.close()

        #self.app.install_path(reply, src_id, dst_id)

        #int.from_bytes(b'\x00\x10', byteorder='little')
        #response = struct.unpack('I', bytes)[0]
        self.logger.debug('ZMQ Response: ')
        self.logger.debug(bytes.decode("ascii"))
        return 1


    def update_bandwidth(self, ip, tcp, datapath, out_port):
        sql_insert = """ INSERT OR IGNORE INTO tbl_bandwidth (fk_flow_id, fk_switch_id, port_id, rate)
                         VALUES (
                                (SELECT flow_id FROM tbl_flow WHERE src_ip = ? AND dst_ip = ? AND src_port = ? AND dst_port = ?),
                                (SELECT switch_id FROM tbl_switch WHERE datapath = ? AND port_id = ?),
                                ?,
                                ?);
                     """
        sql_update = """ UPDATE tbl_bandwidth SET rate = ?
                         WHERE fk_flow_id IN ( SELECT flow_id FROM tbl_flow WHERE src_ip = ? AND dst_ip = ? AND src_port = ? AND dst_port = ?) AND
                               fk_switch_id IN (SELECT switch_id FROM tbl_switch WHERE datapath = ? AND port_id = ?)
                     """
        sql_alloc_rate = """ UPDATE tbl_flow SET rate = ?, demand_rate = ?
                             WHERE src_ip = ? AND dst_ip = ? AND src_port = ? AND dst_port = ?
                         """
        out_port_ = datapath.ports.get(out_port)
        remain_speed = out_port_.max_speed - out_port_.curr_speed

        try:
            params_check = (ip.src, ip.dst, tcp.src_port, tcp.dst_port)
            # Check the tbl_flow to find the bandwidth request
            self.cursor.execute(
                'SELECT * FROM tbl_flow WHERE src_ip = ? AND dst_ip = ? AND src_port = ? AND dst_port = ?',
                params_check)
            entrys = self.cursor.fetchall()
            for entry in entrys:
                if entry[6] != 0:
                    rate = min(remain_speed, entry[6])
                    params_alloc_rate = (
                        rate, 0, ip.src, ip.dst, tcp.src_port, tcp.dst_port)
                    thread = Thread(target=self._send_reply,
                                    args=(rate, entry[1],))
                    thread.start()
                    self.cursor.execute(sql_alloc_rate, params_alloc_rate)
                params_insert = (ip.src, ip.dst, tcp.src_port, tcp.dst_port,
                                 datapath.id, out_port, out_port, remain_speed)
                params_update = (remain_speed, ip.src, ip.dst,
                                 tcp.src_port, tcp.dst_port, datapath.id, out_port)
                self.cursor.execute(sql_insert, params_insert)
                self.cursor.execute(sql_update, params_update)
        except sqlite3.Error as e:
            self.logger.error(e)
        finally:
            self.conn.commit()
        #self._display_table('tbl_bandwidth')

    def update_path(self, src_id, dst_id, nodes, path_rate, avail_rate):
        nodes_text = ','.join(str(s) for s in nodes)
        sql_insert = """ INSERT OR IGNORE INTO tbl_path(src_ip, dst_ip, nodes, path_rate, avail_rate) VALUES(?, ?, ?, ?, ?);
                     """
        sql_update = """ UPDATE tbl_path SET avail_rate = ?
                         WHERE src_ip = ? AND dst_ip = ?;
                     """
        params_insert = (src_id, dst_id, nodes_text, path_rate, avail_rate)
        params_update = (avail_rate, src_id, dst_id)
        try:
            self.cursor.execute(sql_insert, params_insert)
            self.cursor.execute(sql_update, params_update)
        except sqlite3.Error as e:
            self.logger.error(e)
        finally:
            self.conn.commit()
        #self._display_table('tbl_path')

    def update_switch(self, id, ports):
        sql_insert = """ INSERT OR IGNORE INTO tbl_switch(datapath, port_id) VALUES(?, ?);
                     """
        sql_update = """ UPDATE tbl_switch SET max_rate = ?, curr_rate = ?
                         WHERE datapath = ? AND port_id = ?;
                     """
        try:
            for key, port in ports.items():
                params_insert = (id, port.port_no)
                params_update = (
                    port.max_speed, port.curr_speed, id, port.port_no)
                self.cursor.execute(sql_insert, params_insert)
                self.cursor.execute(sql_update, params_update)
        except sqlite3.Error as e:
            self.logger.error(e)
        finally:
            self.conn.commit()
        #self._display_table('tbl_switch')



    def start(self):
        sql_create_flow_table = """ CREATE TABLE IF NOT EXISTS tbl_flow(
                                    flow_id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    src_ip VARCHAR NOT NULL,
                                    dst_ip VARCHAR NOT NULL,
                                    src_port INTEGER,
                                    dst_port INTEGER,
                                    fk_path_id INTEGER,
                                    alloc_rate INTEGER,
                                    demand_rate INTEGER, 
                                    UNIQUE (src_ip, dst_ip, src_port, dst_port));
                                """
        sql_create_switch_table = """ CREATE TABLE IF NOT EXISTS tbl_switch(
                                      switch_id INTEGER PRIMARY KEY AUTOINCREMENT,
                                      datapath INTEGER,
                                      port_id INTEGER,
                                      max_rate INTEGER,
                                      curr_rate INTEGER,
                                      UNIQUE (datapath, port_id));
                                  """
        sql_create_bandwidth_table = """ CREATE TABLE IF NOT EXISTS tbl_bandwidth(
                                         fk_flow_id INTEGER,                                     
                                         fk_switch_id INTEGER,
                                         port_id INTEGER,
                                         rate INTEGER,
                                         UNIQUE (fk_flow_id, fk_switch_id));
                                     """
        sql_create_path_table = """ CREATE TABLE IF NOT EXISTS tbl_path(
                                    path_id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    src_ip VARCHAR NOT NULL,
                                    dst_ip VARCHAR NOT NULL,
                                    nodes TEXT,
                                    path_rate INTEGER, 
                                    avail_rate INTEGER,
                                    UNIQUE (src_ip, dst_ip));
                                """
        self._excute_sql(sql_create_path_table)
        self._excute_sql(sql_create_flow_table)
        self._excute_sql(sql_create_switch_table)
        self._excute_sql(sql_create_bandwidth_table)

        # Start new thread for receiving bandwidth request
        try:
            thread_client = Thread(target=self._process_request)
            #thread_stress = Thread(target=self._process_flood)
            #thread_zmq = Thread(target=self._process_zmq)
            # thread_nanomsg = Thread(target=self._process_nanomsg)

            thread_client.daemon = True
            #thread_stress.daemon = True
            #thread_nanomsg.daemon = True
            #thread_zmq.daemon = True

            thread_client.start()
            #thread_stress.start()
            #thread_zmq.start()
            # thread_nanomsg.start()
            self.logger.debug('DEBUG: Bandwidth controller start success')
        except:
            self.logger.error('ERROR: Bandwidth controller start failure')
            sys.exit()
