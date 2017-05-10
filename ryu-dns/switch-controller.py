# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""
import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
import socket
import struct
import random
import threading

### scheduler
# active_list = []
# to_be_actvie_list = []
#
#
#
# class scheduler(threading.Thread):
#     def __init__(self):
#         threading.Thread.__init__(self)
#         self.init_time = time.time()
#
#     def run(self):
#         if time.time() - self.init_time >= 5:
#             for i in range(random.randint(1,5)):
#                 a = random.randint(1,5)
#                 if a not in to_be_actvie_list:
#                     to_be_actvie_list.append(random.randint(a))
#
#
# if __name__ == "__main__":
#     for thread in range(0, 5):
#         t = scheduler()
#         t.start()


class MDNS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MDNS, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapath = None
        self.flag = 0
        self.switch_flag = 0
        self.first_change_flag = 0
        self.xid = 0
        self.reply = {}
        self.init_time = time.time()
        self.active_list = [1]
        self.to_be_active_list = []
        self.packet_num = 0

    def packet_in_initial(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        self.datapath = datapath
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        for i in self.active_list:
            actions = [datapath.ofproto_parser.OFPActionOutput(i)]
            # actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            data = None
            self.add_flow(datapath, 6, actions)

            actions = [datapath.ofproto_parser.OFPActionOutput(6)]
            self.add_flow(datapath, i, actions)
        self.flag = 1

    def packet_in_normal(self,ev):
        print "normal"
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if msg.in_port == 2:

            datapath_id = datapath.id

            ## hehe
            datapath = self.datapath
            actions = [datapath.ofproto_parser.OFPActionOutput(6)]

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            if data != None:
                resp_data = data[42:]
                if len(resp_data) >= 12:
                    (resp_request_id, resp_flag, resp_qdcount, resp_ancount, resp_nscount,
                     resp_arcount) = struct.unpack(
                        "!HHHHHH",
                        resp_data[:12])
                    print "-----------------------------"
                    print "response from dns : ", datapath_id
                    print "transaction_id : ", resp_request_id
                    # DNS header = 12
                    record = resp_data[12:]
                    # 3www.6whuwzp.2cn0(11+4) + 2 + 2 = 19 -> www.example.com 21
                    record = record[21:]
                    if len(record) >= struct.calcsize("!HHHLHBBBB"):
                        (offset, type, rdclass, ttl, rdlen, ip1, ip2, ip3, ip4) = struct.unpack("!HHHLHBBBB",
                                                                                                record[
                                                                                                :struct.calcsize(
                                                                                                    "!HHHLHBBBB")])
                        print "answer ip : " + "{0}.{1}.{2}.{3}".format(ip1, ip2, ip3, ip4)

                        if resp_request_id not in self.reply.keys():
                            self.reply[resp_request_id] = {datapath_id: [ip1, ip2, ip3, ip4]}
                        else:
                            self.reply[resp_request_id][datapath_id] = [ip1, ip2, ip3, ip4]

                    # defualt the dns1 to be attacked
                    print "len(self.reply[resp_request_id]) == len(self.active_list):" ,len(self.reply[resp_request_id]),len(self.active_list)
                    if len(self.reply[resp_request_id]) == len(self.active_list):
                        if True:
                            out = datapath.ofproto_parser.OFPPacketOut(
                                datapath=datapath, buffer_id=msg.buffer_id, in_port=1,
                                actions=actions, data=data)
                            print "===================================="
                            print "final answer : " + "{0}.{1}.{2}.{3}".format(ip1, ip2, ip3, ip4)
                            print "===================================="
                            datapath.send_msg(out)

                            self.packet_num += 1


    def packet_in_changing(self,ev):
        print "changing"
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        # from 1,2,3,4,5, to decide
        if msg.in_port == 2:

            datapath_id = datapath.id

            ## hehe
            datapath = self.datapath
            actions = [datapath.ofproto_parser.OFPActionOutput(6)]

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            if data != None:
                resp_data = data[42:]
                if len(resp_data) >= 12:
                    (resp_request_id, resp_flag, resp_qdcount, resp_ancount, resp_nscount,
                     resp_arcount) = struct.unpack(
                        "!HHHHHH",
                        resp_data[:12])
                    print "-----------------------------"
                    print "response from dns : ", datapath_id
                    print "transaction_id : ", resp_request_id

                    if resp_request_id == self.xid:
                        self.switch_flag = 0
                        self.init_time = time.time()
                        self.active_list = self.to_be_active_list
                        self.first_change_flag = 0

                    # DNS header = 12
                    record = resp_data[12:]
                    # 3www.6whuwzp.2cn0(11+4) + 2 + 2 = 19 -> www.example.com 21
                    record = record[21:]
                    if len(record) >= struct.calcsize("!HHHLHBBBB"):
                        (offset, type, rdclass, ttl, rdlen, ip1, ip2, ip3, ip4) = struct.unpack("!HHHLHBBBB",
                                                                                                record[
                                                                                                :struct.calcsize(
                                                                                                    "!HHHLHBBBB")])
                        print "answer ip : " + "{0}.{1}.{2}.{3}".format(ip1, ip2, ip3, ip4)

                        if resp_request_id not in self.reply.keys():
                            self.reply[resp_request_id] = {datapath_id: [ip1, ip2, ip3, ip4]}
                        else:
                            self.reply[resp_request_id][datapath_id] = [ip1, ip2, ip3, ip4]

                    # defualt the dns1 to be attacked
                    if len(self.reply[resp_request_id]) == len(self.active_list):
                        if True:
                            out = datapath.ofproto_parser.OFPPacketOut(
                                datapath=datapath, buffer_id=msg.buffer_id, in_port=1,
                                actions=actions, data=data)
                            print "===================================="
                            print "final answer : " + "{0}.{1}.{2}.{3}".format(ip1, ip2, ip3, ip4)
                            print "===================================="
                            datapath.send_msg(out)
                            self.packet_num += 1






        # from 6, to distrubute

        if msg.in_port == 6:

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            if self.first_change_flag == 0:
                print "*******************************"
                if data != None:
                    resp_data = data[42:]
                    if len(resp_data) >= 12:
                        (resp_request_id, resp_flag, resp_qdcount, resp_ancount, resp_nscount,
                         resp_arcount) = struct.unpack(
                            "!HHHHHH",
                            resp_data[:12])
                        print "**********************"
                        print "transaction_id : ", resp_request_id

                        # record the xid
                        self.xid = resp_request_id

                        self.first_change_flag = 1



            for i in self.to_be_active_list:
                actions = [datapath.ofproto_parser.OFPActionOutput(i)]

                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=6,
                    actions=actions, data=data)
                datapath.send_msg(out)



    def add_flow(self, datapath, in_port,  actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port)

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        print "packet in  from dns : ", datapath.id

        if self.packet_num >= 50:

            self.switch_flag = 1
            actions = [self.datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            self.add_flow(datapath, 6, actions)


        # initial
        if datapath.id == 6:
            if self.flag == 0:
                self.packet_in_initial(ev)
                self.flag = 1





        if self.switch_flag == 1:
            self.packet_in_changing(ev)

        else:
            if msg.in_port == 2:
                # normal
                self.packet_in_normal(ev)


