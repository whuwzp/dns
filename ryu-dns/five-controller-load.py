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

class MDNS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MDNS, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapath = None
        self.flag = 0
        self.reply = {}
        self.time = 0
        self.mum = 0
        self.init_time = time.time()
        self.pros_time = 0
        self.pros_time_count = []

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




            # add flow
        if datapath.id == 6:
            self.datapath = datapath

            # out_port = ofproto.OFPP_FLOOD

            if self.flag == 0:
                actions = [datapath.ofproto_parser.OFPActionOutput(1), datapath.ofproto_parser.OFPActionOutput(2),
                           datapath.ofproto_parser.OFPActionOutput(3), datapath.ofproto_parser.OFPActionOutput(4),
                           datapath.ofproto_parser.OFPActionOutput(5)]
                # actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                data = None
                self.add_flow(datapath, 6, actions)

                actions = [datapath.ofproto_parser.OFPActionOutput(6)]
                self.add_flow(datapath, 1, actions)
                self.add_flow(datapath, 2, actions)
                self.add_flow(datapath, 3, actions)
                self.add_flow(datapath, 4, actions)
                self.add_flow(datapath, 5, actions)

                self.flag = 1

        else:

            if  msg.in_port == 2:


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
                            print "answer ip : "+"{0}.{1}.{2}.{3}".format(ip1, ip2, ip3, ip4)

                            if resp_request_id not in self.reply.keys():
                                self.reply[resp_request_id] = {datapath_id : [ip1 , ip2 , ip3 , ip4]}
                            else:
                                self.reply[resp_request_id][datapath_id] = [ip1 , ip2 , ip3 , ip4]


                        # defualt the dns1 to be attacked
                        if len(self.reply[resp_request_id]) == 5 : #2->3
                            if True:



                                out = datapath.ofproto_parser.OFPPacketOut(
                                    datapath=datapath, buffer_id=msg.buffer_id, in_port=1,
                                    actions=actions, data=data)
                                print "===================================="
                                # to save time
                                # print "final answer : " ,self.reply[resp_request_id][3][0], ".", self.reply[resp_request_id][3][1], ".", self.reply[resp_request_id][3][2], ".", self.reply[resp_request_id][3][3]
                                print "final answer : " + "{0}.{1}.{2}.{3}".format(ip1, ip2, ip3, ip4)
                                print "===================================="
                                datapath.send_msg(out)

                                if self.mum == 0:
                                    self.time = time.time()
                                self.mum += 1
                                if time.time() - self.time >= 1000:
                                    print "====================================================", self.mum

                                    time.sleep(100000)

                        if len(self.reply[resp_request_id]) == 5:
                            self.reply[resp_request_id] = {}





                # out = datapath.ofproto_parser.OFPPacketOut(
                #     datapath=datapath, buffer_id=msg.buffer_id, in_port=1,
                #     actions=actions, data=data)
                # datapath.send_msg(out)

                # print "get it"


