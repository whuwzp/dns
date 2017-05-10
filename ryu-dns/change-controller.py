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
import os
import logging

logger = logging.getLogger("MDNS")
logger.setLevel(logging.DEBUG)

fh = logging.FileHandler("logger.log")
fh.setLevel(logging.DEBUG)

ch = logging.StreamHandler()
ch.setLevel(logging.ERROR)

formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
fh.setFormatter(formatter)

logger.addHandler(ch)
logger.addHandler(fh)


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
        self.init_flag = 0
        self.switch_flag = 0
        self.first_change_flag = 0
        self.changed = 0
        self.changed_again = 0
        self.xid = 0
        self.reply = {}
        self.init_time = time.time()
        self.active_list = [1]
        self.to_be_active_list = [1,2,3]
        self.packet_num = 0
        self.after_num = 0
        self.record = []

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
        print "packet num"  ,self.packet_num
        print "packet in from ", msg.in_port
        print "switch_flag" , self.switch_flag
        print "first_packet_flag" , self.first_change_flag
        print "xid" ,self.xid
        print "after_num", self.after_num


        if self.packet_num >= 50 and self.switch_flag == 0:

            if self.changed == 0:
                logger.debug("sudo ")
                os.system('sudo ovs-ofctl add-flow s0 in_port=6,actions=output:controller')
                self.changed = 1
                self.switch_flag = 1

        if self.packet_num >= 100 and self.switch_flag == 0:
            if self.changed_again == 0:
                logger.debug("sudo ")
                os.system('sudo ovs-ofctl add-flow s0 in_port=6,actions=output:controller')
                self.changed_again = 1
                self.switch_flag = 1


        if datapath.id == 6:
            # initial
            if self.init_flag == 0 :
                self.datapath = datapath
                actions = []
                for i in self.active_list:
                    actions.append(datapath.ofproto_parser.OFPActionOutput(i))
                self.add_flow(datapath, 6, actions)
                    #
                    # actions = [datapath.ofproto_parser.OFPActionOutput(6)]
                    # self.add_flow(datapath, i, actions)

                self.init_flag = 1
                print "initial done"
                return
            else:
                if True:

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

                            if resp_request_id != 0:
                                print "###################################"
                                if self.first_change_flag == 0 :
                                    # self.switch_flag = 1
                                    print "first change packet ", datapath.id
                                    self.xid = resp_request_id
                                    print "self.xid",self.xid
                                    self.first_change_flag = 1
                                # new
                                for i in self.to_be_active_list:
                                    actions = [datapath.ofproto_parser.OFPActionOutput(i)]

                                    out = datapath.ofproto_parser.OFPPacketOut(
                                        datapath=datapath, buffer_id=msg.buffer_id, in_port=6,
                                        actions=actions, data=data)
                                    datapath.send_msg(out)
                                # the number sent by the controller
                                self.record.append(resp_request_id)
                                logger.debug("sent bt controller")




        if msg.in_port == 2:
            # response
            datapath_id = datapath.id

            ## hehe
            if self.datapath != None:

                datapath = self.datapath
                actions = [self.datapath.ofproto_parser.OFPActionOutput(6)]

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
                        if  resp_request_id != 0:
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
                            print "len(self.reply[resp_request_id]) == len(self.active_list):", len(
                                self.reply[resp_request_id]), len(self.active_list) , len(self.to_be_active_list)
                            if self.switch_flag == 1 and self.xid == resp_request_id :
                                self.active_list = self.to_be_active_list

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


                                        logger.debug('packet_num:%d, swithing:%d, dns_num:%d, first_packet:%d, sent_by_ctrl:%d', self.packet_num, int(self.switch_flag),
                                                     int(len(self.reply[resp_request_id])),int(
                                                self.xid == resp_request_id),  int(resp_request_id in self.record))
                                        # self.after_num = self.packet_num - 50

                                        self.switch_flag = 0
                                        self.first_change_flag = 0
                                        self.xid = 0


                                        # self.packet_num = 0
                                        self.to_be_active_list = [1,2,3,4,5]



                                        actions = []
                                        for i in self.active_list:
                                            actions.append(datapath.ofproto_parser.OFPActionOutput(i))
                                        self.add_flow(datapath, 6, actions)


                                        return

                            elif self.switch_flag == 1 and self.xid != resp_request_id  :
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

                                        logger.debug(
                                            'packet_num:%d, swithing:%d, dns_num:%d, first_packet:%d, sent_by_ctrl:%d',
                                            self.packet_num, int(self.switch_flag),
                                            int(len(self.reply[resp_request_id])), int(
                                                self.xid == resp_request_id), int(resp_request_id in self.record))

                                        return

                            elif self.switch_flag == 0  :
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

                                        logger.debug(
                                            'packet_num:%d, swithing:%d, dns_num:%d, first_packet:%d, sent_by_ctrl:%d',
                                            self.packet_num, int(self.switch_flag),
                                            int(len(self.reply[resp_request_id])), int(
                                                self.xid == resp_request_id), int(resp_request_id in self.record))

                                        return


