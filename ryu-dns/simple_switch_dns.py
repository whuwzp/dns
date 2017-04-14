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

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapath = None
        self.flag = 0
        self.init_time = time.time()

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
        if datapath.id == 1:
            self.datapath = datapath

            if self.flag == 0:
                actions = [datapath.ofproto_parser.OFPActionOutput(1), datapath.ofproto_parser.OFPActionOutput(2), datapath.ofproto_parser.OFPActionOutput(3) ]
                data = None
                self.add_flow(datapath, 4,  actions)

                actions = [datapath.ofproto_parser.OFPActionOutput(4)]
                self.add_flow(datapath, 1, actions)
                self.add_flow(datapath, 2, actions)
                self.add_flow(datapath, 3, actions)

                self.flag = 1


        else:

            if  msg.in_port == 2:
                print "sel.datapath", self.datapath

                datapath = self.datapath

                actions = [datapath.ofproto_parser.OFPActionOutput(4) ]
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                print data,msg.buffer_id

                out = datapath.ofproto_parser.OFPPacketOut(
                        datapath= datapath, buffer_id=msg.buffer_id, in_port=1,
                        actions=actions, data=data)
                datapath.send_msg(out)


                # print "get it"


