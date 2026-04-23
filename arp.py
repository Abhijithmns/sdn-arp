"""
arp_controller.py — ARP Handling in SDN Networks (Ryu / OpenFlow 1.3)
UE24CS252B - Computer Networks Assignment

Fixes over original:
  1. Installs unicast flow rules after learning (so future traffic bypasses controller)
  2. Per-datapath mac_to_port and arp_table (multi-switch safe)
  3. Skips LLDP and IPv6 multicast frames
  4. Proper flow installation for both directions after ARP resolution

Run:
    ryu-manager arp_controller.py
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp
from ryu.lib.packet import ether_types


class ARPController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ARPController, self).__init__(*args, **kwargs)

        # { dpid -> { mac -> port } }
        self.mac_to_port = {}

        # { dpid -> { ip -> mac } }  — per-switch ARP table (multi-switch safe)
        self.arp_table = {}

    # ------------------------------------------------------------------ #
    #  On switch connect: install table-miss rule (send unknown to ctrl)
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        # Table-miss: match everything, priority 0, send to controller
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions,
                      idle_timeout=0, hard_timeout=0)

        self.logger.info("Switch connected: dpid=%s — table-miss rule installed", datapath.id)

    # ------------------------------------------------------------------ #
    #  Helper: install a flow rule
    # ------------------------------------------------------------------ #
    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=30, hard_timeout=120):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)

    # ------------------------------------------------------------------ #
    #  Helper: send a packet out a specific port
    # ------------------------------------------------------------------ #
    def send_packet(self, datapath, in_port, actions, data):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    # ------------------------------------------------------------------ #
    #  Helper: build and send an ARP reply
    # ------------------------------------------------------------------ #
    def send_arp_reply(self, datapath, src_mac, src_ip,
                       dst_mac, dst_ip, out_port):
        pkt = packet.Packet()

        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=dst_mac,
            src=src_mac
        ))

        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac=dst_mac,
            dst_ip=dst_ip
        ))

        pkt.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        self.send_packet(datapath, datapath.ofproto.OFPP_CONTROLLER,
                         actions, pkt.data)

        self.logger.info("Proxy ARP Reply: %s is-at %s → sent to port %d",
                         src_ip, src_mac, out_port)

    # ------------------------------------------------------------------ #
    #  Main event: PacketIn
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        dpid     = datapath.id
        in_port  = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        # Skip LLDP and IPv6 multicast — not relevant to our project
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth.dst.startswith('33:33'):
            return

        src_mac = eth.src
        dst_mac = eth.dst

        # Initialise per-switch tables
        self.mac_to_port.setdefault(dpid, {})
        self.arp_table.setdefault(dpid, {})

        # ---- Learn MAC → port ----
        if src_mac not in self.mac_to_port[dpid]:
            self.logger.info("Learned MAC: %s on port %d (dpid=%s)",
                             src_mac, in_port, dpid)
        self.mac_to_port[dpid][src_mac] = in_port

        # ================================================================
        #  ARP HANDLING
        # ================================================================
        arp_pkt = pkt.get_protocol(arp.arp)

        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

            self.logger.info("ARP %s: %s (%s) → %s",
                             "REQUEST" if arp_pkt.opcode == arp.ARP_REQUEST else "REPLY",
                             src_ip, src_mac, dst_ip)

            # Learn IP → MAC from any ARP packet
            if src_ip not in self.arp_table[dpid]:
                self.logger.info("ARP Table: Discovered %s → %s", src_ip, src_mac)
            self.arp_table[dpid][src_ip] = src_mac

            if arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table[dpid]:
                    # --- Proxy ARP: we know the answer, reply directly ---
                    reply_mac = self.arp_table[dpid][dst_ip]
                    self.send_arp_reply(
                        datapath,
                        src_mac=reply_mac,
                        src_ip=dst_ip,
                        dst_mac=src_mac,
                        dst_ip=src_ip,
                        out_port=in_port
                    )

                    # ✅ FIX: Install flow rules in BOTH directions now that
                    #         we know both MACs and their ports
                    dst_port = self.mac_to_port[dpid].get(reply_mac)
                    if dst_port:
                        # src → dst
                        match_fwd = parser.OFPMatch(in_port=in_port,
                                                    eth_src=src_mac,
                                                    eth_dst=reply_mac)
                        actions_fwd = [parser.OFPActionOutput(dst_port)]
                        self.add_flow(datapath, priority=10,
                                      match=match_fwd, actions=actions_fwd)

                        # dst → src
                        match_rev = parser.OFPMatch(in_port=dst_port,
                                                    eth_src=reply_mac,
                                                    eth_dst=src_mac)
                        actions_rev = [parser.OFPActionOutput(in_port)]
                        self.add_flow(datapath, priority=10,
                                      match=match_rev, actions=actions_rev)

                        self.logger.info(
                            "Flow installed: %s <-> %s (ports %d <-> %d)",
                            src_mac, reply_mac, in_port, dst_port
                        )
                else:
                    # Unknown target — flood the ARP request
                    self.logger.info("ARP target %s unknown — flooding", dst_ip)
                    actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                    self.send_packet(datapath, in_port, actions, msg.data)

            elif arp_pkt.opcode == arp.ARP_REPLY:
                # Forward reply to the original requester
                dst_port = self.mac_to_port[dpid].get(dst_mac)
                if dst_port:
                    actions = [parser.OFPActionOutput(dst_port)]
                else:
                    actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                self.send_packet(datapath, in_port, actions, msg.data)

            return

        # ================================================================
        #  NORMAL IP FORWARDING (non-ARP)
        # ================================================================
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]

            # ✅ FIX: Install flow rule so future packets bypass controller
            match = parser.OFPMatch(in_port=in_port,
                                    eth_src=src_mac,
                                    eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, priority=10, match=match, actions=actions)

        else:
            out_port = ofproto.OFPP_FLOOD
            actions  = [parser.OFPActionOutput(out_port)]

        self.send_packet(datapath, in_port, actions, msg.data)
