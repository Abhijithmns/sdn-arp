from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import EthAddr

log = core.getLogger()


class ARPController(object):

    def __init__(self):
        core.openflow.addListeners(self)

        # Tables
        self.arp_table = {}   # IP -> MAC
        self.mac_to_port = {}  # MAC -> port (per switch)

    def _handle_ConnectionUp(self, event):
        log.info("Switch connected: %s", event.connection)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        dpid = event.connection.dpid
        in_port = event.port

        # Initialize switch table
        self.mac_to_port.setdefault(dpid, {})

        # Learn MAC → port
        self.mac_to_port[dpid][packet.src] = in_port

        if packet.type == ethernet.ARP_TYPE:
            self.handle_arp(event, packet)
        else:
            self.handle_ip(event, packet)

    # ---------------- ARP HANDLING ---------------- #

    def handle_arp(self, event, packet):
        arp_pkt = packet.payload

        src_ip = arp_pkt.protosrc
        dst_ip = arp_pkt.protodst
        src_mac = arp_pkt.hwsrc

        # Learn IP → MAC
        self.arp_table[src_ip] = src_mac
        log.debug("Learned ARP: %s -> %s", src_ip, src_mac)

        if arp_pkt.opcode == arp.REQUEST:
            log.debug("ARP REQUEST: %s asking for %s", src_ip, dst_ip)

            if dst_ip in self.arp_table:
                dst_mac = self.arp_table[dst_ip]
                self.send_arp_reply(event, src_ip, dst_ip, src_mac, dst_mac)
            else:
                self.flood(event)

        elif arp_pkt.opcode == arp.REPLY:
            log.debug("ARP REPLY: %s is at %s", src_ip, src_mac)
            # Already learned

    def send_arp_reply(self, event, requester_ip, target_ip, requester_mac, target_mac):
        arp_reply = arp()
        arp_reply.opcode = arp.REPLY
        arp_reply.hwsrc = target_mac
        arp_reply.hwdst = requester_mac
        arp_reply.protosrc = target_ip
        arp_reply.protodst = requester_ip

        eth = ethernet()
        eth.type = ethernet.ARP_TYPE
        eth.src = target_mac
        eth.dst = requester_mac
        eth.payload = arp_reply

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=event.port))

        event.connection.send(msg)

        log.debug("Sent ARP reply: %s -> %s", target_ip, requester_ip)

    # ---------------- IP FORWARDING ---------------- #

    def handle_ip(self, event, packet):
        dpid = event.connection.dpid
        in_port = event.port
        dst = packet.dst

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]

            # Install flow (avoid future PacketIn)
            match = of.ofp_match.from_packet(packet, in_port)

            flow_mod = of.ofp_flow_mod()
            flow_mod.match = match
            flow_mod.actions.append(of.ofp_action_output(port=out_port))
            flow_mod.idle_timeout = 30
            flow_mod.hard_timeout = 60

            event.connection.send(flow_mod)

            # Forward current packet
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(msg)

        else:
            self.flood(event)

    # ---------------- FLOOD ---------------- #

    def flood(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)


def launch():
    core.registerNew(ARPController)
