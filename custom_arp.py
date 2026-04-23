#!/usr/bin/env python3
"""
custom_topology.py — Mininet topology for Ryu ARP controller
UE24CS252B - Computer Networks Assignment

Usage:
    sudo python3 custom_topology.py
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def create_topology():
    setLogLevel('info')

    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=False   # We set MACs manually below
    )

    info("*** Adding Ryu Remote Controller\n")
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    info("*** Adding Switch\n")
    s1 = net.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')

    info("*** Adding Hosts\n")
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

    info("*** Adding Links (10Mbps, 5ms delay)\n")
    net.addLink(h1, s1, bw=10, delay='5ms')
    net.addLink(h2, s1, bw=10, delay='5ms')
    net.addLink(h3, s1, bw=10, delay='5ms')
    net.addLink(h4, s1, bw=10, delay='5ms')

    info("*** Starting Network\n")
    net.start()

    info("\n" + "="*55 + "\n")
    info("  Topology running — Ryu controller @ 127.0.0.1:6633\n")
    info("  h1=10.0.0.1  h2=10.0.0.2\n")
    info("  h3=10.0.0.3  h4=10.0.0.4\n")
    info("="*55 + "\n")
    info("  Try:\n")
    info("    mininet> pingall\n")
    info("    mininet> h1 ping h2\n")
    info("    mininet> h1 arp -n\n")
    info("    mininet> sh ovs-ofctl dump-flows s1\n")
    info("    mininet> iperf h1 h2\n")
    info("="*55 + "\n\n")

    CLI(net)
    net.stop()


if __name__ == '__main__':
    create_topology()
