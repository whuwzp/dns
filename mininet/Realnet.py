#!/usr/bin/env python
import os
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import Intf
from mininet.log import setLogLevel, info

def ToRealnet():

    net = Mininet( topo=None, build=False)

    info( '*** Adding controller\n' )
    net.addController('co', controller=RemoteController,ip='127.0.0.1',port=6633)

    info( '*** Add switches\n')
    s1 = net.addSwitch('s1')

    info( '*** Add hosts\n')
    h1 = net.addHost('h1', ip='0.0.0.0')
    h2 = net.addHost('h2', ip='0.0.0.0')

    info( '*** Add links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)

    info( '*** Starting network\n')
    net.start()
    os.popen('ovs-vsctl add-port s1 enp2s0f1') 
    h1.cmdPrint('dhclient '+h1.defaultIntf().name)
    h2.cmdPrint('dhclient '+h2.defaultIntf().name)
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
ToRealnet()
