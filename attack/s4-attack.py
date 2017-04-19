from mininet.topo import Topo

class MyTopo( Topo ):

    def __init__( self ):

        # initilaize topology   
        Topo.__init__( self )

        # add hosts and switches
        s0 = self.addSwitch( 's0', dpid='0000000000000004' )       

        h1 = self.addHost( 'h1' ,ip='192.168.56.8/24')       




        # add links

        self.addLink(h1,s0)




topos = { 'mytopo': ( lambda: MyTopo() ) }
