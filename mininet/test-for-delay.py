from mininet.topo import Topo

class MyTopo( Topo ):

    def __init__( self ):

        # initilaize topology   
        Topo.__init__( self )

        # add hosts and switches
        s0 = self.addSwitch( 's0', dpid='0000000000000004' )       
        s1 = self.addSwitch( 's1' )       
        s2 = self.addSwitch( 's2' )       
        s3 = self.addSwitch( 's3' )       




        # add links

        self.addLink(s0,s1  )
        self.addLink(s0,s2  )
        self.addLink(s0,s3  )



topos = { 'mytopo': ( lambda: MyTopo() ) }
