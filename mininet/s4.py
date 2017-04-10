from mininet.topo import Topo

class MyTopo( Topo ):

    def __init__( self ):

        # initilaize topology   
        Topo.__init__( self )

        # add hosts and switches
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )
        h4 = self.addHost( 'h4' )
        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )
        s3 = self.addSwitch( 's3' )
        s4 = self.addSwitch( 's4' )

        # add links
        self.addLink(h1,s1)
        self.addLink(h2,s2)
        self.addLink(h3,s3)
        self.addLink(h4,s4)
        self.addLink(s1,s2)
        self.addLink(s1,s3)
        self.addLink(s1,s4)


topos = { 'mytopo': ( lambda: MyTopo() ) }