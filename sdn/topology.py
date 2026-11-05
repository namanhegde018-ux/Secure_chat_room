from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI


# Step 1: Create our network topology
class SecureMessagingTopo(Topo):

    def build(self):

        # Step 2: Create four hosts

        alice = self.addHost(
            'alice',
            ip='10.0.0.1/24'
        )

        bob = self.addHost(
            'bob',
            ip='10.0.0.2/24'
        )

        server = self.addHost(
            'server',
            ip='10.0.0.3/24'
        )

        mallory = self.addHost(
            'mallory',
            ip='10.0.0.4/24'
        )

        # Step 3: Create Open vSwitch
        # Standalone mode allows basic switching without a controller.

        s1 = self.addSwitch(
            's1',
            failMode='secure',
	    protocols='OpenFlow13'
        )

        # Step 4: Connect all hosts to the switch

        self.addLink(alice, s1)
        self.addLink(bob, s1)
        self.addLink(server, s1)
        self.addLink(mallory, s1)


# Step 5: Create the network without the default controller

topo = SecureMessagingTopo()

net = Mininet(
    topo=topo,
    controller=None,
    switch=OVSSwitch,
    autoSetMacs=True
)

# Connect Mininet to our OS-Ken controller

net.addController(
    'c0',
    controller=RemoteController,
    ip='127.0.0.1',
    port=6633
)
# Step 6: Start network

net.start()

print("\n================================")
print(" SECURE MESSAGING NETWORK STARTED")
print("================================")

print("Alice:   10.0.0.1")
print("Bob:     10.0.0.2")
print("Server:  10.0.0.3")
print("Mallory: 10.0.0.4")

# Step 7: Open Mininet terminal

CLI(net)

# Step 8: Stop network

net.stop()
