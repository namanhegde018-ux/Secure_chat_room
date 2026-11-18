"""Mininet topology for the database-free secure group messenger lab.

Deterministic switch ports:
  1 Alice, 2 Bob, 3 Server, 4 Mallory, 5 Charlie, 6 David
"""

from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo


HOSTS = [
    ("alice", "10.0.0.1/24", "00:00:00:00:00:01"),
    ("bob", "10.0.0.2/24", "00:00:00:00:00:02"),
    ("server", "10.0.0.3/24", "00:00:00:00:00:03"),
    ("mallory", "10.0.0.4/24", "00:00:00:00:00:04"),
    ("charlie", "10.0.0.5/24", "00:00:00:00:00:05"),
    ("david", "10.0.0.6/24", "00:00:00:00:00:06"),
]


class SecureGroupTopo(Topo):
    def build(self):
        switch = self.addSwitch(
            "s1",
            dpid="0000000000000001",
            protocols="OpenFlow13",
            failMode="secure",
        )

        # Link in this exact order. The order defines OVS port numbers.
        for name, ip, mac in HOSTS:
            host = self.addHost(name, ip=ip, mac=mac)
            self.addLink(host, switch)


def main():
    setLogLevel("info")
    topo = SecureGroupTopo()
    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSSwitch,
        autoSetMacs=False,
        autoStaticArp=False,
    )

    net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6633,
    )

    try:
        info("*** Starting secure group-chat topology\n")
        net.start()
        info("*** Host/port map: Alice=1, Bob=2, Server=3, Mallory=4, Charlie=5, David=6\n")
        info("*** Group members: Alice, Bob, Charlie, David; Server is the relay; Mallory is monitored/blocked\n")
        CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    main()
