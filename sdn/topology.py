#!/usr/bin/env python3
"""Mininet lab: one OVS switch, one server host, N anonymous client hosts.

Run from sdn/: sudo .venv-sdn/bin/python topology.py --clients 3
"""

import argparse

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

import lab_config as cfg


class LabTopo(Topo):
    def build(self, clients):
        switch = self.addSwitch(cfg.BRIDGE, protocols="OpenFlow13", failMode="secure")
        server = self.addHost(cfg.SERVER_NODE, ip=f"{cfg.SERVER_IP}/24")
        self.addLink(server, switch)
        for i in range(1, clients + 1):
            host = self.addHost(cfg.client_node(i), ip=f"{cfg.client_ip(i)}/24")
            self.addLink(host, switch)


def main():
    parser = argparse.ArgumentParser(description="Secure messaging SDN lab")
    parser.add_argument("--clients", type=int, default=cfg.DEFAULT_CLIENTS,
                        help=f"number of client hosts (1..{cfg.MAX_CLIENTS})")
    args = parser.parse_args()
    if not 1 <= args.clients <= cfg.MAX_CLIENTS:
        parser.error(f"--clients must be between 1 and {cfg.MAX_CLIENTS}")

    setLogLevel("info")
    net = Mininet(
        topo=LabTopo(clients=args.clients),
        controller=RemoteController("c0", ip=cfg.OPENFLOW_HOST, port=cfg.OPENFLOW_PORT),
        switch=OVSSwitch,
        autoSetMacs=True,
        autoStaticArp=True,
    )
    net.start()
    try:
        CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    main()