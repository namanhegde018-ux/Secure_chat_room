"""OS-Ken OpenFlow 1.3 controller for a server-relayed group chat lab.

Policy:
- Default deny: unmatched packets are sent to the controller and not forwarded.
- ARP discovery is allowed among trusted hosts only (Alice, Bob, Server,
  Charlie, David); Mallory is excluded.
- Mallory ingress traffic and traffic addressed to Mallory are sent to the
  controller for logging, with no data-plane forwarding action.
- Session-specific IPv4 forwarding is installed by sdn_api.py using ovs-ofctl.
  Participants communicate via the Server relay, not directly peer-to-peer.
"""

import json
import time
import urllib.error
import urllib.request

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from os_ken.lib.packet import arp, ethernet, ether_types, ipv4, ipv6, packet
from os_ken.ofproto import ofproto_v1_3


FLASK_EVENT_URL = "http://127.0.0.1:5000/internal/event"
MALLORY_IP = "10.0.0.4"
MALLORY_MAC = "00:00:00:00:00:04"
MALLORY_PORT = 4

HOST_BY_PORT = {
    1: "Alice",
    2: "Bob",
    3: "Server",
    4: "Mallory",
    5: "Charlie",
    6: "David",
}

HOST_BY_IP = {
    "10.0.0.1": "Alice",
    "10.0.0.2": "Bob",
    "10.0.0.3": "Server",
    "10.0.0.4": "Mallory",
    "10.0.0.5": "Charlie",
    "10.0.0.6": "David",
}

TRUSTED_PORTS = (1, 2, 3, 5, 6)


class SecureMessagingController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._last_reported = {}
        print("[LOAD] SecureMessagingController instantiated", flush=True)

    def add_flow(self, datapath, priority, match, actions, cookie=0):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions,
            )
        ]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=cookie,
            priority=priority,
            match=match,
            instructions=instructions,
        )
        datapath.send_msg(mod)

    def _send_dashboard_event(self, source, destination, message, event_key):
        """Send a rate-limited security event to the local Flask process."""
        now = time.monotonic()
        previous = self._last_reported.get(event_key, 0.0)
        if now - previous < 1.5:
            return
        self._last_reported[event_key] = now

        payload = json.dumps({
            "source": source,
            "destination": destination,
            "status": "BLOCKED",
            "message": message,
        }).encode("utf-8")
        request = urllib.request.Request(
            FLASK_EVENT_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=0.5) as response:
                response.read()
            self.logger.info("Dashboard event delivered: %s -> %s", source, destination)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self.logger.warning("Could not send dashboard event: %s", exc)

    @staticmethod
    def _packet_addresses(pkt, eth):
        source_ip = None
        destination_ip = None
        ip4 = pkt.get_protocol(ipv4.ipv4)
        ip6 = pkt.get_protocol(ipv6.ipv6)
        arp_pkt = pkt.get_protocol(arp.arp)
        if ip4:
            source_ip, destination_ip = ip4.src, ip4.dst
        elif ip6:
            source_ip, destination_ip = ip6.src, ip6.dst
        elif arp_pkt:
            source_ip, destination_ip = arp_pkt.src_ip, arp_pkt.dst_ip
        return source_ip, destination_ip

    def _friendly_destination(self, pkt, eth, destination_ip):
        if destination_ip in HOST_BY_IP:
            return HOST_BY_IP[destination_ip]
        if destination_ip:
            if destination_ip.lower().startswith("ff"):
                return "IPv6 multicast"
            return destination_ip
        if eth.dst.lower() == "ff:ff:ff:ff:ff:ff":
            return "Broadcast"
        if eth.dst.lower().startswith("33:33:"):
            return "IPv6 multicast"
        return eth.dst

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        print(
            f"[EVENT] SwitchFeatures received: DPID={datapath.id}",
            flush=True,
        )

        # Clear stale rules on a fresh switch connection. Session rules are
        # recreated by the API after a controller/switch restart.
        delete = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            table_id=ofproto.OFPTT_ALL,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch(),
        )
        datapath.send_msg(delete)
        print("[DEBUG] Flow-table cleanup submitted", flush=True)

        # Table-miss: send unmatched traffic to the controller. The packet-in
        # handler intentionally does not forward unmatched packets.
        self.add_flow(
            datapath,
            priority=0,
            match=parser.OFPMatch(),
            actions=[
                parser.OFPActionOutput(
                    ofproto.OFPP_CONTROLLER,
                    ofproto.OFPCML_NO_BUFFER,
                )
            ],
        )

        # Monitor Mallory's ingress traffic. Output-to-controller is the only
        # action, so the packet is not forwarded to another host.
        to_controller = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )
        ]
        self.add_flow(
            datapath,
            priority=600,
            match=parser.OFPMatch(in_port=MALLORY_PORT),
            actions=to_controller,
        )

        # Monitor IPv4 traffic addressed to Mallory.
        self.add_flow(
            datapath,
            priority=600,
            match=parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=MALLORY_IP,
            ),
            actions=to_controller,
        )

        # Monitor ARP requests/replies whose target protocol address is Mallory.
        self.add_flow(
            datapath,
            priority=600,
            match=parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_ARP,
                arp_tpa=MALLORY_IP,
            ),
            actions=to_controller,
        )

        # Permit ARP discovery among trusted hosts only; never include port 4.
        for in_port in TRUSTED_PORTS:
            outputs = [
                parser.OFPActionOutput(port)
                for port in TRUSTED_PORTS
                if port != in_port
            ]
            self.add_flow(
                datapath,
                priority=300,
                match=parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_ARP,
                ),
                actions=outputs,
            )

        print("[SUCCESS] Base security and ARP rules submitted", flush=True)
        self.logger.info("Switch connected; base security rules submitted")

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_handler(self, ev):
        msg = ev.msg
        print(
            f"[OPENFLOW ERROR] type={msg.type} code={msg.code}",
            flush=True,
        )
        self.logger.error("OpenFlow error: type=%s code=%s", msg.type, msg.code)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        in_port = msg.match.get("in_port")
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        source_ip, destination_ip = self._packet_addresses(pkt, eth)
        is_mallory_traffic = (
            in_port == MALLORY_PORT
            or source_ip == MALLORY_IP
            or destination_ip == MALLORY_IP
            or eth.src.lower() == MALLORY_MAC
            or eth.dst.lower() == MALLORY_MAC
        )

        if is_mallory_traffic:
            source = HOST_BY_PORT.get(in_port, HOST_BY_IP.get(source_ip, eth.src))
            destination = self._friendly_destination(pkt, eth, destination_ip)
            if destination_ip == MALLORY_IP or eth.dst.lower() == MALLORY_MAC:
                destination = "Mallory"
            message = f"Blocked by SDN policy (switch ingress port {in_port})"
            print(f"[BLOCKED ATTEMPT] {source} -> {destination}", flush=True)
            key = (in_port, eth.src.lower(), eth.dst.lower(), source_ip, destination_ip)
            self._send_dashboard_event(source, destination, message, key)
            # Deliberately do not send PacketOut: the packet is dropped.
            return

        # Default-deny: unmatched non-Mallory traffic is not forwarded.
        self.logger.debug("Unmatched packet dropped: ingress=%s", in_port)
