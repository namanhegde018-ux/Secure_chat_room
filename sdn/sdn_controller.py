"""OpenFlow 1.3 policy for the messaging lab (os_ken).

Policy:
  * IPv6 is dropped in the switch.
  * ARP is allowed.
  * Any host may open TCP to the signaling port on the server and may ping it.
  * The server may answer those flows.
  * IPv4 between two non-server hosts is dropped, and the pair is blocked briefly.
  * Anything else that reaches the controller is dropped.

No client names or per-user addresses are configured. Identity is handled by main.py.
"""

import logging
import time

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib.packet import ethernet, ipv4, packet
from os_ken.ofproto import ofproto_v1_3

import lab_config as cfg

log = logging.getLogger("sdn.policy")

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_IPV6 = 0x86DD
ETH_LLDP = 0x88CC
IP_ICMP = 1
IP_TCP = 6

PRIO_TABLE_MISS = 0
PRIO_IPV6_DROP = 200
PRIO_ALLOW = 400
PRIO_BLOCK_PAIR = 450

BLOCK_IDLE_SECONDS = 30
REPORT_INTERVAL = 5.0


class ServerOnlyPolicy(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._last_report = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_switch_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser

        # Start from an empty table so only this policy is active.
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp,
            table_id=ofp.OFPTT_ALL,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            match=parser.OFPMatch(),
        ))

        normal = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        server = cfg.SERVER_IP
        port = cfg.SIGNAL_PORT

        self._add(dp, PRIO_TABLE_MISS, parser.OFPMatch(),
                  [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])
        self._add(dp, PRIO_IPV6_DROP, parser.OFPMatch(eth_type=ETH_IPV6), [])
        self._add(dp, PRIO_ALLOW, parser.OFPMatch(eth_type=ETH_ARP), normal)
        self._add(dp, PRIO_ALLOW, parser.OFPMatch(
            eth_type=ETH_IPV4, ip_proto=IP_TCP, ipv4_dst=server, tcp_dst=port), normal)
        self._add(dp, PRIO_ALLOW, parser.OFPMatch(
            eth_type=ETH_IPV4, ip_proto=IP_TCP, ipv4_src=server, tcp_src=port), normal)
        self._add(dp, PRIO_ALLOW, parser.OFPMatch(
            eth_type=ETH_IPV4, ip_proto=IP_ICMP, ipv4_dst=server), normal)
        self._add(dp, PRIO_ALLOW, parser.OFPMatch(
            eth_type=ETH_IPV4, ip_proto=IP_ICMP, ipv4_src=server), normal)

        log.info("policy installed on switch %s: 7 base rules (server %s:%d)",
                 dp.id, server, port)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None or eth.ethertype == ETH_LLDP:
            self._drop(msg, dp, in_port)
            return

        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is None:
            self._report(("non-ipv4", eth.src, eth.dst),
                         f"BLOCKED frame {eth.src} -> {eth.dst} ethertype 0x{eth.ethertype:04x}")
            self._drop(msg, dp, in_port)
            return

        if cfg.SERVER_IP in (ip.src, ip.dst):
            self._report(("server", ip.src, ip.dst),
                         f"BLOCKED {ip.src} -> {ip.dst} (server accepts only TCP "
                         f"{cfg.SIGNAL_PORT} and ICMP)")
            self._drop(msg, dp, in_port)
            return

        self._block_pair(dp, ip.src, ip.dst)
        self._report(("pair", ip.src, ip.dst),
                     f"BLOCKED client-to-client {ip.src} -> {ip.dst}")
        self._drop(msg, dp, in_port)

    def _add(self, dp, priority, match, actions, idle=0):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp,
            cookie=cfg.POLICY_COOKIE,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle,
            hard_timeout=0,
        ))

    def _block_pair(self, dp, src, dst):
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=ETH_IPV4, ipv4_src=src, ipv4_dst=dst)
        self._add(dp, PRIO_BLOCK_PAIR, match, [], idle=BLOCK_IDLE_SECONDS)

    def _drop(self, msg, dp, in_port):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=[],
            data=data,
        ))

    def _report(self, key, text):
        now = time.monotonic()
        if now - self._last_report.get(key, 0.0) >= REPORT_INTERVAL:
            self._last_report[key] = now
            log.warning(text)