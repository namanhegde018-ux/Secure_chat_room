from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls
)
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet


class SecureMessagingController(app_manager.OSKenApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.logger.info("Secure Messaging Controller Started")

    # Function to install flow rules
    def add_flow(self, datapath, priority, match, actions):

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions
        )

        datapath.send_msg(mod)

    # When a switch connects
    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER
    )
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Remove old forwarding rules
        delete = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            table_id=ofproto.OFPTT_ALL,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch()
        )

        datapath.send_msg(delete)

        # Default rule: send unmatched packets to controller
        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(
            datapath,
            priority=0,
            match=match,
            actions=actions
        )

        # Block Mallory's incoming port
        self.add_flow(
            datapath,
            priority=500,
            match=parser.OFPMatch(in_port=4),
            actions=[]
        )

        # Block traffic destined for Mallory
        self.add_flow(
            datapath,
            priority=500,
            match=parser.OFPMatch(
                eth_dst="00:00:00:00:00:03"
            ),
            actions=[]
        )

        self.logger.info(
            "Switch connected. Default-deny policy installed."
        )

        # Allow ARP only among authorised hosts

        arp_paths = {
            1: [2, 3],
            2: [1, 3],
            3: [1, 2]
        }

        for in_port, output_ports in arp_paths.items():

            arp_actions = [
                parser.OFPActionOutput(port)
                for port in output_ports
            ]

            self.add_flow(
                datapath,
                priority=300,
                match=parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0806
                ),
                actions=arp_actions
            )

        self.logger.info(
            "Mallory blocking rules installed."
        )

    # Receive and log packets that have no permission
    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER
    )
    def packet_in_handler(self, ev):

        msg = ev.msg

        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        self.logger.info(
            "UNAUTHORISED TRAFFIC: ingress=%s source=%s destination=%s",
            in_port,
            eth.src,
            eth.dst
        )

        # Intentionally do not forward the packet.
        # Unmatched traffic is dropped.
