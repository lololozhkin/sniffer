from packets.arp import ARP
from packets.ether import Ether
from packets.ip import IPv4
from packets.raw import RAW
from packets.tcp import TCP
from packets.udp import UDP
from packets.visitors.packetvisitor import PacketVisitor


class ZeroVerbosityVisitor(PacketVisitor):
    def visit_ether(self, pkt: Ether) -> str:
        return ''

    def visit_ip(self, pkt: IPv4) -> str:
        if pkt.has_layer(TCP):
            transport_layer = pkt.get_layer(TCP)
        elif pkt.has_layer(UDP):
            transport_layer = pkt.get_layer(UDP)
        else:
            transport_layer = None

        src_port = f':{transport_layer.src_port}' \
            if transport_layer is not None \
            else ''
        dst_port = f':{transport_layer.dst_port}'\
            if transport_layer is not None \
            else ''

        return f'IP {pkt.src}{src_port} > {pkt.dst}{dst_port}'

    def visit_tcp(self, pkt: TCP) -> str:
        return ''

    def visit_udp(self, pkt: UDP) -> str:
        return ''

    def visit_arp(self, pkt: ARP) -> str:
        return 'ARP'

    def visit_raw(self, pkt: RAW) -> str:
        return ''
