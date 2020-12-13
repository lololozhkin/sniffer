from hexdump import hexdump

from packets.arp import ARP
from packets.ether import Ether
from packets.ip import IPv4
from packets.raw import RAW
from packets.tcp import TCP
from packets.udp import UDP
from packets.visitors.first_verbosity_visitor import FirstVerbosityVisitor
from packets.visitors.packetvisitor import PacketVisitor


class SecondVerbosityVisitor(PacketVisitor):
    def visit_ether(self, pkt: Ether) -> str:
        return pkt.accept_visitor(FirstVerbosityVisitor())

    def visit_ip(self, pkt: IPv4) -> str:
        return pkt.accept_visitor(FirstVerbosityVisitor())

    def visit_tcp(self, pkt: TCP) -> str:
        return pkt.accept_visitor(FirstVerbosityVisitor())

    def visit_udp(self, pkt: UDP) -> str:
        return pkt.accept_visitor(FirstVerbosityVisitor())

    def visit_arp(self, pkt: ARP) -> str:
        return pkt.accept_visitor(FirstVerbosityVisitor())

    def visit_raw(self, pkt: RAW) -> str:
        return f'RAW payload: \n' + hexdump(pkt.data, result='return')
