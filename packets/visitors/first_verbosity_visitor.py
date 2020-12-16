from packets.arp import ARP
from packets.ether import Ether
from packets.ip import IPv4
from packets.raw import RAW
from packets.tcp import TCP
from packets.udp import UDP
from packets.visitors.packetvisitor import PacketVisitor
from packets.visitors.zero_verbosity_visitor import ZeroVerbosityVisitor


class FirstVerbosityVisitor(PacketVisitor):
    def visit_ether(self, pkt: Ether) -> str:
        return f'Ethernet {pkt.src} > {pkt.dst} (type: {pkt.typ})'

    def visit_ip(self, pkt: IPv4) -> str:
        initial = pkt.accept_visitor(ZeroVerbosityVisitor())
        return (
            f'{initial} ('
            f'id: {pkt.id}, '
            f'ttl: {pkt.ttl}, '
            f'proto: {pkt.proto}, '
            f'flags: ({pkt.str_flags})'
            f')'
        )

    def visit_tcp(self, pkt: TCP) -> str:
        return (
            f'TCP {pkt.src_port} > {pkt.dst_port} ('
            f'seq number: {pkt.seq_num}, '
            f'ack number: {pkt.ack_num}, '
            f'window size: {pkt.window_size}, '
            f'checksum: {pkt.checksum}, '
            f'urg pointer: {pkt.urg_ptr}, '
            f'flags: ({",".join(pkt.str_flags())})'
            f')'
        )

    def visit_udp(self, pkt: UDP) -> str:
        return (
            f'UDP {pkt.src_port} > {pkt.dst_port} ('
            f'checksum: {pkt.checksum}'
            f')'
        )

    def visit_arp(self, pkt: ARP) -> str:
        return (
            f'ARP ('
            f'hardware type: {pkt.h_type}, '
            f'protocol type: {pkt.p_type}, '
            f'hardware len: {pkt.h_len}, '
            f'protocol len: {pkt.p_len}, '
            f'opcode: {pkt.op}({pkt.str_operation()})'
            f'sender hw address: {pkt.h_src}, '
            f'sender net address: {pkt.p_src}, '
            f'target hw address: {pkt.h_dst}, '
            f'target net address: {pkt.p_dst}'
            f')'
        )

    def visit_raw(self, pkt: RAW) -> str:
        return 'RAW payload'
