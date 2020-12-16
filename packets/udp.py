import struct
from typing import TYPE_CHECKING

from packets.packet import Packet
from packets.raw import RAW

if TYPE_CHECKING:
    from packets.visitors.packetvisitor import PacketVisitor


class UDP(Packet):
    def __init__(
            self,
            _pkt: bytes = None,
            src_port: int = 20,
            dst_port: int = 53,
            payload=b''
    ):
        if _pkt is not None:
            parsed_packet = struct.unpack(">HHHH", _pkt[:8])
            self.src_port, self.dst_port = parsed_packet[:2]
            self.length, self.checksum = parsed_packet[2:4]
            self.payload = _pkt[8:]
        else:
            self.src_port = src_port
            self.dst_port = dst_port
            self.payload = payload
            self.checksum = 0

    def __str__(self):
        return f'UDP src port: {self.src_port} ' \
               f'dst port: {self.dst_port} ' \
               f'data length: {self.length} '

    def accept_visitor(self, visitor: 'PacketVisitor'):
        return visitor.visit_udp(self)

    def build(self):
        packet = struct.pack(
            '>HHHH',
            self.src_port,
            self.dst_port,
            len(self.payload) + 8,
            self.checksum
        )

        return packet + self.payload

    def get_next_layer(self):
        return RAW(self.payload)
