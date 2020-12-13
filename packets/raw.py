from typing import TYPE_CHECKING

from packets.packet import Packet
from hexdump import hexdump

if TYPE_CHECKING:
    from packets.visitors.packetvisitor import PacketVisitor


class RAW(Packet):
    def __init__(self, _pkt: bytes):
        self.data = _pkt

    def __str__(self):
        return f'RAW load: \n{hexdump(self.data, result="return")}'

    def get_next_layer(self):
        pass

    def build(self):
        return self.data

    def accept_visitor(self, visitor: 'PacketVisitor'):
        return visitor.visit_raw(self)
