import struct
from typing import Union, TYPE_CHECKING

import packets.arp as arp
from packets.packet import Packet
from packets.ip import IPv4
from packets.raw import RAW

if TYPE_CHECKING:
    from packets.visitors.packetvisitor import PacketVisitor


class Ether(Packet):
    def __init__(
            self,
            _pkt: bytes = None,
            src_mac: Union[bytes, str] = '00:00:00:00:00:00',
            dst_mac: Union[bytes, str] = 'ff:ff:ff:ff:ff:ff',
            typ: int = 0,
            payload: bytes = b''
    ):
        self.int_to_proto = {
            0x0800: IPv4,
            0x0806: arp.ARP
        }

        if _pkt is not None:
            src, dst, typ = struct.unpack('>6s6sH', _pkt[:14])
            self.src = self.mac_to_str(src)
            self.dst = self.mac_to_str(dst)
            self.typ = typ
            self.payload = _pkt[14:]
        else:
            self.src = self.mac_to_str(src_mac)
            self.dst = self.mac_to_str(dst_mac)
            self.typ = typ
            self.payload = payload

    def __str__(self):
        typ = self.int_to_proto[self.typ].__name__ \
            if self.typ in self.int_to_proto \
            else self.typ

        return f'Ether from {self.src} ' \
               f'to {self.dst} ' \
               f'type {typ}'

    def accept_visitor(self, visitor: 'PacketVisitor'):
        return visitor.visit_ether(self)

    def get_next_layer(self):
        if self.typ not in self.int_to_proto:
            return RAW(self.payload)

        return self.int_to_proto[self.typ](_pkt=self.payload)

    def build(self):
        header = struct.pack(
            '>6s6sH',
            self.str_mac_to_bytes(self.src),
            self.str_mac_to_bytes(self.dst),
            self.typ
        )
        return header + self.payload

    @staticmethod
    def mac_to_bytes(mac: Union[str, bytes]):
        Ether.validate_mac(mac)
        if isinstance(mac, str):
            return Ether.str_mac_to_bytes(mac)
        return mac

    @staticmethod
    def mac_to_str(mac: Union[str, bytes]):
        Ether.validate_mac(mac)
        if isinstance(mac, str):
            return mac
        return Ether.byte_mac_to_str(mac)

    @staticmethod
    def str_mac_to_bytes(mac: str) -> bytes:
        Ether.validate_mac(mac)

        byte_mac = b''
        for num in mac.split(':'):
            b = int(num, 16).to_bytes(1, 'big')
            byte_mac += b

        return byte_mac

    @staticmethod
    def byte_mac_to_str(mac: bytes) -> str:
        Ether.validate_mac(mac)
        return ':'.join(hex(b)[2:].rjust(2, '0') for b in mac)

    @staticmethod
    def validate_mac(mac: Union[str, bytes]):
        if isinstance(mac, str):
            byt_nums = mac.split(':')
            if len(byt_nums) != 6:
                raise ValueError('Invalid mac')
            for num in byt_nums:
                if len(num) not in (1, 2):
                    raise ValueError('Invalid mac')
                try:
                    int(num, 16).to_bytes(1, 'big')
                except ValueError:
                    raise ValueError('Invalid mac')
        else:
            if len(mac) != 6:
                raise ValueError('Invalid mac')
