import binascii
import struct
from typing import Union, TYPE_CHECKING

from packets.packet import Packet
from packets import ip
import packets.ether as ether

if TYPE_CHECKING:
    from packets.visitors.packetvisitor import PacketVisitor


class ARP(Packet):
    type_to_str_formatter = {
        0x0001: ether.Ether.mac_to_str,
        0x0800: ip.IPv4.str_ip
    }

    type_to_bytes_formatter = {
        0x0001: ether.Ether.mac_to_bytes,
        0x0800: ip.IPv4.bytes_ip
    }

    def __init__(
            self,
            _pkt=None,
            h_type: int = 0x0001,
            p_type: int = 0x0800,
            h_len: int = 6,
            p_len: int = 4,
            op: int = 0x0001,
            h_src: Union[bytes, str] = b'',
            p_src: Union[bytes, str] = b'',
            h_dst: Union[bytes, str] = b'',
            p_dst: Union[bytes, str] = b''
    ):
        if _pkt is not None:
            unpack = struct.unpack(
                '>HHBBH',
                _pkt[:8]
            )
            self.h_type, self.p_type, self.h_len, self.p_len, self.op = unpack

            addr_len = 2 * (self.h_len + self.p_len)
            addresses = struct.unpack(
                f'>{self.h_len}s{self.p_len}s{self.h_len}s{self.p_len}s',
                _pkt[8:8 + addr_len]
            )
            self.h_src, self.p_src, self.h_dst, self.p_dst = addresses
            self.h_src = self.str_addr(self.h_src, self.h_type)
            self.p_src = self.str_addr(self.p_src, self.p_type)
            self.h_dst = self.str_addr(self.h_dst, self.h_type)
            self.p_dst = self.str_addr(self.p_dst, self.p_type)
        else:
            self.h_type = h_type
            self.p_type = p_type
            self.h_len = h_len
            self.p_len = p_len
            self.op = op
            self.h_src = self.str_addr(h_src, h_type)
            self.p_src = self.str_addr(p_src, p_type)
            self.h_dst = self.str_addr(h_dst, h_type)
            self.p_dst = self.str_addr(p_dst, p_type)

    def __str__(self):
        return f'ARP hardware type: {self.h_type}; ' \
               f'proto type: {self.p_type} ' \
               f'h_src: {self.h_src} ' \
               f'p_src: {self.p_src} ' \
               f'h_dst: {self.h_dst} ' \
               f'p_dst: {self.p_dst}'

    def str_operation(self):
        if self.op == 0x0001:
            return 'request'
        if self.op == 0x0002:
            return 'response'
        return 'unknown'

    def accept_visitor(self, visitor: 'PacketVisitor'):
        return visitor.visit_arp(self)

    def build(self):
        return struct.pack(
            f'>HHBBH{self.h_len}s{self.p_len}s{self.h_len}s{self.p_len}s',
            self.h_type,
            self.p_type,
            self.h_len,
            self.p_len,
            self.op,
            self.byte_addr(self.h_src, self.h_type),
            self.byte_addr(self.p_src, self.p_type),
            self.byte_addr(self.h_dst, self.h_type),
            self.byte_addr(self.p_dst, self.p_type)
        )

    def str_addr(self, addr: Union[str, bytes], typ: int):
        if typ in self.type_to_str_formatter:
            return self.type_to_str_formatter[typ](addr)
        if isinstance(addr, str):
            return addr

        return addr.hex()

    def byte_addr(self, addr: Union[str, bytes], typ: int):
        if typ in self.type_to_str_formatter:
            return self.type_to_bytes_formatter[typ](addr)
        if isinstance(addr, str):
            return binascii.unhexlify(addr)
        return addr

    def get_next_layer(self):
        pass
