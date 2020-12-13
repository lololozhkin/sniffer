import struct
from typing import Union, TYPE_CHECKING

from packets.packet import Packet
from packets.raw import RAW
from packets.tcp import TCP
from packets.udp import UDP

if TYPE_CHECKING:
    from packets.visitors.packetvisitor import PacketVisitor


class IPv4(Packet):
    int_to_proto = {
        6: TCP,
        17: UDP
    }

    def __init__(
            self,
            _pkt: bytes = None,
            version: int = 4,
            header_len: int = 0,
            qos: int = 0,
            packet_len: int = 0,
            ip_id: int = 0,
            flags: int = 0,
            offset: int = 0,
            ttl: int = 64,
            proto: int = 0,
            checksum: int = 0,
            ip_src: Union[str, bytes] = '127.0.0.1',
            ip_dst: Union[str, bytes] = '255.255.255.255',
            payload: bytes = b''
    ):
        if _pkt is not None:
            unpacked = struct.unpack(
                '>BBHHHBBH4s4s',
                _pkt[:20]
            )
            self.version = unpacked[0] >> 4
            self.header_len = unpacked[0] & 0xF
            self.qos = unpacked[1]
            self.packet_len = unpacked[2]
            self.id = unpacked[3]
            self.flags = unpacked[4] >> 13
            self.offset = ((unpacked[4] << 3) & 0xFFFF) >> 3
            self.ttl = unpacked[5]
            self.proto = unpacked[6]
            self.checksum = unpacked[7]
            self.src = self.str_ip(unpacked[8])
            self.dst = self.str_ip(unpacked[9])
            self.payload = _pkt[20:]
        else:
            self.version = version
            self.header_len = header_len
            self.qos = qos
            self.packet_len = packet_len
            self.id = ip_id
            self.flags = flags
            self.offset = offset
            self.ttl = ttl
            self.proto = proto
            self.checksum = checksum
            self.src = self.str_ip(ip_src)
            self.dst = self.str_ip(ip_dst)
            self.payload = payload

    def __str__(self):
        proto = self.int_to_proto[self.proto].__name__ \
            if self.proto in self.int_to_proto \
            else self.proto

        return f'IP from: {self.src}; ' \
               f'to {self.dst}; ' \
               f'proto: {proto}'

    @property
    def str_flags(self):
        bit_to_flag = ["More fragments", "Don't fragment", "Evil"]
        ans = []
        flags = self.flags
        for i in range(3):
            if flags & 1:
                ans.append(bit_to_flag[i])
            flags >>= 1
        if len(ans) == 0:
            return 'No flags set'
        return ', '.join(ans)

    @staticmethod
    def bytes_ip_to_str(ip: bytes):
        IPv4.verify_ip(ip)
        return '.'.join(str(num) for num in ip)

    @staticmethod
    def str_ip_to_bytes(ip: str):
        IPv4.verify_ip(ip)
        nums = ip.split('.')
        return b''.join(int(num).to_bytes(1, 'big') for num in nums)

    @staticmethod
    def verify_ip(ip: Union[str, bytes]):
        if isinstance(ip, str):
            nums = ip.split('.')
            if len(nums) != 4:
                raise ValueError("Incorrect IP")
            for num in nums:
                if not(0 <= int(num) <= 255):
                    raise ValueError("Incorrect IP")
        else:
            if len(ip) != 4:
                raise ValueError("Incorrect IP")

    @staticmethod
    def str_ip(ip: Union[str, bytes]):
        IPv4.verify_ip(ip)
        if isinstance(ip, str):
            return ip
        return IPv4.bytes_ip_to_str(ip)

    @staticmethod
    def bytes_ip(ip: Union[str, bytes]):
        IPv4.verify_ip(ip)
        if isinstance(ip, str):
            return IPv4.str_ip_to_bytes(ip)
        return ip

    def build(self):
        return struct.pack(
            '>BBHHHBBH4s4s',
            (self.version << 4) | self.header_len,
            self.qos,
            self.packet_len,
            self.id,
            (self.flags << 13) | self.offset,
            self.ttl,
            self.proto,
            self.checksum,
            self.bytes_ip(self.src),
            self.bytes_ip(self.dst),
            ) + self.payload

    def get_next_layer(self):
        if self.proto not in self.int_to_proto:
            return RAW(_pkt=self.payload)

        return self.int_to_proto[self.proto](_pkt=self.payload)

    def accept_visitor(self, visitor: 'PacketVisitor'):
        return visitor.visit_ip(self)
