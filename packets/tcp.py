import struct
from typing import TYPE_CHECKING

from packets.packet import Packet
from packets.raw import RAW

if TYPE_CHECKING:
    from packets.visitors.packetvisitor import PacketVisitor


class TCPFlags:
    URG = 0b000100000
    ACK = 0b000010000
    PSH = 0b000001000
    RST = 0b000000100
    SYN = 0b000000010
    FIN = 0b000000001


class TCP(Packet):
    def __init__(
            self,
            _pkt: bytes = None,
            src_port: int = 20,
            dst_port: int = 80,
            seq_num: int = 0,
            ack_num: int = 0,
            data_offset: int = 5,
            flags: int = TCPFlags.SYN,
            window_size: int = 1024,
            urg_ptr: int = 0,
            options_and_data: bytes = b''
    ):
        if _pkt is not None:
            parsed_packet = struct.unpack(">HHIIHHHH", _pkt[:20])
            self.src_port, self.dst_port = parsed_packet[:2]
            self.seq_num, self.ack_num = parsed_packet[2:4]
            self.flags, self.window_size = parsed_packet[4:6]
            self.checksum, self.urg_ptr = parsed_packet[6:8]
            self.options_and_data = _pkt[20:]
            self.data_offset = self.flags >> 12
            self.flags = self.flags & 0x1FF
        else:
            self.src_port = src_port
            self.dst_port = dst_port
            self.seq_num = seq_num
            self.ack_num = ack_num
            self.data_offset = data_offset
            self.flags = flags
            self.window_size = window_size
            self.urg_ptr = urg_ptr
            self.options_and_data = options_and_data
            self.checksum = 0

    def __str__(self):
        ans = f'from: {self.src_port}, ' \
              f'to: {self.dst_port}, ' \
              f'seq: {self.seq_num}, ' \
              f'ack: {self.ack_num}, ' \
              f'checksum: {self.checksum}'

        return f'{ans} {" ".join(self.str_flags())}'

    def str_flags(self):
        str_flags = []
        if self.is_ack:
            str_flags.append('ACK')
        if self.is_push:
            str_flags.append('PSH')
        if self.is_rst:
            str_flags.append('RST')
        if self.is_syn:
            str_flags.append('SYN')
        if self.is_fin:
            str_flags.append('FIN')

        return str_flags

    def accept_visitor(self, visitor: 'PacketVisitor'):
        return visitor.visit_tcp(self)

    def build(self):
        data_offset_and_flags = (self.data_offset << 12) | self.flags

        packet_without_options = struct.pack(
            '>HHIIHHHH',
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            data_offset_and_flags,
            self.window_size,
            self.checksum,
            self.urg_ptr
        )

        return packet_without_options + self.options_and_data

    def get_next_layer(self):
        return RAW(self.options_and_data)

    @property
    def is_ack(self):
        return bool(self.flags & TCPFlags.ACK)

    @property
    def is_push(self):
        return bool(self.flags & TCPFlags.PSH)

    @property
    def is_rst(self):
        return bool(self.flags & TCPFlags.RST)

    @property
    def is_syn(self):
        return bool(self.flags & TCPFlags.SYN)

    @property
    def is_fin(self):
        return bool(self.flags & TCPFlags.FIN)
