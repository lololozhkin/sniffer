from abc import ABC, abstractmethod

from packets.arp import ARP
from packets.ether import Ether
from packets.ip import IPv4
from packets.packet import Packet
from packets.raw import RAW
from packets.tcp import TCP
from packets.udp import UDP


class PacketVisitor(ABC):
    @abstractmethod
    def visit_ether(self, pkt: Ether) -> str:
        pass

    @abstractmethod
    def visit_ip(self, pkt: IPv4) -> str:
        pass

    @abstractmethod
    def visit_tcp(self, pkt: TCP) -> str:
        pass

    @abstractmethod
    def visit_udp(self, pkt: UDP) -> str:
        pass

    @abstractmethod
    def visit_arp(self, pkt: ARP) -> str:
        pass

    @abstractmethod
    def visit_raw(self, pkt: RAW) -> str:
        pass
