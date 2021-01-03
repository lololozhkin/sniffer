import select
import socket
import time
from collections import deque
from typing import Tuple

from receivers.receiver import Receiver


class SocketReceiver(Receiver):
    ETH_P_ALL = 3
    MAX_SIZE = 1518

    def __init__(self, *interfaces):
        self.epoll = select.poll()
        self.packets = deque()

        self.descriptor_to_socket = {}
        if len(interfaces):
            for iface in interfaces:
                sock = socket.socket(
                    socket.AF_PACKET,
                    socket.SOCK_RAW,
                    socket.htons(self.ETH_P_ALL)
                )

                try:
                    sock.bind((iface, 0))
                except OSError:
                    raise OSError(f"Unable to find interface {iface}")

                self.epoll.register(sock.fileno(), select.EPOLLIN)
                self.descriptor_to_socket[sock.fileno()] = sock
        else:
            sock = socket.socket(
                    socket.AF_PACKET,
                    socket.SOCK_RAW,
                    socket.htons(self.ETH_P_ALL)
                )
            self.epoll.register(sock.fileno(), select.EPOLLIN)
            self.descriptor_to_socket[sock.fileno()] = sock

    def accept_packets(self):
        events = self.epoll.poll()
        t = time.time()
        for fileno, _ in events:
            sock = self.descriptor_to_socket[fileno]
            data, addr = sock.recvfrom(self.MAX_SIZE)

            self.packets.append((data, t))

    def recv(self) -> Tuple[bytes, float]:
        if not len(self.packets):
            self.accept_packets()
        data, t = self.packets.popleft()
        return data, t
