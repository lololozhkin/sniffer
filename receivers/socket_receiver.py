import socket

from receivers.receiver import Receiver


class SocketReceiver(Receiver):
    ETH_P_ALL = 3

    def __init__(self):
        self.sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(self.ETH_P_ALL)
        )

    def recv(self, buf_size: int):
        data, addr = self.sock.recvfrom(buf_size)
        return data
