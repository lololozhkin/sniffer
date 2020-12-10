import socket

from dump_writers.dump_writer import DumpWriter
from output_writer.output_writer import OutputWriter


class Sniffer:
    ETH_P_ALL = 3

    def __init__(
            self,
            dump_writer: DumpWriter,
            output_writer: OutputWriter
    ):
        if dump_writer is None or output_writer is None:
            raise ValueError("One or more arguments were given as None")

        self.dump_writer = dump_writer
        self.out_writer = output_writer
        self.sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(Sniffer.ETH_P_ALL)
        )

        self.packets_captured = 0

    def start_sniffing(self):
        with self.dump_writer as dump, self.out_writer as out:
            try:
                while True:
                    data, _ = self.sock.recvfrom(5000)
                    self.packets_captured += 1
                    dump.write_data(data)
                    out.write(data)
            except KeyboardInterrupt:
                out.write(f'\n\nPackets captured: {self.packets_captured}')
