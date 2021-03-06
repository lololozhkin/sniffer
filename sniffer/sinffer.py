from typing import Callable

from dump_writers.dump_writer import DumpWriter
from output_writer.output_writer import OutputWriter
from receivers.receiver import Receiver


class Sniffer:
    def __init__(
            self,
            dump_writer: DumpWriter,
            output_writer: OutputWriter,
            receiver: Receiver,
            filter_func: Callable[[bytes], bool]
    ):
        for arg in (dump_writer, output_writer, receiver, filter_func):
            if arg is None:
                ValueError("One or more arguments were given as None")

        self.dump_writer = dump_writer
        self.out_writer = output_writer
        self.receiver = receiver
        self.filter_func = filter_func
        self.packets_captured = 0

    def start_sniffing(self):
        with self.dump_writer as dump, self.out_writer as out:
            try:
                while True:
                    data, t = self.receiver.recv()
                    if self.filter_func(data):
                        self.packets_captured += 1
                        dump.write_data(data, t)
                        out.write(data, t)
            except KeyboardInterrupt:
                out.write(f'\n\nPackets captured: {self.packets_captured}')
