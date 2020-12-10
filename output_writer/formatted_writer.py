from typing import Union

from scapy.layers.inet import Ether
from .output_writer import OutputWriter


class FormattedWriter(OutputWriter):
    def write(self, data: Union[bytes, str]):
        if isinstance(data, bytes):
            packet = Ether(_pkt=data)
            print(packet.summary(), file=self.out)
        else:
            print(data, file=self.out)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False
