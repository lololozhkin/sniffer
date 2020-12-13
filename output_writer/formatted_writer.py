import sys
import time
from typing import Union

from packets.ether import Ether
from packets.visitors.packetvisitor import PacketVisitor
from .output_writer import OutputWriter


class FormattedWriter(OutputWriter):
    def __init__(
            self,
            visitor: PacketVisitor,
            time_needed: bool = False,
            out=sys.stdout
    ):
        super().__init__(out)
        self.time_needed = time_needed
        self.visitor = visitor

    def write(self, data: Union[bytes, str], time_in_seconds: float = 0.0):
        if isinstance(data, bytes):
            packet = Ether(_pkt=data)
            parts = [
                layer.accept_visitor(self.visitor)
                for layer in packet.layers()
            ]
            parts = [
                layer for layer in parts if layer is not None and len(layer)
            ]

            out = '\n'.join(parts)
            if self.time_needed:
                out = f'{time_in_seconds * 10**6:.3f}: {out}'
            out += '\n'
            print(out, file=self.out)
        else:
            print(data, file=self.out)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False
