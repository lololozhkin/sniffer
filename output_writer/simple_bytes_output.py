import sys
from typing import Union

from output_writer.output_writer import OutputWriter


class BytesOutput(OutputWriter):
    def __init__(self, file=sys.stdout):
        self.out = file

    def write(self, data: Union[bytes, str]):
        print(data, file=self.out)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False
