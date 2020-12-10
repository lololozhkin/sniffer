from typing import Union

from output_writer.output_writer import OutputWriter


class OutNothing(OutputWriter):
    def write(self, data: Union[bytes, str]):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False
