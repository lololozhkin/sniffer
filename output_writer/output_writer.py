import sys
from abc import ABC, abstractmethod
from typing import Union


class OutputWriter(ABC):
    def __init__(self, out=sys.stdout):
        self.out = out

    @abstractmethod
    def write(self, data: Union[bytes, str]):
        pass

    @abstractmethod
    def __enter__(self):
        pass

    @abstractmethod
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
