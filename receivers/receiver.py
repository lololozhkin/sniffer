from abc import ABC, abstractmethod
from typing import Tuple


class Receiver(ABC):
    @abstractmethod
    def recv(self) -> Tuple[bytes, float]:
        pass
