from abc import ABC, abstractmethod
from typing import Tuple

from packets.packet import Packet


class Receiver(ABC):
    @abstractmethod
    def recv(self) -> Tuple[bytes, float]:
        pass
