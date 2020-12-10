from abc import ABC, abstractmethod


class Receiver(ABC):
    @abstractmethod
    def recv(self, buf_size: int):
        pass
