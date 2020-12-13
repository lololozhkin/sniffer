from abc import ABC, abstractmethod


class DumpWriter(ABC):
    @abstractmethod
    def write_data(self, data: bytes, time_in_seconds: float = 0.0):
        pass

    @abstractmethod
    def open_writer(self):
        pass

    @abstractmethod
    def close(self):
        pass

    @abstractmethod
    def __enter__(self):
        pass

    @abstractmethod
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
