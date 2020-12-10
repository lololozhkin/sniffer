from abc import ABC, abstractmethod
import os


class DumpWriter(ABC):
    def __init__(self, file_path: str = None):
        try:
            open(file_path, 'wb').close()
            self._file_path = file_path
        except Exception:
            raise

    @abstractmethod
    def write_data(self, data: bytes):
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

