from dump_writers.dump_writer import DumpWriter


class EmptyWriter(DumpWriter):
    def write_data(self, data: bytes, time_in_seconds: float = 0.0):
        pass

    def open_writer(self):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return True
