import os
import struct

from dump_writers.dump_writer import DumpWriter
from composers.pcap_record_composer import PcapRecordComposer


class PcapWriter(DumpWriter):
    MAGIC_NUMBER = 0xa1b2c3d4
    MINOR_VERSION = 2
    MAJOR_VERSION = 4
    THIS_ZONE = 0
    SIG_FIGS = 0
    SNAP_LEN = 0x40000
    NETWORK = 1

    def __init__(self, file_path: str, max_size: int = -1):
        self.file_path = file_path
        self.max_size = max_size
        self.total_files = 0
        self.file = None

    @staticmethod
    def global_pcap_header():
        header = struct.pack(
            '<IHHIIII',
            PcapWriter.MAGIC_NUMBER,
            PcapWriter.MINOR_VERSION,
            PcapWriter.MAJOR_VERSION,
            PcapWriter.THIS_ZONE,
            PcapWriter.SIG_FIGS,
            PcapWriter.SNAP_LEN,
            PcapWriter.NETWORK
        )
        return header

    def write_data(self, data: bytes, time_in_seconds: float = 0.0):
        if self.file is None:
            raise ValueError('dumpfile is not set')
        
        composer = PcapRecordComposer(data, time_in_seconds)
        if self.max_size != -1 and self.max_size * 1024 <= self.file.tell():
            self.open_new_writer()

        self.file.write(composer.compose())

    def open_new_writer(self):
        d, file_name = os.path.split(self.file_path)
        if self.total_files > 0:
            file_name = file_name[:-len(str(self.total_files))]
        self.total_files += 1
        file_name += f'{self.total_files}'
        self.file_path = os.path.join(d, file_name)
        self.open_writer()

    def open_writer(self):
        self.file = open(self.file_path, 'wb')
        self.file.write(self.global_pcap_header())

    def close(self):
        self.file.close()

    def __enter__(self):
        self.open_writer()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
