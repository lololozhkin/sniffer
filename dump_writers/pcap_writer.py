import struct
import time

from dump_writers.dump_writer import DumpWriter
from pcap_record_composer import PcapRecordComposer


class PcapWriter(DumpWriter):
    MAGIC_NUMBER = 0xa1b2c3d4
    MINOR_VERSION = 2
    MAJOR_VERSION = 4
    THIS_ZONE = 0
    SIG_FIGS = 0
    SNAP_LEN = 0x40000
    NETWORK = 1

    def __init__(self, file_path=None):
        super().__init__(file_path)
        self._file = None

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

    def write_data(self, data: bytes):
        t = time.time()

        if self._file is not None:
            composer = PcapRecordComposer(data, t)
            self._file.write(composer.compose())
        else:
            raise ValueError("Writer is not opened")

    def open_writer(self):
        if self._file_path is not None:
            self._file = open(self._file_path, 'wb')
            self._file.write(self.global_pcap_header())
        else:
            raise ValueError("Dumpfile is not set")

    def close(self):
        if self._file is None:
            raise ValueError("File is not set")

        self._file.close()

    def __enter__(self):
        self.open_writer()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
