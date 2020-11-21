import socket
import struct
import sys
import time

from pcap_record_composer import PcapRecordComposer

ETH_P_ALL = 3
MAGIC_NUMBER = 0xa1b2c3d4
MINOR_VERSION = 2
MAJOR_VERSION = 4
THIS_ZONE = 0
SIG_FIGS = 0
SNAP_LEN = 0x40000
NETWORK = 1


def global_header():
    header = struct.pack(
        '<IHHIIII',
        MAGIC_NUMBER,
        MINOR_VERSION,
        MAJOR_VERSION,
        THIS_ZONE,
        SIG_FIGS,
        SNAP_LEN,
        NETWORK
    )
    return header


class Sniffer:
    def __init__(self, dump_file=None):
        if dump_file is None:
            self.dump_file = sys.stdout
        else:
            self.dump_file = open(dump_file, 'wb')
        self.sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(ETH_P_ALL)
        )

    def start_sniffing(self):
        self.dump_file.write(global_header())
        while True:
            data, addr = self.sock.recvfrom(5000)
            if self.dump_file == sys.stdout:
                print(data)
                continue

            print(data)
            t = time.time()
            seconds = int(t)
            microseconds = int((t - seconds) * 1000)
            composer = PcapRecordComposer(data, seconds, microseconds)
            self.dump_file.write(composer.compose())
