#!/usr/bin/env python3

import argparse

from dump_writers.pcap_writer import PcapWriter
from output_writer.formatted_writer import FormattedWriter
from receivers.socket_receiver import SocketReceiver
from sinffer import Sniffer


def main():
    parser = argparse.ArgumentParser(
        prog='Sniffer allows you to see all packets appeared '
             'in your network adapter and dump them to pcap format'
    )
    parser.add_argument(
        '-d',
        '--dump-file',
        help='Dump data to that file',
        type=str
    )

    args = parser.parse_args()
    path = args.dump_file

    dump_writer = PcapWriter(path)
    out_writer = FormattedWriter()
    receiver = SocketReceiver()

    sniffer = Sniffer(dump_writer, out_writer, receiver)
    sniffer.start_sniffing()


if __name__ == '__main__':
    main()
