#!/usr/bin/env python3

import argparse

from dump_writers.pcap_writer import PcapWriter
from output_writer.simple_bytes_output import BytesOutput
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
    out_writer = BytesOutput()
    sniffer = Sniffer(dump_writer, out_writer)
    sniffer.start_sniffing()


if __name__ == '__main__':
    main()
