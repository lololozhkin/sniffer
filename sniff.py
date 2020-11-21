#!/usr/bin/env python3

import argparse
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
    sniffer = Sniffer(args.dump_file)
    sniffer.start_sniffing()


if __name__ == '__main__':
    main()
