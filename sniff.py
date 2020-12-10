#!/usr/bin/env python3

import argparse

from dump_writers.empty_writer import EmptyWriter
from dump_writers.pcap_writer import PcapWriter
from output_writer.formatted_writer import FormattedWriter
from receivers.socket_receiver import SocketReceiver
from sniffer.sinffer import Sniffer


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

    try:
        if path is not None:
            file = open(path, 'wb')
            dump_writer = PcapWriter(file)
        else:
            dump_writer = EmptyWriter()

        out_writer = FormattedWriter()
        receiver = SocketReceiver()
    except FileNotFoundError:
        print(f'File {args.dump_file} is not found or could not be created')
        return
    except PermissionError:
        print(
            f'Permission error. '
            f'You need to use root privileges to run the program'
        )
        return
    except ValueError as e:
        print(e)
        return

    sniffer = Sniffer(dump_writer, out_writer, receiver)
    sniffer.start_sniffing()


if __name__ == '__main__':
    main()
