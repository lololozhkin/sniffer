import argparse


def get_parser():
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
    parser.add_argument(
        '-m',
        '--max-size',
        help='If current size of dump file is more then max size parameter, '
             'new file will be created with name, '
             'using total files per this session. '
             'If dump file is not set, this parameter will be ignored. '
             'If you want to write all information in one file, '
             'set this parameter to -1. By default it is equal -1',
        type=int,
        default=-1
    )
    parser.add_argument(
        '-v',
        '--verbosity',
        help='Verbosity level increases every time flag appeared in command. '
             'Maximal verbosity level is 2, by default it is 0',
        action='count',
        default=0
    )
    parser.add_argument(
        '-t',
        '--time',
        help='Use this flag if you need to see time when packet comes. '
             'Time is shown in microseconds',
        action='store_true',
    )
    parser.add_argument(
        '-i',
        '--ifaces',
        help='By default, this program will sniff packets at all interfaces. '
             'If you want to specify only needed interfaces, '
             'use this parameter',
        nargs='+',
        type=str
    )
    parser.add_argument(
        '-f',
        '--filter',
        help="Simple filter, using noe field of packet's protocol. "
             "Format is written in readme. For example: TCP.src_port == 1337",
        type=str,
        default=None
    )

    return parser
