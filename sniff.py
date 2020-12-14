#!/usr/bin/env python3


from filters.filter_from_str import filter_from_str
from packets.visitors.first_verbosity_visitor import FirstVerbosityVisitor
from packets.visitors.second_verbosity_visitor import SecondVerbosityVisitor
from packets.visitors.zero_verbosity_visitor import ZeroVerbosityVisitor
from parsers.main_parser import get_parser
from dump_writers.empty_writer import EmptyWriter
from dump_writers.pcap_writer import PcapWriter
from output_writer.formatted_writer import FormattedWriter
from receivers.socket_receiver import SocketReceiver
from sniffer.sinffer import Sniffer


def main():
    parser = get_parser()

    args = parser.parse_args()
    args.verbosity = min(args.verbosity, 2)
    args.ifaces = list() if args.ifaces is None else args.ifaces
    path = args.dump_file

    verbosity_to_visitor = [
        ZeroVerbosityVisitor(),
        FirstVerbosityVisitor(),
        SecondVerbosityVisitor()
    ]

    try:
        filter_func = filter_from_str(args.filter)
    except ValueError as e:
        print(e)
        return

    try:
        if path is not None:
            dump_writer = PcapWriter(path, args.max_size)
        else:
            dump_writer = EmptyWriter()

        out_writer = FormattedWriter(
            verbosity_to_visitor[args.verbosity],
            args.time
        )
        receiver = SocketReceiver(*args.ifaces)
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

    sniffer = Sniffer(dump_writer, out_writer, receiver, filter_func)
    sniffer.start_sniffing()


if __name__ == '__main__':
    main()
