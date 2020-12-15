import unittest
from io import StringIO
from unittest import mock

from dump_writers.dump_writer import DumpWriter
from output_writer.output_writer import OutputWriter
from receivers.receiver import Receiver
from sniffer.sinffer import Sniffer


class TestSniffer(unittest.TestCase):
    def setUp(self) -> None:
        self.dump_mock = mock.Mock(spec=DumpWriter)
        self.dump_bytes = []

        self.receiver_mock = mock.Mock(spec=Receiver)
        self.recv_packets = []
        self.recv_packets_pointer = 0

        self.writer_mock = mock.Mock(spec=OutputWriter)

        self.configure_receiver_mock()
        self.configure_dump_mock()
        self.configure_writer_mock()

        self.sniffer = Sniffer(
            self.dump_mock,
            self.writer_mock,
            self.receiver_mock,
            lambda data: True
        )

    def configure_dump_mock(self):
        self.dump_mock = mock.Mock(spec=DumpWriter)
        self.dump_bytes = []

        def write(data, t):
            self.dump_bytes.append(data)

        self.dump_mock.write_data.side_effect = write
        self.dump_mock.__enter__ = mock.Mock(return_value=self.dump_mock)
        self.dump_mock.__exit__ = mock.Mock(return_value=False)

    def configure_receiver_mock(self):
        self.receiver_mock = mock.Mock(spec=Receiver)
        self.recv_packets = []
        self.recv_packets_pointer = 0

        def recv():
            if self.recv_packets_pointer >= len(self.recv_packets):
                raise KeyboardInterrupt
            ans = self.recv_packets[self.recv_packets_pointer]
            self.recv_packets_pointer += 1
            return ans, 0

        self.receiver_mock.recv = mock.Mock(side_effect=recv)

    def configure_writer_mock(self):
        self.writer_mock = mock.Mock(spec=OutputWriter)
        self.writer_mock.__enter__ = mock.Mock(return_value=self.writer_mock)
        self.writer_mock.__exit__ = mock.Mock(return_value=False)

    def testPacketCounter_FilteredAllPackets(self):
        self.recv_packets = [b'abacaba', b'd', b'abacaba']
        self.sniffer.start_sniffing()
        self.assertEqual(len(self.recv_packets), self.sniffer.packets_captured)

    def testSniffer_PacketsAreWrittenOut(self):
        self.recv_packets = [b'abacaba']
        self.sniffer.start_sniffing()
        self.assertEqual(2, self.writer_mock.write.call_count)

    def testSniffer_PacketsAreDumped(self):
        self.recv_packets = [b'typical packet']
        self.sniffer.start_sniffing()
        self.dump_mock.write_data.assert_called_once()

    def testSniffer_NotFilteredPacketsAreNotDumped(self):
        self.sniffer.filter_func = lambda packet: False
        self.recv_packets = [b'packet', b'other', b'another one']
        self.sniffer.start_sniffing()
        self.dump_mock.write_data.assert_not_called()

    def testSniffer_NotFilteredPacketsAreNotWrittenOut(self):
        self.sniffer.filter_func = lambda packet: False
        self.recv_packets = [b'love sniffing', b'very much']
        self.sniffer.start_sniffing()
        self.writer_mock.write.assert_called_once()


