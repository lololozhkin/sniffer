from io import StringIO
from unittest import TestCase
from unittest.mock import Mock, patch

from dump_writers.empty_writer import EmptyWriter
from dump_writers.pcap_writer import PcapWriter


class TestDumpWriter(TestCase):
    def setUp(self) -> None:
        self.bytes_out = []
        self.dump_writer = PcapWriter('')

    @patch("builtins.open")
    def testDumpWriter_ContextManagerIsWorking(self, open_mock):
        file_mock = Mock()
        open_mock.return_value = file_mock
        with self.dump_writer as _:
            pass
        file_mock.write.assert_called_once()
        file_mock.close.assert_called_once()

    @patch("builtins.open")
    def testDumpWriter_GlobalPcapHeaderIsWritten(self, open_mock):
        file_mock = Mock()
        open_mock.return_value = file_mock
        self.dump_writer.open_writer()
        file_mock.write.assert_called_once()
        file_mock.write.assert_called_with(PcapWriter.global_pcap_header())

    @patch("composers.pcap_record_composer.PcapRecordComposer.compose")
    @patch("builtins.open")
    def testDumpWriter_dataIsWritten(self, open_mock, compose_mock):
        file_mock = Mock()
        open_mock.return_value = file_mock

        packet = b'abacabadabacaba'
        compose_mock.return_value = packet
        with self.dump_writer as w:
            w.write_data(packet)

        file_mock.write.assert_called_with(packet)
        compose_mock.assert_called_once()

    @patch("builtins.open")
    def testDumpWriter_NewFileCreatedWhenSizeReached(self, open_mock):
        first_packet = b'abacaba'
        second_packet = b'dabacaba'
        file_mock = Mock()
        open_mock.return_value = file_mock
        file_mock.tell.side_effect = [
            len(first_packet) * 1024,
            len(second_packet) * 1024
        ]
        self.dump_writer = PcapWriter('file', 1)
        with self.dump_writer as w:
            w.write_data(first_packet)
            open_mock.assert_called_with('file.1.pcap', 'wb')

            w.write_data(second_packet)
            open_mock.assert_called_with('file.2.pcap', 'wb')

    def testDumpWriter_ThrowsIfFileIsNotSet(self):
        self.assertRaises(ValueError, self.dump_writer.write_data, 'abacaba')

    def testEmptyWriter_DoesNothing(self):
        writer = EmptyWriter()
        self.assertIsNone(writer.write_data(b'abacaba'))
        self.assertIsNone(writer.open_writer())
        self.assertIsNone(writer.close())

        is_cont_manager = True
        try:
            with writer as w:
                pass
        except AttributeError:
            is_cont_manager = False

        self.assertTrue(is_cont_manager)
