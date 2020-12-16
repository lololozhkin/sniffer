from io import StringIO
from unittest import TestCase
from unittest.mock import Mock, patch

from output_writer.formatted_writer import FormattedWriter
from packets.visitors.packetvisitor import PacketVisitor


class TestOutputWriter(TestCase):
    def setUp(self) -> None:
        self.visitor = Mock(name='visitor', spec=PacketVisitor)
        self.out = StringIO()
        with patch('time.time') as time_mock:
            time_mock.return_value = 0.0
            self.writer = FormattedWriter(self.visitor, True, self.out)

    def testWriter_ContextManager(self):
        cont_manager = True
        try:
            with self.writer as w:
                pass
        except AttributeError:
            cont_manager = False

        self.assertTrue(cont_manager)

    def testWriter_WriteStr(self):
        str_info = 'very delicious packet'
        self.writer.write(str_info)
        self.assertEqual(str_info, self.out.getvalue().strip())

    def testWriter_WriteBytesOut_UsingVisitors(self):
        p = (
            b"\xc4\x65\x16\xa0\x24\xfb\x10\xfe\xed\x5b\x85\x34\x08\x00\x45\xa4"
            b"\x00\x34\xbb\x1e\x00\x00\x79\x06\xc1\x1a\x23\xba\xe0\x19\xc0\xa8"
            b"\x00\x6b\x01\xbb\xcb\x8a\xdf\x4c\x63\xc4\x78\xb3\x84\xeb\x80\x10"
            b"\x04\x1a\x15\xb4\x00\x00\x01\x01\x08\x0a\x8a\x77\x69\x94\x82\xd3"
            b"\x13\x33"
        )

        self.visitor.visit_ether.return_value = ''
        self.visitor.visit_ip.return_value = ''
        self.visitor.visit_tcp.return_value = ''
        self.visitor.visit_raw.return_value = ''

        self.writer.write(p)

        self.visitor.visit_ether.assert_called_once()
        self.visitor.visit_ip.assert_called_once()
        self.visitor.visit_tcp.assert_called_once()
        self.visitor.visit_raw.assert_called_once()
