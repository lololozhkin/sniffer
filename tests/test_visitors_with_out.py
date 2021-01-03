import re
from io import StringIO
from unittest import TestCase

from output_writer.formatted_writer import FormattedWriter
from packets.raw import RAW
from packets.visitors.first_verbosity_visitor import FirstVerbosityVisitor
from packets.visitors.second_verbosity_visitor import SecondVerbosityVisitor
from packets.visitors.zero_verbosity_visitor import ZeroVerbosityVisitor


TCP_PACKET = (
    b"\xc4\x65\x16\xa0\x24\xfb\x10\xfe\xed\x5b\x85\x34\x08\x00\x45\xa4"
    b"\x00\x34\xbb\x1e\x00\x00\x79\x06\xc1\x1a\x23\xba\xe0\x19\xc0\xa8"
    b"\x00\x6b\x01\xbb\xcb\x8a\xdf\x4c\x63\xc4\x78\xb3\x84\xeb\x80\x10"
    b"\x04\x1a\x15\xb4\x00\x00\x01\x01\x08\x0a\x8a\x77\x69\x94\x82\xd3"
    b"\x13\x33"
)

UDP_PACKET = (
    b"\xff\xff\xff\xff\xff\xff\xc4\x65\x16\xa0\x24\xfb\x08\x00\x45\x00"
    b"\x00\x48\x9e\xee\x40\x00\x40\x11\x18\xfc\xc0\xa8\x00\x6b\xc0\xa8"
    b"\x00\xff\xe1\x15\xe1\x15\x00\x34\x83\x00\x53\x70\x6f\x74\x55\x64"
    b"\x70\x30\xd6\x29\x2f\xaa\x28\xa8\x39\x97\x00\x01\x00\x04\x48\x95"
    b"\xc2\x03\x52\x87\xd2\x69\x99\x70\xb6\x72\x8c\x78\x59\xe4\xc7\xf2"
    b"\x77\xef\x8c\x90\x56\x15"
)

ICMP_PACKET = (
    b"\xc4\x65\x16\xa0\x24\xfb\x10\xfe\xed\x5b\x85\x34\x08\x00\x45\xc0"
    b"\x00\x50\x63\x9d\x00\x00\x40\x01\x94\x93\xc0\xa8\x00\x01\xc0\xa8"
    b"\x00\x6b\x03\x00\xfd\xba\x00\x00\x00\x00\x45\x00\x00\x34\x13\xd4"
    b"\x40\x00\x40\x06\x26\x5c\xc0\xa8\x00\x6b\x5d\xba\xe1\xc6\x95\x6c"
    b"\x01\xbb\xd0\x2c\x71\x57\x24\xa2\xa5\xdf\x80\x10\x01\xf5\x88\xe4"
    b"\x00\x00\x01\x01\x08\x0a\xe8\xb9\x98\x6c\x08\x53\xbe\xa8"
)

ARP_PACKET = (
    b"\x18\x4f\x32\x3f\x29\x73\xc4\x65\x16\xa0\x24\xfb\x08\x06\x00\x01"
    b"\x08\x00\x06\x04\x00\x02\xc4\x65\x16\xa0\x24\xfb\xc0\xa8\x00\x6a"
    b"\x18\x4f\x32\x3f\x29\x73\xc0\xa8\x00\x66"
)


class ZeroVerbosityTests(TestCase):
    def setUp(self) -> None:
        self.visitor = ZeroVerbosityVisitor()
        self.out = StringIO()
        self.writer = FormattedWriter(self.visitor, True, self.out)

    def assertPorts(self, packet, port_amount):
        self.writer.write(packet)

        out = self.out.getvalue().strip()
        self.assertIn('IP', out)

        shown_ports = re.findall(
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d+)',
            out
        )
        self.assertEqual(port_amount, len(shown_ports))

    def testVisitor_PacketWithPorts_TCP(self):
        self.assertPorts(TCP_PACKET, 2)

    def testVisitor_PacketWithPorts_UDP(self):
        self.assertPorts(UDP_PACKET, 2)

    def testVisitor_PacketWithoutPorts(self):
        self.assertPorts(ICMP_PACKET, 0)

    def testVisitor_PacketIsNotIP(self):
        self.writer.write(ARP_PACKET)
        out = self.out.getvalue().strip()

        self.assertIn('ARP', out)
        self.assertNotIn('IP', out)


class BigVerbosityTestsMixin:
    def sequenceInStr(self, string, *seq):
        for word in seq:
            self.assertIn(word, string)

    def testVisitor_AllProtocolsAreWritten_TCP(self):
        self.writer.write(TCP_PACKET)
        out = self.out.getvalue().strip()
        self.sequenceInStr(out, 'Ethernet', 'IP', 'TCP')

    def testVisitor_AllProtocolsAreWritten_UDP(self):
        self.writer.write(UDP_PACKET)
        out = self.out.getvalue().strip()
        self.sequenceInStr(out, 'Ethernet', 'IP', 'UDP')

    def testVisitor_AllProtocolsAreWritten_RAW(self):
        self.writer.write(ICMP_PACKET)
        out = self.out.getvalue().strip()
        self.sequenceInStr(out, 'Ethernet', 'IP', 'RAW')

    def testVisitor_AllProtocolsAreWritten_ARP(self):
        self.writer.write(ARP_PACKET)
        out = self.out.getvalue().strip()
        self.sequenceInStr(out, 'Ethernet', 'ARP')


class FirstVerbosityTests(TestCase, BigVerbosityTestsMixin):
    def setUp(self) -> None:
        self.visitor = FirstVerbosityVisitor()
        self.out = StringIO()
        self.writer = FormattedWriter(self.visitor, True, self.out)


class SecondVerbosityTests(TestCase, BigVerbosityTestsMixin):
    def setUp(self) -> None:
        self.visitor = SecondVerbosityVisitor()
        self.out = StringIO()
        self.writer = FormattedWriter(self.visitor, True, self.out)

    def testVisitor_ShowRawInHexDump(self):
        packet = RAW(_pkt=b'abacabadabacaba')
        expected = 'RAW payload: \n00000000: 61 62 61 63 61 62 61 64  ' \
                   '61 62 61 63 61 62 61     abacabadabacaba'
        self.assertEqual(expected, packet.accept_visitor(self.visitor))
