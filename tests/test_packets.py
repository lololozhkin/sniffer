from packets.arp import ARP
from packets.ip import IPv4
from unittest import TestCase

from packets.ether import Ether
from packets.tcp import TCP
from packets.udp import UDP


class TestPackets(TestCase):
    def testEtherFields(self):
        packet = b'\xa1\xb2\xc3\xd4\xe5\xf6\xf6\xe5\xd4\xc3\xb2\xa1\x90\x00'
        e = Ether(_pkt=packet)
        self.assertEqual('a1:b2:c3:d4:e5:f6', e.src)
        self.assertEqual('f6:e5:d4:c3:b2:a1', e.dst)
        e = Ether(
            src_mac='a1:b2:c3:d4:e5:f6',
            dst_mac='f6:e5:d4:c3:b2:a1',
            typ=0x9000
        )
        self.assertEqual(packet, e.build())

    def testIPFields(self):
        packet = (
            b'E\x00\x00\x14\x00\x01\x00\x00\x19\x00\x1f'
            b'\xb4\xc0\xa8\x00\xe4\xc0\xa8\x00\x01'
        )
        p = IPv4(_pkt=packet)
        self.assertEqual('192.168.0.228', p.src)
        self.assertEqual('192.168.0.1', p.dst)
        self.assertEqual(25, p.ttl)
        self.assertEqual(1, p.id)

        p = IPv4(
            header_len=5,
            packet_len=20,
            ip_id=1,
            ttl=25,
            checksum=8116,
            ip_src='192.168.0.228',
            ip_dst='192.168.0.1'
        )

        self.assertEqual(packet, p.build())

    def testTCPFields(self):
        packet = (
            b'\x0594\x19\x00\x00\x01A\x00\x00\x00{P\x02 \x00\x00\x00\x00\x00'
        )
        t = TCP(_pkt=packet)

        self.assertEqual(1337, t.src_port)
        self.assertEqual(13337, t.dst_port)
        self.assertEqual(321, t.seq_num)
        self.assertEqual(123, t.ack_num)
        self.assertEqual('SYN', ''.join(t.str_flags()))

        t = TCP(
            src_port=1337,
            dst_port=13337,
            seq_num=321,
            ack_num=123,
            flags=2,
            data_offset=5,
            window_size=8192
        )
        self.assertEqual(packet, t.build())

    def testUDPFields(self):
        packet = (
            b'\x05\xa88p\x00\x08\x00\x00'
        )
        u = UDP(_pkt=packet)

        self.assertEqual(1448, u.src_port)
        self.assertEqual(14448, u.dst_port)

        u = UDP(src_port=1448, dst_port=14448)
        self.assertEqual(packet, u.build())

    def testARPFields(self):
        packet = (
            b'\x00\x01\x08\x00\x06\x04\x00\x01\xc4e\x16\xa0$\xfb\xc0'
            b'\xa8\x00k\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        )
        a = ARP(_pkt=packet)

        self.assertEqual('c4:65:16:a0:24:fb', a.h_src)
        self.assertEqual('192.168.0.107', a.p_src)
        self.assertEqual('00:00:00:00:00:00', a.h_dst)
        self.assertEqual('0.0.0.0', a.p_dst)

        a = ARP(
            h_src='c4:65:16:a0:24:fb',
            p_src='192.168.0.107',
            h_dst='00:00:00:00:00:00',
            p_dst='0.0.0.0'
        )
        self.assertEqual(packet, a.build())

    def testLayers_HasLayer(self):
        packet = (
            b"\xc4\x65\x16\xa0\x24\xfb\x10\xfe\xed\x5b\x85\x34\x08\x00\x45\xa4"
            b"\x00\x34\xbb\x1e\x00\x00\x79\x06\xc1\x1a\x23\xba\xe0\x19\xc0\xa8"
            b"\x00\x6b\x01\xbb\xcb\x8a\xdf\x4c\x63\xc4\x78\xb3\x84\xeb\x80\x10"
            b"\x04\x1a\x15\xb4\x00\x00\x01\x01\x08\x0a\x8a\x77\x69\x94\x82\xd3"
            b"\x13\x33"
        )
        e = Ether(_pkt=packet)
        self.assertTrue(e.has_layer(Ether))
        self.assertTrue(e.has_layer(IPv4))
        self.assertTrue(e.has_layer(TCP))

    def testLayers_GetLayer(self):
        packet = (
            b"\xff\xff\xff\xff\xff\xff\xc4\x65\x16\xa0\x24\xfb\x08\x00\x45\x00"
            b"\x00\x48\x9e\xee\x40\x00\x40\x11\x18\xfc\xc0\xa8\x00\x6b\xc0\xa8"
            b"\x00\xff\xe1\x15\xe1\x15\x00\x34\x83\x00\x53\x70\x6f\x74\x55\x64"
            b"\x70\x30\xd6\x29\x2f\xaa\x28\xa8\x39\x97\x00\x01\x00\x04\x48\x95"
            b"\xc2\x03\x52\x87\xd2\x69\x99\x70\xb6\x72\x8c\x78\x59\xe4\xc7\xf2"
            b"\x77\xef\x8c\x90\x56\x15"
        )
        e = Ether(_pkt=packet)

        self.assertTrue(isinstance(e.get_layer(UDP), UDP))
        self.assertIsNone(e.get_layer(TCP))
