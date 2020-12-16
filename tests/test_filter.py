from unittest import TestCase

from filters.filter_from_str import filter_from_str


class TestFilter(TestCase):
    def setUp(self) -> None:
        self.ether_ip_tcp = (
            b'\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00'
            b'\x00\x08\x00E\x00\x00(\x00\x01\x00\x00@\x06|'
            b'\xcd\x7f\x00\x00\x01\x7f\x00\x00\x01\x0594\x19'
            b'\x00\x00\x00\x00\x00\x00\x00\x00P\x02 \x00X\x8e\x00\x00'
        )

        self.ether_ip_udp = (
            b'\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00'
            b'\x00\x08\x00E\x00\x00\x1c\x00\x01\x00\x00@\x11'
            b'|\xce\x7f\x00\x00\x01\x7f\x00\x00\x01\x0594\x19'
            b'\x00\x08\xc8\x89'
        )

        self.ether_arp = (
            b'\x10\xfe\xed[\x854\xc4e\x16\xa0$\xfb\x08\x06'
            b'\x00\x01\x08\x00\x06\x04\x00\x01\xc4e\x16\xa0'
            b'$\xfb\xc0\xa8\x00k\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        )

    def testFilter_withProto_TCP(self):
        func = filter_from_str('proto == TCP')

        self.assertTrue(func(self.ether_ip_tcp))
        self.assertFalse(func(self.ether_ip_udp))
        self.assertFalse(func(self.ether_arp))

    def testFilter_withProto_IP(self):
        func = filter_from_str('proto == IP')

        self.assertTrue(func(self.ether_ip_tcp))
        self.assertTrue(func(self.ether_ip_udp))
        self.assertFalse(func(self.ether_arp))

    def testFilter_withProto_Ether(self):
        func = filter_from_str('proto == IP')

        self.assertTrue(func(self.ether_ip_tcp))
        self.assertTrue(func(self.ether_ip_udp))
        self.assertFalse(func(self.ether_arp))

    def testFilter_withProto_NonExistingProto(self):
        self.assertRaises(ValueError, filter_from_str, 'proto == lol')

    def testFilter_withFields_TCP_ports(self):
        func = filter_from_str('tcp.src_port == 1337')

        self.assertTrue(func(self.ether_ip_tcp))
        self.assertFalse(func(self.ether_ip_udp))
        self.assertFalse(func(self.ether_arp))

        func = filter_from_str('tcp.src_port == 1448')

        self.assertFalse(func(self.ether_ip_tcp))
        self.assertFalse(func(self.ether_ip_udp))
        self.assertFalse(func(self.ether_arp))

    def testFilter_withFields_TCP_flags(self):
        func = filter_from_str('tcp.syn == True')

        self.assertTrue(func(self.ether_ip_tcp))
        self.assertFalse(func(self.ether_ip_udp))
        self.assertFalse(func(self.ether_arp))

        func = filter_from_str('tcp.ack == True')

        self.assertFalse(func(self.ether_ip_tcp))
        self.assertFalse(func(self.ether_ip_udp))
        self.assertFalse(func(self.ether_arp))

    def testFilter_withFields_IP(self):
        func = filter_from_str('ip.src == 127.0.0.1')

        self.assertTrue(func(self.ether_ip_tcp))
        self.assertTrue(func(self.ether_ip_udp))
        self.assertFalse(func(self.ether_arp))

        func = filter_from_str('ip.dst == 1.2.3.4')

        self.assertFalse(func(self.ether_ip_tcp))
        self.assertFalse(func(self.ether_ip_udp))
        self.assertFalse(func(self.ether_arp))

    def testFilter_withFields_NonExistingFieldThrows(self):
        self.assertRaises(ValueError, filter_from_str, 'tcp.lol_flag == kek')

    def testFilter_totallyIncorrectFilter(self):
        self.assertRaises(ValueError, filter_from_str, 'tcp.....')
        self.assertRaises(ValueError, filter_from_str, 'wow ==== 10')
        self.assertRaises(ValueError, filter_from_str, 'udp.lol.kek == 14')
        self.assertRaises(ValueError, filter_from_str, 'bad_proto.lol == 11')
        self.assertRaises(ValueError, filter_from_str, 'bad_query == 12')

    def testFilter_ReturnsTrueWithoutArgs(self):
        func = filter_from_str()

        self.assertTrue(func(self.ether_ip_tcp))
        self.assertTrue(func(self.ether_ip_udp))
        self.assertTrue(func(self.ether_arp))

