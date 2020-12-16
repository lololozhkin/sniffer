from packets.arp import ARP
from packets.ip import IPv4
from packets.packet import Packet
from packets.ether import Ether
from packets.tcp import TCP
from packets.udp import UDP

str_proto_to_class = {
    "tcp": TCP,
    "udp": UDP,
    "arp": ARP,
    "eth": Ether,
    "ip": IPv4
}


def filter_for_proto(packet: Packet, proto: str):
    proto = proto.lower()
    return packet.has_layer(str_proto_to_class[proto.lower()])


def filter_for_attribute(packet: Packet, layer: str, attr: str, value: str):
    if not filter_for_proto(packet, layer):
        return False

    attr = attr.lower()
    layer = layer.lower()
    value = value.lower()

    layer = packet.get_layer(str_proto_to_class[layer.lower()])

    return str(layer.__dict__[attr]).lower() == value


def filter_from_str(str_filter: str = None):
    if str_filter is None:
        return lambda data: True

    if '==' in str_filter:
        if str_filter.count('==') != 1:
            raise ValueError(
                "Invalid filter syntax (== must be in filter once)"
            )
        left, right = str_filter.split('==')
        left = left.strip()
        right = right.strip()
        left_split = left.split('.')
        if len(left_split) == 1:
            if left_split[0] != 'proto':
                raise ValueError("Invalid field")
            else:
                if right.lower() not in str_proto_to_class:
                    raise ValueError("Invalid protocol")
                return lambda data: filter_for_proto(Ether(data), right)
        elif len(left_split) == 2:
            if left_split[0].lower() not in str_proto_to_class:
                raise ValueError("Invalid protocol")
            obj = str_proto_to_class[left_split[0].lower()]()
            if left_split[1] not in obj.__dict__:
                raise ValueError(
                    f"Invalid attr: {left_split[0]} "
                    f"doesn't has attribute {left_split[1]}"
                )
            return lambda data: filter_for_attribute(
                Ether(data),
                left_split[0],
                left_split[1],
                right
            )
        else:
            raise ValueError(
                "Invalid attribute. It must contain exactly one dot"
            )
    else:
        raise ValueError("Incorrect filter syntax (== must be in filter)")
