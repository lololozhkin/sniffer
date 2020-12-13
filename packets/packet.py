from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from packets.visitors.packetvisitor import PacketVisitor


class Packet(ABC):
    @abstractmethod
    def get_next_layer(self):
        pass

    @abstractmethod
    def build(self):
        pass

    @abstractmethod
    def accept_visitor(self, visitor: 'PacketVisitor'):
        pass

    def layers(self):
        layers = [self]
        while layers[-1]:
            layers.append(layers[-1].get_next_layer())

        return layers[:-1]

    def has_layer(self, layer: type) -> bool:
        return any(isinstance(lay, layer) for lay in self.layers())

    def get_layer(self, layer: type):
        for lay in self.layers():
            if isinstance(lay, layer):
                return lay
