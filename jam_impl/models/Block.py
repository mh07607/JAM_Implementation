from dataclasses import dataclass

from jam_impl.models import Extrinsic, Header

@dataclass
class Block:
    header: Header
    extrinsic: Extrinsic