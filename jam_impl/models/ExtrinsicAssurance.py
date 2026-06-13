from dataclasses import dataclass

@dataclass
class ExtrinsicAssurance:
    anchor: str
    bitfield: str
    validator_index: int
    signature: str

    def encode(self):
        pass