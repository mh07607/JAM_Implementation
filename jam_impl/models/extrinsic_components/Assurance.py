from dataclasses import dataclass

@dataclass
class Assurance:
    anchor: str
    bitfield: str
    validator_index: int
    signature: str

    def encode(self):
        pass