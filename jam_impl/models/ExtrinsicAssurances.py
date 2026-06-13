from dataclasses import dataclass
from typing import List
from ExtrinsicAssurance import ExtrinsicAssurance

@dataclass
class ExtrinsicAssurances:
    assurances: List[ExtrinsicAssurance]