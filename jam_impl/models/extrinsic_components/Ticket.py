from dataclasses import dataclass

@dataclass
class Ticket:
    attempt: int
    signature: str