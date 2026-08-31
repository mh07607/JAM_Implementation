from dataclasses import dataclass

@dataclass
class Header: # H
    parent_header_hash: str # parent header? hash H_P
    prior_state_root: str # prior state root H_R
    extrinsic_hash: str # extrinsic hash H_X
    timeslot_index: int # timeslot index H_T
    epoch_marker: str | None # epoch_marker H_E
    winning_tickets_marker: str | None # Winning Tickets H_W
    offenders_marker: list[str] # Offenders Markers H_O
    author_index: int # Block Author Index H_I
    entropy_yielding_vrf_signature: str # Entropy-yielding VRF signature H_V
    block_seal: str # Block seal H_S