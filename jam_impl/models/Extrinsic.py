from dataclasses import dataclass
from jam_impl.models.extrinsic_components.Preimage import Preimage
from jam_impl.models.extrinsic_components.Guarantee import Guarantee
from jam_impl.models.extrinsic_components.Assurance import Assurance
from jam_impl.models.extrinsic_components.Disputes import Disputes
from jam_impl.models.extrinsic_components.Ticket import Ticket

@dataclass
class Extrinsic:
    assurances: list[Assurance] # Extrinsic assurances E_A
    tickets: list[Ticket]# Extrinsic Tickets E_T
    preimages: list[Preimage] # Extrinsic Preimages E_P
    guarantees: list[Guarantee] # Extrinsic Guarantees/Reports E_R
    disputes: Disputes # Extrinsic Disputes E_D