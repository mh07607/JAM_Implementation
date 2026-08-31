from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Union

# --- Common Types ---
Hash = str  # Represented as hex strings '0x...'
Bytes = str  # Represented as hex strings '0x...'
ServiceId = int
Timeslot = int
CoreIndex = int
ValidatorIndex = int

@dataclass
class ServiceAccount:
    """
    Corresponds to the service account tuple A in Section 9 of the Graypaper:
    A = (s, p, l, f, c, b, g, m, r, a, p)
    """
    storage: Dict[Bytes, Bytes] = field(default_factory=dict)  # s: general key-value storage
    preimages: Dict[Hash, Bytes] = field(default_factory=dict)  # p: preimage lookup dictionary
    preimage_metadata: Dict[Tuple[Hash, int], List[Timeslot]] = field(default_factory=dict)  # l: preimage tracking map (requested/available timeslots)
    gratis_offset: int = 0  # f: gratis storage allowance offset (in tokens)
    code_hash: Hash = "0x" + "00" * 32  # c: PVM code hash
    balance: int = 0  # b: token balance
    gas_limit_refine: int = 0  # g: gas limit per refine step
    gas_limit_accumulate: int = 0  # m: gas limit per accumulate step
    created_at: Timeslot = 0  # r: timeslot of creation
    last_accumulated: Timeslot = 0  # a: timeslot of last accumulation
    parent_service: ServiceId = 0  # p: parent service index

@dataclass
class RecentBlockInfo:
    """
    Corresponds to the elements of β_H (Section 7):
    (h, s, b, t, p)
    """
    header_hash: Hash
    state_root: Hash
    accumulation_result_mmb: Hash
    timeslot: Timeslot
    reported_packages: Dict[CoreIndex, Hash]  # Map of core index to work-package hash

@dataclass
class RecentHistoryState:
    """
    Corresponds to β (Section 7):
    β = (β_H, β_B)
    """
    blocks: List[RecentBlockInfo] = field(default_factory=list)  # β_H
    accumulation_output_log: List[Hash] = field(default_factory=list)  # β_B: Merkle mountain range peaks

@dataclass
class SafroleState:
    """
    Corresponds to γ (Section 6.2):
    γ = (γ_P, γ_Z, γ_S, γ_A)
    """
    pending_keys: List[Bytes] = field(default_factory=list)  # γ_P: pending keys for next epoch
    epoch_root: Hash = "0x" + "00" * 32  # γ_Z: Bandersnatch ring root
    slot_sealers: List[Union[Hash, Bytes]] = field(default_factory=list)  # γ_S: current epoch slot sealers (tickets or fallback keys)
    ticket_accumulator: List[Tuple[Hash, int]] = field(default_factory=list)  # γ_A: high-scoring tickets (y, e) for the next epoch

@dataclass
class DisputesState:
    """
    Corresponds to ψ (Section 10.1):
    ψ = (ψ_G, ψ_B, ψ_W, ψ_O)
    """
    good_set: Set[Hash] = field(default_factory=set)  # ψ_G: correct work-reports
    bad_set: Set[Hash] = field(default_factory=set)  # ψ_B: incorrect work-reports
    wonky_set: Set[Hash] = field(default_factory=set)  # ψ_W: unjudgable work-reports
    punish_set: Set[Bytes] = field(default_factory=set)  # ψ_O: misbehaving validator keys (Ed25519)

@dataclass
class WorkPackageSpec:
    hash: Hash
    length: int
    erasure_root: Hash
    exports_root: Hash
    exports_count: int

@dataclass
class RefinementContext:
    anchor: Hash
    state_root: Hash
    beefy_root: Hash
    lookup_anchor: Hash
    lookup_anchor_slot: Timeslot
    prerequisites: List[Hash]

@dataclass
class RefineLoad:
    gas_used: int
    imports: int
    extrinsic_count: int
    extrinsic_size: int
    exports: int

@dataclass
class WorkItemResult:
    service_id: ServiceId
    code_hash: Hash
    payload_hash: Hash
    accumulate_gas: int
    result: Dict[str, Bytes]  # e.g., {"ok": "0x..."} or {"err": "0x..."}
    refine_load: RefineLoad

@dataclass
class WorkReport:
    """
    Corresponds to report R (Section 11.1)
    """
    package_spec: WorkPackageSpec
    context: RefinementContext
    core_index: CoreIndex
    authorizer_hash: Hash
    auth_gas_used: int
    auth_output: Bytes
    segment_root_lookup: List[Hash]
    results: List[WorkItemResult]

@dataclass
class QueueItem:
    """
    An entry in the ready_queue (ω)
    """
    report: WorkReport
    dependencies: List[Hash]

@dataclass
class AvailabilityAssignment:
    """
    Corresponds to ρ (Section 11.1)
    """
    report: WorkReport
    reported_at: Timeslot

@dataclass
class PrivilegedServices:
    """
    Corresponds to χ (Section 9.4):
    χ = (χ_M, χ_V, χ_R, χ_A, χ_Z)
    """
    blessed: ServiceId = 0  # χ_M
    designate: ServiceId = 0  # χ_V
    registrar: ServiceId = 0  # χ_R
    authorizer_managers: List[ServiceId] = field(default_factory=list)  # χ_A
    always_accumulate: Dict[ServiceId, int] = field(default_factory=dict)  # χ_Z: service_id -> basic gas limit

@dataclass
class ValidatorStats:
    blocks_produced: int = 0  # b
    tickets_introduced: int = 0  # t
    preimages_introduced: int = 0  # p
    preimage_octets: int = 0  # d
    reports_guaranteed: int = 0  # g
    availability_assurances: int = 0  # a

@dataclass
class GlobalState:
    """
    The complete global State tuple σ of the Join-Accumulate Machine (JAM).
    σ = (α, β, θ, γ, δ, η, ι, κ, λ, ρ, τ, ϕ, χ, ψ, π, ω, ξ)
    """
    # Core States
    authorizations: List[List[Hash]] = field(default_factory=list)  # α: Core authorizations pool
    authorization_queues: List[List[Hash]] = field(default_factory=list)  # ϕ: Core authorizations queue
    availability_assignments: Dict[CoreIndex, Optional[AvailabilityAssignment]] = field(default_factory=dict)  # ρ: Core availability assignments

    # History & Logs
    history: RecentHistoryState = field(default_factory=RecentHistoryState)  # β: Recent blocks and outputs log
    latest_accumulation_outputs: List[Tuple[ServiceId, Hash]] = field(default_factory=list)  # θ: Most recent Accumulation outputs log

    # Consensus & Validator Keys
    safrole: SafroleState = field(default_factory=SafroleState)  # γ: Safrole consensus state
    entropy: List[Hash] = field(default_factory=list)  # η: Randomness/entropy pool accumulator (history of 4)
    validator_queue: List[Bytes] = field(default_factory=list)  # ι: Validator keys enqueued for next-next epoch
    validator_current: List[Bytes] = field(default_factory=list)  # κ: Currently active validator keys
    validator_prior: List[Bytes] = field(default_factory=list)  # λ: Validator keys active in previous epoch
    validator_stats: Dict[ValidatorIndex, ValidatorStats] = field(default_factory=dict)  # π: Per-epoch validator metrics

    # Services
    services: Dict[ServiceId, ServiceAccount] = field(default_factory=dict)  # δ: Stateful service account map
    privileges: PrivilegedServices = field(default_factory=PrivilegedServices)  # χ: Service privilege map

    # Queue & Progress
    timeslot: Timeslot = 0  # τ: Timeslot index of the most recent block
    disputes: DisputesState = field(default_factory=DisputesState)  # ψ: Dispute verification & punishment sets
    ready_queue: List[List[QueueItem]] = field(default_factory=list)  # ω: Ready but not-yet-accumulated reports (one per core slot)
    accumulated_history: List[Set[Hash]] = field(default_factory=list)  # ξ: Work-packages accumulated over current epoch slots
