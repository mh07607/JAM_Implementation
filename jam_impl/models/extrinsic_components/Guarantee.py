from dataclasses import dataclass

@dataclass
class PackageSpec:
    hash: str
    length: int
    erasure_root: str
    exports_root: str
    exports_count: int

@dataclass
class Context:
    anchor: str
    state_root: str
    beefy_root: str
    lookup_anchor: str
    lookup_anchor_slot: int
    prerequisites: list  # adjust if a specific type is known

@dataclass
class ResultOk:
    ok: str  # hex-encoded data

@dataclass
class RefineLoad:
    gas_used: int
    imports: int
    extrinsic_count: int
    extrinsic_size: int
    exports: int

@dataclass
class ResultItem:
    service_id: int
    code_hash: str
    payload_hash: str
    accumulate_gas: int
    result: ResultOk
    refine_load: RefineLoad

@dataclass
class Report:
    package_spec: PackageSpec
    context: Context
    core_index: int
    authorizer_hash: str
    auth_gas_used: int
    auth_output: str
    segment_root_lookup: list  # adjust if needed
    results: list[ResultItem]

@dataclass
class Guarantee:
    report: Report