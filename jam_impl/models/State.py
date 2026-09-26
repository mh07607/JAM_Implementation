from dataclasses import dataclass

@dataclass
class ServiceDefinitionDataService:
    version: int
    code_hash: bytes
    balance: int
    min_item_gas: int
    min_memo_gas: int
    bytes_count: int
    deposit_offset: int
    items: int
    creation_slot: int
    last_accumulation_slot: int
    parent_service: int

@dataclass
class ServiceDefinitionData:
    service: ServiceDefinitionDataService

@dataclass
class ServiceDefinition:
    service_index: int
    data: ServiceDefinitionData

class AuthorizationQueue:
    pass

class RecentHistory:
    pass

class SafroleState:
    pass

class Disputes:
    pass

class EntropyAccumulator:
    pass

class UpcomingValidators:
    pass

class CurrentValidators:
    pass

class PreviousValidators:
    pass

class AvailabilityAssignments:
    pass

@dataclass
class State:
    pass
