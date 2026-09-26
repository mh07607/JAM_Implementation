import jam_impl.util as util
from jam_impl.util import Decoder, Encoder
from jam_impl.codec.header_codec import spec_globals
from jam_impl.codec.extrinsic_codec import decode_report
from jam_impl.models.State import (
    ServiceDefinition, ServiceDefinitionData, ServiceDefinitionDataService
)
from collections.abc import Callable
from dataclasses import dataclass
from tqdm import tqdm

AUTHORIZATION_QUEUE_LENGTH = 80
RECENT_HISTORY_LENGTH = 8
TICKET_ENTRY_PER_VALIDATOR_COUNT = 2
VALIDATORS_PER_CORE = 3

#Helpers
class StrictSet(set):
    def __init__(self, iterable=None):
        if iterable is not None:
            for item in iterable:
                self.add(item)

    def add(self, item):
        if item in self:
            raise ValueError(f"Duplicate item found: {item!r}")
        super().add(item)

def decode_validator_list(d: Decoder) -> list[dict]:
    validators = []
    for _ in range(util.NUM_VALIDATORS_IN_EPOCH_MARK):
        # This is a set, there should be no duplicates here
        # TODO: Have a duplicate check here        
        validators.append({
            "bandersnatch": d.hash32().hex(),
            "ed25519": d.hash32().hex(),
            "bls": d.take(144).hex(),
            "metadata": d.take(128).hex()
        })
    return validators

def decode_validators_statistics(d: Decoder) -> list[dict]:
    return [
        {
            "num_blocks_produced": d.u32(),
            "num_tickets_introduced": d.u32(),
            "num_preimages_introduced": d.u32(),
            "num_octets_introduced": d.u32(),
            "num_reports_guaranteed": d.u32(),
            "num_availability_assurances": d.u32()
        }
        for _ in range(util.NUM_VALIDATORS_IN_EPOCH_MARK)
    ]

# state component decoders
def decode_authorization_pool(b :bytes) -> tuple[str, bytes]:
    # TODO make core_count a variable inside util so that it can be used in multiple places
    core_count = util.NUM_VALIDATORS_IN_EPOCH_MARK // VALIDATORS_PER_CORE
    d = Decoder(b)
    pools = []
    for _ in range(core_count):     
        pool_length = d.decode_compact()              
        pools.append([d.hash32().hex() for _ in range(pool_length)])        
    d.finish()

def decode_authorization_queue(b :bytes) -> tuple[str, bytes]:    
    core_count = util.NUM_VALIDATORS_IN_EPOCH_MARK // VALIDATORS_PER_CORE
    d = Decoder(b)
    queues = []
    for _ in range(core_count):
        queues.append([d.hash32().hex() for _ in range(AUTHORIZATION_QUEUE_LENGTH)])    
    d.finish()

def decode_recent_history(b :bytes) -> tuple[str, bytes]:
    d = Decoder(b)
    block_count = d.u8()
    for _ in range(block_count):
        header_hash, accumulation_result, state_root = d.hash32().hex(), d.hash32().hex(), d.hash32().hex()
        n = d.decode_compact()
        work_package_hashes = [ {"key": d.hash32().hex(), "value": d.hash32().hex() } for _ in range (n) ]
    # mmr encoding for Beta_B    
    n = d.decode_compact()
    accumulation_output_log = []
    for _ in range(n):
        if( d.u8() == 1 ):
            accumulation_output_log.append(d.hash32().hex())
        else:
            accumulation_output_log.append(None)
    accumulation_output_log = { "peaks": accumulation_output_log }
    d.finish()

def decode_safrole_state(b: bytes) -> tuple[str, bytes]:    
    d = Decoder(b)
    pending_validators = decode_validator_list(d)
    epoch_root = d.take(144).hex()
    flag = d.u8()
    slot_sealers = None
    match flag:
        case 0:
            slot_sealers = [(d.hash32().hex(), d.u8()) for _ in range(util.LENGTH_OF_EPOCH_IN_TIMESLOTS)]
        case 1:
            # fallback
            slot_sealers = [d.hash32().hex() for _ in range(util.LENGTH_OF_EPOCH_IN_TIMESLOTS)]
            slot_sealers = { "keys": slot_sealers }
        case _:
            print(f"Slot sealer flag is invalid: {flag}")
    n = d.decode_compact()
    ticket_accumulator = [{ "id": d.hash32().hex(), "attempt": d.u8() } for _ in range(n)]
    # print({
    #     "pending_validators": pending_validators,
    #     "epoch_root": epoch_root,
    #     "slot_sealers_flag": flag,
    #     "slot_sealers": slot_sealers,
    #     "ticket_accumulator": ticket_accumulator,        
    # })
    d.finish()

def decode_disputes(b: bytes) -> tuple[str, bytes]:
    d = Decoder(b)
    n = d.decode_compact()
    good = [ d.hash32().hex() for _ in range(n) ]
    n = d.decode_compact()
    bad = [ d.hash32().hex() for _ in range(n) ]
    n = d.decode_compact()
    wonky = [ d.hash32().hex() for _ in range(n) ]
    n = d.decode_compact()
    offdenders = [ d.hash32().hex() for _ in range(n) ]
    d.finish()

def decode_entropy_accumulator(b: bytes) -> tuple[str, bytes]:
    d = Decoder(b)
    entropy_accumulator = [ d.hash32().hex() for _ in range(4) ]
    d.finish()

def decode_upcoming_validators(b: bytes) -> tuple[str, bytes]:
    d = Decoder(b)
    upcoming_validators = decode_validator_list(d)
    d.finish()

def decode_current_validators(b: bytes) -> tuple[str, bytes]:
    d = Decoder(b)
    current_validators = decode_validator_list(d)
    d.finish()

def decode_previous_validators(b: bytes) -> tuple[str, bytes]:
    d = Decoder(b)
    previous_validators = decode_validator_list(d)
    d.finish()

def decode_availability_assignments(b: bytes) -> tuple[str, bytes]:
    d = Decoder(b)
    availability_assignments = []
    for _ in range(util.NUM_VALIDATORS_IN_EPOCH_MARK // VALIDATORS_PER_CORE):
        report_exists = d.u8()
        if(report_exists):
            report = decode_report(d)
            timeout = d.u32()
            availability_assignments.append({
                "report": report,
                "timeout": timeout
            })
        else:
            availability_assignments.append(None)
    d.finish()

def decode_most_recent_timeslot(b: bytes) -> tuple[str, bytes]:
    d = Decoder(b)
    most_recent_timeslot = d.u32()
    d.finish()

def decode_privileged_services(b: bytes) -> tuple[str, bytes]:
    d = Decoder(b)
    manager_service_index, upcoming_validators_editor_index, service_creator_index = d.u32(), d.u32(), d.u32()
    authorizer_queue_altering_indices = [ d.u32() for _ in range(util.NUM_VALIDATORS_IN_EPOCH_MARK // VALIDATORS_PER_CORE) ]
    n = d.decode_compact()
    auto_accumulating_services = [ { "index": d.u32(), "gas": d.u64() } for _ in range(n) ]
    # print(manager_service_index, 
    #     upcoming_validators_editor_index, 
    #     service_creator_index, 
    #     authorizer_queue_altering_indices,
    #     auto_accumulating_services)
    d.finish()

# TODO: These look like what is called statistics in the ASN.
# Many of these are compacts but not described as compacts in neither
# the ASN or the GP
def decode_registrar_state(b: bytes) -> tuple[str, bytes]:
    d = Decoder(b)
    current_validator_statistics = decode_validators_statistics(d)
    last_epoch_validator_statistics = decode_validators_statistics(d)    
    core_statistics = [ 
        {
            "da_load": d.decode_compact(),
            "popularity": d.decode_compact(),
            "imports": d.decode_compact(),
            "extrinsic_count": d.decode_compact(),
            "extrinsic_size": d.decode_compact(),
            "exports": d.decode_compact(),
            "bundle_size": d.decode_compact(),
            "gas_used": d.decode_compact()
        }
        for _ in range(util.NUM_VALIDATORS_IN_EPOCH_MARK // VALIDATORS_PER_CORE) ]        
    n = d.decode_compact()
    service_statistics = {}
    for _ in range(n):
        service_id = d.u32()
        record = {
            "provided_count": d.decode_compact(),
            "provided_size": d.decode_compact(),
            "refinement_count": d.decode_compact(),
            "refinement_gas_used": d.decode_compact(),
            "imports": d.decode_compact(),
            "extrinsic_count": d.decode_compact(),
            "extrinsic_size": d.decode_compact(),
            "exports": d.decode_compact(),
            "accumulate_count": d.decode_compact(),
            "accumulate_gas_used": d.decode_compact()
        }
        service_statistics[service_id] = record
    d.finish()
    # = d.u32(), d.u32()

def decode_accumulation_queue(b: bytes) -> tuple[str, bytes]:
    d = Decoder(b)
    for _ in range(util.LENGTH_OF_EPOCH_IN_TIMESLOTS):
        n = d.decode_compact()
        for _ in range(n):
            report = decode_report(d)
            m = d.decode_compact()
            # TODO: Below is a set
            dependencies = StrictSet([ d.hash32().hex() for _ in range (m) ])
    d.finish()

def decode_accumulation_history(b: bytes) -> tuple[str, bytes]:
    d = Decoder(b)
    for _ in range(util.LENGTH_OF_EPOCH_IN_TIMESLOTS):        
        n = d.decode_compact()
        # TODO: Below is a set
        work_package_hashes = StrictSet([ d.hash32().hex() for _ in range (n) ])
    d.finish()

# TODO: These look like what is called accumulation outputs in the ASN.
def decode_statistics(b: bytes) -> tuple[str, bytes]:
    d = Decoder(b)
    n = d.decode_compact()
    for _ in range(n):
        stat_id = d.u32()
        work_report_hash = d.hash32().hex()
    d.finish()

def decode_service_definition(b: bytes, service_index: int) -> ServiceDefinition:
    d = Decoder(b)
    service_definition = ServiceDefinition(
        service_index=service_index,
        data=ServiceDefinitionData(
            service=ServiceDefinitionDataService(
                version=d.u8(),
                code_hash=d.hash32(),
                balance=d.u64(),
                min_item_gas=d.u64(),
                min_memo_gas=d.u64(),
                bytes_count=d.u64(),
                deposit_offset=d.u64(),
                items=d.u32(),
                creation_slot=d.u32(),
                last_accumulation_slot=d.u32(),
                parent_service=d.u32()
            )
        )
    )
    return service_definition

# def decode_storage(d: Decoder) -> tuple[str, bytes]:
#     n = d.decode_compact()
#     return "storage", d.take(n)

# def decode_preimages(d: Decoder) -> tuple[str, bytes]:
#     n = d.decode_compact()
#     return "preimages", d.take(n)

def decode_form_three_component(d: Decoder) -> tuple[str, bytes]:
    pass

key_to_state_component_mapping = {
    1: decode_authorization_pool,
    2: decode_authorization_queue,
    3: decode_recent_history,
    4: decode_safrole_state,
    5: decode_disputes,
    6: decode_entropy_accumulator,
    7: decode_upcoming_validators,
    8: decode_current_validators,
    9: decode_previous_validators,
    10: decode_availability_assignments,
    11: decode_most_recent_timeslot,
    12: decode_privileged_services,
    13: decode_registrar_state,
    14: decode_accumulation_queue,
    15: decode_accumulation_history,
    16: decode_statistics,
#    255: decode_service_definition
}

# GP D.1 Form 1 to 3
def state_key_decoder(key: bytes) -> Callable:    
    first = key[0]
    # first form
    if(0 < first <= 16 and key[1:] == b'\x00' * 30):
        return key_to_state_component_mapping[first]
    # second form
    elif(first == 255 
    and key[2] == 0
    and key[4] == 0
    and key[6] == 0
    and key[8:] == b'\x00' * 23 ):
        service_index = key[0:1] + key[2:3] + key[4:5] + key[6:7]
        return int.from_bytes(service_index, byteorder="little")
    # third form
    else:
        service_index = key[0:1] + key[2:3] + key[4:5] + key[6:7]
        return decode_form_three_component

def decode_state(b: bytes):
    with spec_globals("tiny"):
        d = Decoder(b)
        state_root = d.hash32()
        n = d.decode_compact() 
        keyvals = []   
        for i in range(n):
            key = d.take(31)
            # print(key.hex())
            n = d.decode_compact()
            value = d.take(n)
            decode_function = state_key_decoder(key)
            if(type(decode_function) == int):
                service_index = decode_function
                decode_service_definition(value, service_index)
            else:
                decode_function(value)
            # print(name)
            # print(value.hex())
            keyvals.append({
                "key": key.hex(),
                "value": value.hex()
            })
            # for debugging form 3
            # if(i == 5):
            #     break        
        return {
            "state_root": state_root,
            "keyvals": keyvals
        }

if __name__ == "__main__":
    import os
    test_vectors = []
    for root, dirs, files in os.walk("/home/arsalan/repos/JAM_Implementation/jamtestvectors/traces/"):
        for file in files:
            if file.endswith(".bin") and not file.startswith("ec-"):
                test_vectors.append(os.path.join(root, file))
    print(len(test_vectors), "to complete")
    b = None
    for test_vector in tqdm(test_vectors):
        try: 
            with open(test_vector, "rb") as f:
                b = f.read()
            decode_state(b)
        except Exception as error:
            print(f"Error!\n{error}\n on {test_vector}")
        