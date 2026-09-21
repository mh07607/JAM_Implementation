import math
import jam_impl.util as util

def parse_extrinsic(b: bytes):
    r = util.Reader(b)
    # ------------ tickets
    # n, o = util.decode_compact_length_prefix(r.b, r.o)
    # r.o = o
    # tickets = []
    # for i in range(n):
    #     tickets.append({
    #         "attempt": r.u8(),
    #         "signature": r.take(784)
    #     })
    # print(tickets)
    # ----------- preimages
    # n, o = util.decode_compact_length_prefix(r.b, r.o)
    # r.o = o
    # preimages = []
    # for i in range(n):
    #     requester = r.u32()
    #     m, o = util.decode_compact_length_prefix(r.b, r.o)
    #     r.o = o
    #     blob = r.take(m)
    #     preimages.append({
    #         "requester": requester,
    #         "blob": blob.hex()
    #     })
    # print(preimages)
    # ----------- guarantees
    n, o = util.decode_compact_length_prefix(r.b, r.o)
    r.o = o
    guarantees = []
    for i in range(n):
        package_hash = r.hash32().hex()
        length = r.u32()
        erasure_root, exports_root = r.hash32().hex(), r.hash32().hex()
        exports_count = r.u16()
        package_spec = {
            "hash": package_hash,
            "length": length,
            "erasure_root": erasure_root,
            "exports_root": exports_root,
            "exports_count": exports_count
        }
        context = {
            "anchor": r.hash32().hex(),
            "state_root": r.hash32().hex(),
            "beefy_root": r.hash32().hex(),
            "lookup_anchor": r.hash32().hex(),
            "lookup_anchor_slot": r.u32()
        }
        prerequisites_length, o = util.decode_compact_length_prefix(r.b, r.o)
        r.o = o
        prerequisites = []
        for j in range(prerequisites_length):
            prerequisites.append(r.hash32().hex())
        context["prerequisites"] = prerequisites
        core_index = r.u8()
        authorizer_hash = r.hash32().hex()
        auth_gas_used = r.u8()
        auth_output_length, o = util.decode_compact_length_prefix(r.b, r.o)
        r.o = o
        auth_output = r.take(auth_output_length).hex()    
        segment_root_lookup_length, o = util.decode_compact_length_prefix(r.b, r.o)
        r.o = o
        segment_root_lookup = [ { "work_package_hash": r.hash32(), "segment_tree_root": r.hash32() } for k in range(segment_root_lookup_length) ]
        results_length, o = util.decode_compact_length_prefix(r.b, r.o)
        r.o = o
        results = []
        for j in range(results_length):
            service_id = r.u32()
            code_hash, payload_hash = r.hash32(), r.hash32()
            accumulate_gas = r.u64()
            result_flag = r.u8()
            result = None
            match result_flag:
                case 0:
                    result_length, o = util.decode_compact_length_prefix(r.b, r.o)
                    r.o = o
                    result = { "ok": r.take(result_length).hex() }
                case 1:
                    result = { "out_of_gas" : None }
                case 2:
                    result = { "panic" : None }
                case 3:
                    result = { "invalid_exports_count" : None }
                case 4:
                    result = { "digest_size_limit_exceeded" : None }
                case 5:
                    result = { "BAD" : None }
                case 6:
                    result = { "BIG" : None }
                case _:
                    console.log(f"Result with service id {service_id} has no valid output")        
            gas_used, o = util.decode_compact_length_prefix(r.b, r.o)
            r.o = o
            imports, o = util.decode_compact_length_prefix(r.b, r.o)
            r.o = o
            extrinsic_count, o = util.decode_compact_length_prefix(r.b, r.o)
            r.o = o
            extrinsic_size, o = util.decode_compact_length_prefix(r.b, r.o)
            r.o = o
            exports, o = util.decode_compact_length_prefix(r.b, r.o)
            r.o = o
            results.append({
                "service_id": service_id,
                "code_hash": code_hash.hex(),
                "payload_hash": payload_hash.hex(),
                "accumulate_gas": accumulate_gas,
                "result": result,
                "refine_load": {
                    "gas_used": gas_used,
                    "imports": imports,
                    "extrinsic_count": extrinsic_count,
                    "extrinsic_size": extrinsic_size,
                    "exports": exports,                    
                }
            })
        slot = r.u32()
        signatures_length, o = util.decode_compact_length_prefix(r.b, r.o)
        r.o = o
        signatures = [ {
            "validator_index": r.u16(),
            "signature": r.take(64).hex()
        } for j in range(signatures_length) ]
        guarantees.append({
            "report": {
                "package_spec": package_spec,
                "context": context,
                "core_index": core_index,
                "authorizer_hash": authorizer_hash,
                "auth_gas_used": auth_gas_used,
                "auth_output": auth_output,
                "segment_root_lookup": segment_root_lookup,
                "results": results,                
            },
            "slot": slot,
            "signatures": signatures
        })
    print(guarantees)
    return guarantees
            

    # ----------- assurance
    # n, o = util.decode_compact_length_prefix(r.b, r.o)
    # r.o = o
    # assurances = []    
    # for i in range(n):
    #     assurances.append({
    #         "anchor": r.hash32().hex(),
    #         "bitfield": r.take(math.ceil(util.NUM_VALIDATORS_IN_EPOCH_MARK / 24)).hex(),
    #         "validator_index": r.u16(),
    #         "signature": r.take(64).hex()
    #     })
    # print(assurances)
    # r.finish()

if __name__ == "__main__":
    b = None
    with open("/home/arsalan/repos/JAM_Implementation/jamtestvectors/codec/full/guarantees_extrinsic.bin", "rb") as f:
        b = f.read()
    parse_extrinsic(b)