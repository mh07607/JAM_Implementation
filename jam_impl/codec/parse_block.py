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
    # n, o = util.decode_compact_length_prefix(r.b, r.o)
    # r.o = o
    # for i in range(n):
    # ----------- assurance
    n, o = util.decode_compact_length_prefix(r.b, r.o)
    r.o = o
    assurances = []    
    for i in range(n):
        assurances.append({
            "anchor": r.hash32().hex(),
            "bitfield": r.take(math.ceil(util.NUM_VALIDATORS_IN_EPOCH_MARK / 24)).hex(),
            "validator_index": r.u16(),
            "signature": r.take(64).hex()
        })
    print(assurances)
    r.finish()

if __name__ == "__main__":
    b = None
    with open("/home/arsalan/repos/JAM_Implementation/jamtestvectors/codec/full/assurances_extrinsic.bin", "rb") as f:
        b = f.read()
    parse_extrinsic(b)