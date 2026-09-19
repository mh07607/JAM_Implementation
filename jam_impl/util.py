import hashlib

HASH_LEN_IN_BYTES = 32
ZERO_HASH = bytes(HASH_LEN_IN_BYTES)

def hash_via_blake2b(data: bytes) -> bytes:
    return hashlib.blake2b(data, HASH_LEN_IN_BYTES).digest()

# TO-DO
def hash_via_keccak256(data: bytes) -> bytes:
    pass

def encode_fixed(x: int, length: int) -> bytes:
    assert 0 <= x < (1 << 8*length)
    return x.to_bytes(length=length, byteorder="little")

def decode_fixed(b: bytes, length: int) -> int:
    assert len(b) == length, f"E_{length} expected {length} octets, got {len(b)}"
    return int.from_bytes(b, byteorder="little")

def u8(x): return encode_fixed(x, 1)
def u16(x): return encode_fixed(x, 2)
def u32(x): return encode_fixed(x, 4)
def u64(x): return encode_fixed(x, 8)
def u128(x): return encode_fixed(x, 16)

def encode_compact(x: int) -> bytes:
    # GP C.5
    assert x >= 0 and x < 2**64, f"{x} is outside valid compact range i.e between 0 and 2^64"
    if x < 128:
        return bytes([x])
    for l in range(1, 9):
        if 2**(7*l) <= x and x < 2**(7*(l+1)):
            size_tag = 2**8 - 2**(8-l) + x//2**(8*l)
            return bytes([size_tag]) + encode_fixed(x % 2**(8*l), l)            
    return bytes([2**8-1]) + u64(x)

def decode_compact_length_prefix(b: bytes, offset: int) -> tuple[int, int]:
    first_octet = b[offset]
    if first_octet < 128: return first_octet, off + 1
    table = [(128, 192, 1), (192, 224, 2), (224, 240, 3), (240, 248, 4),
            (248, 252, 5), (252, 254, 6), (254, 255, 7), (255, 256, 8)]
    for low, high, l in table:
        if low <= first_octet < high:
            high_part = first_octet - (2**8 - 2**(8-l))
            payload = b[offset+1 : offset+1+l]
            return high_part * 2**(8*l) + payload, offset + 1 + l
    raise ValueError(f"Invalid compact. Tag: {first_octet}")

def maybe_bytes(blob: bytes | None) -> bytes:
    return b"\x00" if x is None else b"\x01" + x

def read_variable_length_sequence(r: Reader) -> bytes:
    n, o = decode_compact_length_prefix(r.b, r.o)
    r.o = o
    return r.take(n)

class Reader():
    def __init__(self, data: bytes):
        self.b, self.o = data, 0
    def take(self, n: int):
        assert self.o + n <= len(self.b), "Premature end of Input."
        s = self.b[self.o:self.o+n]
        self.o += n
        return s
    def u8(self): return self.take(1)[0]
    def u16(self): return decode_fixed(self.take(2), 2)
    def u32(self): return decode_fixed(self.take(4), 4)
    def u64(self): return decode_fixed(self.take(8), 8)
    def hash32(self): return self.take(32)
    def var_blob(self) -> bytes:
        n, o = decode_compact_at_offset(self.b, self.o)
        self.o = o
        return self.take(n)
    def finish(self):
        assert self.o == len(self.b), f"{len(self.b) - self.o} octets"

def read_maybe(r: Reader, fixed_len: int | None) -> bytes | None:
    d = r.u8()
    if d == 0:
        return None
    return r.take(fixed_len) if fixed_len is not None else read_variable_length_sequence(r)

def parse_header(b: bytes) -> dict:
    # Only works for certain headers under assumptions for both markers
    # offenders marker excluded
    r = Reader(b)
    parent, prior_state_root, extrinsic_hash = r.hash32(), r.hash32(), r.hash32()
    slot = r.u32()
    epoch_marker = read_maybe(r, 32)
    tickets_marker = read_maybe(r, 32)
    author_index = r.u16()    
    vrf_sig = r.take(96)
    # r.finish()
    return {
        "parent": parent.hex(),
        "prior_state_root": prior_state_root.hex(),
        "extrinsic_hash": extrinsic_hash.hex(),
        "slot": slot,
        "epoch_marker": epoch_marker,
        "tickets_marker": tickets_marker,
        "author_index": author_index,
        "entropy_vrf_signature": vrf_sig
    }

def state_serialize():
    pass

def merkalize():
    pass

# if __name__ == "main":    
b = None
with open("/home/arsalan/repos/JAM_Implementation/jamtestvectors/codec/tiny/header_0.bin", "rb") as f:
    b = f.read()
print(parse_header(b))