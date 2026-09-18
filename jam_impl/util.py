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

def decode_compact_at_offset(blob: bytes, offset: int) -> tuple[int, int]:
    first_octet = blob[offset]
    if first_octet < 128: return first_octet, off + 1
    table = [(128, 192, 1), (192, 224, 2), (224, 240, 3), (240, 248, 4)
            (248, 252, 5), (252, 254, 6), (254, 255, 7), (255, 256, 8)]
    for low, high, l in table:
        if low <= first_octet < high:
            high_part = first_octet - (2**8 - 2**(8-l))
            payload = blob[offset+1:offset+1+l]
            return high_part * 2**(8*l) + payload, offset + 1 + l
    raise ValueError(f"Invalid compact. Tag: {first_octet}")

def state_serialize():
    pass

def merkalize():
    pass

