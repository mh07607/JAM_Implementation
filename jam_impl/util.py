import hashlib

HASH_LEN_IN_BYTES = 32
ZERO_HASH = bytes(HASH_LEN_IN_BYTES)

def hash_via_blake2b(data: bytes) -> bytes:
    return hashlib.blake2b(data, HASH_LEN_IN_BYTES).digest()

# TO-DO
def hash_via_keccak256(data: bytes) -> bytes:
    pass

def encode_fixed(x: int, length: int) -> bytes:
    assert 0 <= x < (1 << 8*n)
    return x.to_bytes(byteorder="little")

def decode_fixed(b: bytes, length: int) -> int:
    assert len(b) == n, f"E_{n} expected {n} octets, got {len(b)}"
    return int.from_bytes(b, little)

def u8(x): return encode_fixed(x, 1)
def u16(x): return encode_fixed(x, 2)
def u32(x): return encode_fixed(x, 4)
def u64(x): return encode_fixed(x, 8)
def u128(x): return encode_fixed(x, 16)

def encode_compact(x: int) -> bytes:
    pass

def state_serialize():
    pass

def merkalize():
    pass

