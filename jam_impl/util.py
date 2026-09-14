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
    x.to_bytes(byteorder="little")


