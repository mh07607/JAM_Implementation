import struct
import json

def decode_natural(data: bytes, offset: int = 0):
    """
    Decode a natural number encoded by encode_natural.
    Returns (value, bytes_consumed).
    """
    b = data[offset]
    if b == 0x00:
        return 0, 1
    if b == 0xFF:
        # Fallback: 8-byte little-endian value
        val = int.from_bytes(data[offset+1:offset+9], 'little')
        return val, 9

    # Determine l: number of leading 1 bits in b
    if (b & 0x80) == 0:
        l = 0
    elif (b & 0x40) == 0:
        l = 1
    elif (b & 0x20) == 0:
        l = 2
    elif (b & 0x10) == 0:
        l = 3
    elif (b & 0x08) == 0:
        l = 4
    elif (b & 0x04) == 0:
        l = 5
    elif (b & 0x02) == 0:
        l = 6
    else:
        l = 7

    # Extract the high part (the lower (8-l) bits of the prefix byte)
    mask = (0xFF >> l)          # e.g., for l=1 -> 0x7F
    high = b & mask

    # Read the remainder (l bytes, little-endian)
    rem_bytes = data[offset+1:offset+1+l]
    remainder = int.from_bytes(rem_bytes, 'little') if l > 0 else 0

    value = (high << (8 * l)) + remainder
    return value, 1 + l

def decode_assurances(buffer: bytes):
    """
    Reverse of encode_assurances.
    Returns a list of dicts with keys: anchor, bitfield, validator_index, signature.
    """
    offset = 0
    count, consumed = decode_natural(buffer, offset)
    offset += consumed

    # Total bytes occupied by the items
    total_items_bytes = len(buffer) - offset
    # Fixed size per item: anchor (32) + validator (2) + signature (64)
    fixed_per_item = 32 + 2 + 64
    total_fixed = count * fixed_per_item
    total_bitfield_bytes = total_items_bytes - total_fixed
    bitfield_len = total_bitfield_bytes // count   # must be integer

    if total_bitfield_bytes % count != 0:
        raise ValueError("Bitfield length cannot be evenly divided; invalid data")

    assurances = []
    for _ in range(count):
        # Anchor: 32 bytes
        anchor_bytes = buffer[offset:offset+32]
        offset += 32
        # Bitfield: bitfield_len bytes
        bitfield_bytes = buffer[offset:offset+bitfield_len]
        offset += bitfield_len
        # Validator index: 2 bytes little-endian
        validator = struct.unpack('<H', buffer[offset:offset+2])[0]
        offset += 2
        # Signature: 64 bytes
        signature_bytes = buffer[offset:offset+64]
        offset += 64

        assurances.append({
            'anchor': '0x' + anchor_bytes.hex(),
            'bitfield': '0x' + bitfield_bytes.hex(),
            'validator_index': validator,
            'signature': '0x' + signature_bytes.hex()
        })

    return assurances

test_vector_path = 'jamtestvectors/codec/full/assurances_extrinsic'

with open(test_vector_path + '.json', 'r') as f:
    original = json.load(f)

# Read the binary file
with open(test_vector_path + '.bin', 'rb') as f:
    binary_data = f.read()

decoded = decode_assurances(binary_data)
print(decoded)

# Compare
print(f"Original length: {len(original)}")
print(f"Decoded length : {len(decoded)}")

if len(original) != len(decoded):
    print("FAIL: lengths differ")
else:
    mismatch = False
    for i, (o, d) in enumerate(zip(original, decoded)):
        if (o['anchor'] != d['anchor'] or
            o['bitfield'] != d['bitfield'] or
            o['validator_index'] != d['validator_index'] or
            o['signature'] != d['signature']):
            print(f"Mismatch at index {i}:")
            print(f"  Original: {o}")
            print(f"  Decoded : {d}")
            mismatch = True
            break
    if not mismatch:
        print("\n✅ PASS: decoded data perfectly matches the original JSON.")