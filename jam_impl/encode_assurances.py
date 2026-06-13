test_vector_path = "jamtestvectors/codec/full/assurances_extrinsic"

with open(test_vector_path+'.bin', 'rb') as file:
    print(file.read().hex())

import json
import struct

def encode_hex(hex_str):
    """Convert a 0x-prefixed hex string to bytes"""
    return bytes.fromhex(hex_str[2:])

def encode_u16_le(value):
    """E2 - 2 byte little endian"""
    return struct.pack('<H', value)

def encode_length_prefix(assurances: dict, data: bytes):
    length = len(assurances)    
    return encode_natural(length) + data

def encode_natural(x):
    """General natural number encoding from equation C.5"""
    if x == 0:
        return bytes([0])
    for l in range(8):
        if (1 << (7 * l)) <= x < (1 << (7 * (l + 1))):
            prefix = (0xFF - (0xFF >> l)) | (x >> (8 * l))
            remainder = x % (1 << (8 * l))
            return bytes([prefix]) + remainder.to_bytes(l, 'little')
    # fallback for large numbers
    return bytes([0xFF]) + x.to_bytes(8, 'little')

def encode_assurances(assurances):
    """Encode EA according to equation C.20:
    EA = E(↕[(a, f, E2(v), s) | (a, f, v, s) ← EA])
    """
    encoded_items = b''
    for a in assurances:
        anchor    = encode_hex(a['anchor'])       # a - 32 bytes
        print("\n anchor", anchor.hex())
        bitfield  = encode_hex(a['bitfield'])     # f - variable length
        validator = encode_u16_le(a['validator_index'])  # E2(v)
        signature = encode_hex(a['signature'])    # s - 64 bytes

        # each item is: anchor ++ length_prefix(bitfield) ++ validator_index ++ signature        
        encoded_items += anchor + bitfield + validator + signature

    # wrap the whole array with a length prefix (number of items)
    return encode_length_prefix(assurances, encoded_items)


with open(test_vector_path+'.json', 'r') as f:
    data = json.load(f)

result = encode_assurances(data)
print(result.hex())

# Compare against the .bin file
with open(test_vector_path+'.bin', 'rb') as f:
    expected = f.read()

print("Match:", result == expected)