import base64
import itertools
import codecs

# The encrypted byte string
data = b"\x0e,\x082 ,\x17%\x1b/!%\x18\x15*+ \x01\x00w'\x15v%\x18,\x1b%$\x16s\x0b\x11p{,\x17q2\x05's\x0c\n\x17\x052+!\x15ws\x18+\x001!,%%!,\x14,\x0b\n\x08t\x0b\x05&+&\x01\x00-\x1b/5% \n.w /\x04p\x175\x7f\x7f"

# Transformation functions
def xor(data): return bytes([b ^ 0x42 for b in data])
def reverse(data): return data[::-1]
def rot13(data): return codecs.encode(data.decode('latin-1'), 'rot_13').encode('latin-1')
def b64(data):
    try: return base64.b64decode(data)
    except Exception: return b''

# Mapping of operation names to functions
ops = {
    'xor': xor,
    'reverse': reverse,
    'rot13': rot13,
    'base64': b64,
}

# Try all 24 permutations
for perm in itertools.permutations(ops.keys()):
    try:
        tmp = data
        for op in perm:
            tmp = ops[op](tmp)
        print(f"[+] Order: {' -> '.join(perm)}")
        print(tmp.decode(errors='ignore'))
        print("="*50)
    except Exception as e:
        continue
