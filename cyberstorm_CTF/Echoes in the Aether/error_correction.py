def decode_with_error_correction(binary_str):
    # Try different bit groupings and encodings
    strategies = [
        ('8-bit ASCII', 8, lambda x: bytes(int(x[i:i+8], 2) for i in range(0, len(x), 8))),
        ('7-bit ASCII', 7, lambda x: bytes(int(x[i:i+7], 2) for i in range(0, len(x), 7))),
        ('Hex', 4, lambda x: bytes.fromhex(hex(int(x, 2))[2:])),
        ('Inverted Bits', 8, lambda x: bytes(int(''.join('1' if c == '0' else '0' for c in x[i:i+8]), 2) for i in range(0, len(x), 8)));
    ]
    
    for name, bits, decoder in strategies:
        try:
            decoded = decoder(binary_str)
            decoded_str = decoded.decode('utf-8', errors='replace')
            if 'CTF{' in decoded_str:
                return f"{name}: {decoded_str.split('}')[0]}"
        except:
            continue
    
    return "Flag not found. Try manual analysis."

result = decode_with_error_correction(binary_data)
print("\nDecoding Result:")
print(result)