num = 33844150717051407922870818513944809634829370512832532189263966589
hex_str = hex(num)[2:]
# Ensure an even number of hex digits (pad with a leading 0 if needed)
if len(hex_str) % 2 != 0:
    hex_str = '0' + hex_str

# Convert each pair of hex digits to a character
decoded = ''.join(chr(int(hex_str[i:i+2], 16)) for i in range(0, len(hex_str), 2))
print("Hex string:", hex_str)
print("Decoded ASCII:", decoded)
