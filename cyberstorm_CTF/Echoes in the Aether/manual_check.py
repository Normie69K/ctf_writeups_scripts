def find_flag_patterns(binary_str):
    # Common flag patterns in binary
    patterns = {
        'CTF{': ['01000011', '01010100', '01000110', '01111011'],  # 'C', 'T', 'F', '{'
        'flag': ['01100110', '01101100', '01100001', '01100111']   # 'f', 'l', 'a', 'g'
    }
    
    for key, values in patterns.items():
        joined = ''.join(values)
        if joined in binary_str:
            start = binary_str.index(joined)
            end = binary_str.find('01111101', start)  # Look for '}' binary
            if end != -1:
                flag_bits = binary_str[start:end+8]
                return bytes(int(flag_bits[i:i+8], 2) for i in range(0, len(flag_bits), 8)).decode('utf-8')
    return "No recognizable patterns found."

print("\nManual Pattern Check:")
print(find_flag_patterns(binary_data))