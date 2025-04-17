import sys
import zlib
from PIL import Image
from datetime import datetime

def extract_flag(image_path):
    # Step 1: Extract UUID from image metadata
    try:
        with Image.open(image_path) as img:
            uuid = img.info.get('Comment', '').strip()
            print(f"[+] Found UUID in metadata: {uuid}")
    except Exception as e:
        print(f"[-] Error opening image: {e}")
        return

    # Step 2: Extract Zlib compressed data
    try:
        with open(image_path, 'rb') as f:
            f.seek(0x93)  # Skip PNG header to zlib data offset
            compressed_data = f.read()
    except Exception as e:
        print(f"[-] Error reading file: {e}")
        return

    # Step 3: Decompress zlib data
    try:
        decompressed = zlib.decompress(compressed_data)
        print(f"[+] Decompressed {len(decompressed)} bytes")
    except zlib.error as e:
        print(f"[-] Decompression failed: {e}")
        return

    # Step 4: Convert UUID components to timestamp
    try:
        uuid_parts = uuid.split('-')
        timestamp = int(uuid_parts[0], 16)
        date_str = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d')
    except Exception as e:
        print(f"[-] UUID parsing failed: {e}")
        return

    # Step 5: Generate flag candidates
    candidates = [
        f"CTF{{{date_str}_ChopperAI}}",
        f"CTF{{2000-11-27_{uuid_parts[-1]}}}",
        f"CTF{{{uuid}}}"
    ]

    # Step 6: Search for candidates in decompressed data
    print("\n[+] Possible flags:")
    found = False
    for candidate in candidates:
        if candidate.encode() in decompressed:
            print(f"  [+] Found in data: {candidate}")
            found = True
    if not found:
        print("  [-] No flags found in data. Try these candidates:")
        print('\n'.join(candidates))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python solve.py <image.png>")
        sys.exit(1)

    extract_flag(sys.argv[1])
