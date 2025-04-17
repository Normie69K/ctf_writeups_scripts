#!/usr/bin/env python3
import argparse

def xor_data(data, key):
    """XOR every byte of data with the given key."""
    return bytes(b ^ key for b in data)

def main():
    parser = argparse.ArgumentParser(
        description="Reverse multiple XOR loops on an input file."
    )
    parser.add_argument(
        "file",
        help="Path to the file to deobfuscate (e.g., your trove file)."
    )
    parser.add_argument(
        "keys",
        help=("Comma-separated list of XOR keys in hex (e.g., 0x12,0x34,0xAB). "
              "The order should be the same as they were applied in the binary.")
    )
    args = parser.parse_args()

    # Read the encrypted/obfuscated file
    with open(args.file, "rb") as f:
        data = f.read()

    # Parse the keys and convert them to integers.
    keys = [int(x.strip(), 16) for x in args.keys.split(",")]
    print(f"[+] Loaded {len(data)} bytes from {args.file}")
    print(f"[+] Applying XOR deobfuscation with keys: {keys}")

    # To reverse the process, we need to apply the XOR keys in reverse order.
    for key in reversed(keys):
        data = xor_data(data, key)
        print(f"[+] Applied XOR with key: 0x{key:02X}")

    print("\nDeobfuscated output:")
    try:
        # Try to decode as text
        print(data.decode())
    except UnicodeDecodeError:
        # If not decodable, output raw bytes in hex
        print(data.hex())

if __name__ == "__main__":
    main()
