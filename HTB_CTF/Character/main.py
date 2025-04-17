from pwn import *

host = '94.237.61.66'
port = 55709

# Start connection to remote nc server
p = remote(host, port)

flag = ''

# Adjust number of characters to try (e.g., 50 max)
for i in range(500):
    try:
        # Wait for prompt
        p.recvuntil(b'Enter an index:')
        
        # Send the index
        p.sendline(str(i))
        
        # Receive the response line
        response = p.recvline().decode().strip()
        
        # Extract character from response
        if 'Character at Index' in response:
            ch = response.split(':')[-1].strip()
            print(f"Index {i} => {ch}")
            flag += ch
        else:
            print(f"Unexpected response at index {i}: {response}")
            break
    except EOFError:
        print("Connection closed.")
        break

print("\nExtracted Flag:", flag)

# Close the connection
p.close()
