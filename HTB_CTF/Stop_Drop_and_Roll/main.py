from pwn import *

host = '83.136.251.68'
port = 37404

p = remote(host, port)

# Scenario → Action map
action_map = {
    'GORGE': 'STOP',
    'PHREAK': 'DROP',
    'FIRE': 'ROLL'
}

# Answer 'y' to start
p.recvuntil(b'(y/n)')
p.sendline(b'y')
print("[*] Game started!")

try:
    while True:
        # Receive full block up to the next "What do you do?" prompt
        data = p.recvuntil(b'What do you do?').decode()
        print("[Server]\n" + data.strip())

        # Extract the LAST line that contains the scenario
        lines = data.strip().splitlines()
        scenario_line = None
        for line in reversed(lines):
            if any(x in line for x in action_map):
                scenario_line = line.strip()
                break

        if scenario_line:
            scenario = [word.strip() for word in scenario_line.split(',')]
            response = '-'.join([action_map.get(w, '?') for w in scenario])
            print(f"[Sending] {response}")
            p.sendline(response)
        else:
            print("[!] Couldn't detect scenario line.")
            break

except EOFError:
    print("[!] Server closed the connection.")
except KeyboardInterrupt:
    print("[*] Interrupted by user.")
finally:
    p.close()
