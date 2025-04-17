from pwn import *

host = '83.136.251.68'
port = 37404

p = remote(host, port)

action_map = {
    'GORGE': 'STOP',
    'PHREAK': 'DROP',
    'FIRE': 'ROLL'
}

# Start game
p.recvuntil(b'(y/n)')
p.sendline(b'y')
print("[*] Game started!")

round_count = 0

try:
    while True:
        data = p.recvuntil(b'What do you do?').decode()

        # Print full block from server
        print(f"\n[Round {round_count + 1}]")
        print(data.strip())

        # Detect flag or win message
        if "flag" in data.lower() or "HTB" in data or "{" in data:
            print("\n🎉 FLAG DETECTED!")
            break

        # Extract last scenario line
        lines = data.strip().splitlines()
        scenario_line = next((line for line in reversed(lines) if any(w in line for w in action_map)), None)

        if scenario_line:
            scenario = [word.strip() for word in scenario_line.split(',')]
            response = '-'.join([action_map.get(w, '?') for w in scenario])
            print(f"[Sending] {response}")
            p.sendline(response)
            round_count += 1
        else:
            print("[!] Scenario not found.")
            break

except EOFError:
    print("[!] Server closed the connection.")
except KeyboardInterrupt:
    print("[*] Stopped manually.")
finally:
    print(f"Total Rounds: {round_count}")
    p.close()
