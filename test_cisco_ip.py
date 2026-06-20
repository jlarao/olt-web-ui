import sys, io, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
import paramiko
from dotenv import load_dotenv
import os

load_dotenv()

HOST = os.getenv('M1_HOST'); PORT = int(os.getenv('M1_PORT', 12222))
USER = os.getenv('M1_USER'); PASS = os.getenv('M1_PASS', '')
CISCO_MAC = 'C0:64:E4:F7:C2:D7'

def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS,
              timeout=10, look_for_keys=False, allow_agent=False)
    return c

def cmd(c, command, timeout=15):
    _, stdout, _ = c.exec_command(command, timeout=timeout)
    return stdout.read().decode('utf-8', errors='replace').strip()

c = connect()

print("=== IP del Cisco SG220-26 ===")

# Buscar en ARP table
arp = cmd(c, "/ip arp print terse")
for line in arp.splitlines():
    if 'C0:64:E4' in line.upper() or 'c0:64:e4' in line.lower():
        print(f"  ARP: {line}")

# Buscar en neighbor (tiene address)
neigh = cmd(c, "/ip neighbor print detail")
for block in re.split(r'\n\s*\d+\s+', '\n' + neigh):
    if 'C0:64:E4' in block.upper():
        addr = re.search(r'address=(\S+)', block)
        identity = re.search(r'identity="([^"]*)"', block)
        iface = re.search(r'interface=(\S+)', block)
        print(f"  Neighbor: IP={addr.group(1) if addr else '?'}  "
              f"name={identity.group(1) if identity else '?'}  "
              f"iface={iface.group(1) if iface else '?'}")

# mac-scan para encontrar la IP
print("\n  Buscando con mac-scan (5s)...")
ms = cmd(c, "/tool mac-scan interface=bridge1 duration=5", timeout=20)
for line in ms.splitlines():
    if 'C0:64:E4' in line.upper() or 'c0:64:e4' in line.lower():
        print(f"  mac-scan: {line}")

c.close()
