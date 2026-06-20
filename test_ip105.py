import sys, io, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
import paramiko
from dotenv import load_dotenv
import os

load_dotenv()

HOST = os.getenv('M1_HOST'); PORT = int(os.getenv('M1_PORT', 12222))
USER = os.getenv('M1_USER'); PASS = os.getenv('M1_PASS', '')
TARGET = '192.168.3.105'

def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS,
              timeout=10, look_for_keys=False, allow_agent=False)
    return c

def cmd(c, command, timeout=30):
    _, stdout, _ = c.exec_command(command, timeout=timeout)
    return stdout.read().decode('utf-8', errors='replace').strip()

c = connect()

# 1. Neighbor table
print(f"=== /ip neighbor — {TARGET} ===")
neigh = cmd(c, "/ip neighbor print detail")
found = False
for block in re.split(r'\n\s*\d+\s+', '\n' + neigh):
    if TARGET in block:
        print(block[:500])
        found = True
if not found:
    print(f"  No aparece en neighbor (total: {neigh.count('mac-address=')} vecinos)")

# 2. ARP
print(f"\n=== ARP {TARGET} ===")
arp = cmd(c, f"/ip arp print terse where address={TARGET}")
print(arp if arp else "  (sin entrada ARP)")

# 3. Sniffer all traffic desde esa IP — 30s
print(f"\n=== Sniffer todo tráfico desde {TARGET} — 30s ===")
cmd(c, "/tool sniffer stop", timeout=5)
cmd(c, f"/tool sniffer set filter-ip-address={TARGET}/32 filter-direction=rx "
       f"only-headers=no memory-limit=2048 file-name=\"\"", timeout=5)
cmd(c, "/tool sniffer start", timeout=5)
import time; time.sleep(30)
cmd(c, "/tool sniffer stop", timeout=5)

pkts = cmd(c, "/tool sniffer packet print detail", timeout=15)
if pkts.strip():
    print(pkts[:3000])
else:
    # Intentar con sniffer quick
    print("  (sniffer RAM sin resultados — probando quick 20s)")
    quick = cmd(c, f"/tool sniffer quick filter-ip-address={TARGET}/32 duration=20", timeout=35)
    lines = [l for l in quick.splitlines() if '<-' in l or '->' in l]
    print(f"  Paquetes: {len(lines)}")
    for l in lines[:20]:
        print(" ", l)

# 4. CDP/LLDP desde esa MAC (si la tenemos del ARP)
print(f"\n=== Nuevo neighbor table completo (UBNT presentes?) ===")
neigh2 = cmd(c, "/ip neighbor print detail")
ubnt_oui = {'FC:EC:DA','68:72:51','80:2A:A8','DC:9F:DB','24:A4:3C',
            '20:23:51','24:2F:D0','B0:4E:26','5C:E9:31','28:EE:52',
            '24:5A:4C','E0:63:DA','FC:EC:DA','44:D9:E7','F0:9F:C2'}
ubnt_found = []
for block in re.split(r'\n\s*\d+\s+', '\n' + neigh2):
    if not block.strip(): continue
    mac_m = re.search(r'mac-address=([0-9A-Fa-f:]{17})', block)
    if mac_m and mac_m.group(1).upper()[:8] in ubnt_oui:
        addr = re.search(r'address=(\d+\.\d+\.\d+\.\d+)', block)
        ident = re.search(r'identity="([^"]*)"', block)
        ver = re.search(r'version="?([^"\s,]+)"?', block)
        age = re.search(r'age=(\S+)', block)
        ubnt_found.append(
            f"  {mac_m.group(1).upper()}  IP={addr.group(1) if addr else '?':16s}"
            f"  age={age.group(1) if age else '?':8s}"
            f"  {(ident.group(1) or ''):20s}  {ver.group(1) if ver else ''}"
        )

print(f"  UBNT en neighbor: {len(ubnt_found)}")
for r in ubnt_found:
    print(r)

c.close()
