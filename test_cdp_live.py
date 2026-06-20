"""
Captura CDP en MKT1 — verificar tráfico del UBNT 192.168.3.102
"""
import sys, io, time, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
import paramiko
from dotenv import load_dotenv
import os

load_dotenv()

HOST = os.getenv('M1_HOST', '10.10.11.1')
PORT = int(os.getenv('M1_PORT', 12222))
USER = os.getenv('M1_USER', 'admin')
PASS = os.getenv('M1_PASS', '')

TARGET_IP = '192.168.3.102'

def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS,
              timeout=10, look_for_keys=False, allow_agent=False)
    return c

def cmd(c, command, timeout=75):
    _, stdout, _ = c.exec_command(command, timeout=timeout)
    return stdout.read().decode('utf-8', errors='replace').strip()

client = connect()
print(f"Conectado a MKT1 ({HOST}:{PORT})\n")

# 1. Neighbor table ahora mismo — ¿ya aparece?
print("=== /ip neighbor — ¿aparece 192.168.3.102? ===")
neigh = cmd(client, "/ip neighbor print detail")
if TARGET_IP in neigh or '192.168.3' in neigh:
    for block in re.split(r'\n\s*\d+\s+', '\n' + neigh):
        if '192.168.3' in block or 'cdp' in block.lower() or 'lldp' in block.lower():
            print(block[:400])
else:
    print(f"  (no hay entradas con 192.168.3.x todavía)")
    print(f"  Total vecinos: {neigh.count('mac-address=')}")

# 2. ARP — confirmar que el equipo responde
print(f"\n=== ARP — ¿hay entrada para {TARGET_IP}? ===")
arp = cmd(client, f"/ip arp print terse where address={TARGET_IP}")
print(arp if arp else f"  (sin entrada ARP para {TARGET_IP})")

# 3. Bridge host — ¿la MAC está conectada?
print(f"\n=== Bridge hosts con IP 192.168.3.x ===")
# mac-scan para refrescar ARP en esa subred
mac_scan = cmd(client, "/tool mac-scan interface=bridge1 duration=3", timeout=15)
lines_3x = [l for l in mac_scan.splitlines() if '192.168.3.' in l]
for l in lines_3x:
    print(" ", l)

# 4. Sniffer CDP — 65 segundos (ciclo CDP airOS = 60s)
print(f"\n=== Sniffer CDP en MKT1 — 65 segundos ===")
print("  (CDP airOS transmite cada 60s, esperamos 65s para asegurar al menos 1 ciclo)")
cdp_raw = cmd(client, "/tool sniffer quick mac-protocol=cdp duration=65", timeout=80)
cdp_lines = [l for l in cdp_raw.splitlines() if ('<-' in l or '->' in l) and 'bridge1' not in l]
print(f"  Paquetes CDP capturados: {len(cdp_lines)}")

from collections import Counter
macs = Counter()
for l in cdp_lines:
    parts = l.split()
    for p in parts:
        if re.match(r'^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}', p) and p.count(':') == 5:
            if not p.startswith('01:00:0C'):  # excluir destino multicast CDP
                macs[p.upper()] += 1
            break

if macs:
    print(f"\n  MACs que enviaron CDP:")
    for mac, cnt in sorted(macs.items(), key=lambda x: -x[1]):
        print(f"    {mac}  ({cnt} pkts)")
else:
    print("  (ningún dispositivo envió CDP en 65s)")

# 5. Sniffer LLDP — 30 segundos adicionales
print(f"\n=== Sniffer LLDP en MKT1 — 30 segundos ===")
lldp_raw = cmd(client, "/tool sniffer quick mac-protocol=lldp duration=30", timeout=45)
lldp_lines = [l for l in lldp_raw.splitlines() if ('<-' in l or '->' in l) and 'bridge1' not in l]
print(f"  Paquetes LLDP capturados: {len(lldp_lines)}")
lldp_macs = Counter()
for l in lldp_lines:
    parts = l.split()
    for p in parts:
        if re.match(r'^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}', p) and p.count(':') == 5:
            if not p.startswith('01:80:C2'):
                lldp_macs[p.upper()] += 1
            break
for mac, cnt in sorted(lldp_macs.items(), key=lambda x: -x[1]):
    print(f"    {mac}  ({cnt} pkts)")

# 6. Neighbor table al final — ¿apareció ya?
print(f"\n=== /ip neighbor ahora (tras las capturas) ===")
neigh2 = cmd(client, "/ip neighbor print detail")
found = False
for block in re.split(r'\n\s*\d+\s+', '\n' + neigh2):
    if not block.strip():
        continue
    if '192.168.3' in block or 'cdp' in block.lower():
        print(block[:500])
        found = True
if not found:
    print(f"  (sigue sin aparecer 192.168.3.x en neighbor — total: {neigh2.count('mac-address=')} vecinos)")

client.close()
print("\n=== Fin ===")
