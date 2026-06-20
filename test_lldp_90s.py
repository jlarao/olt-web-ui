"""
Captura LLDP en MKT3 durante 90s.
Hipótesis: los UBNT airOS (XM.v/XW.v) usan LLDP, no MNDP UDP:5678.
RouterOS muestra los campos identity/platform/version de los TLVs LLDP.
"""
import sys, io, time, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

import paramiko
from dotenv import load_dotenv
import os
from collections import defaultdict, Counter

load_dotenv()

HOST = os.getenv('M2_HOST', '10.10.11.3')
PORT = int(os.getenv('M2_PORT', 22))
USER = os.getenv('M2_USER', 'admin')
PASS = os.getenv('M2_PASS', '')

UBNT_OUI = {
    '68:72:51', '80:2A:A8', 'DC:9F:DB', '24:A4:3C', '20:23:51',
    '24:2F:D0', 'B0:4E:26', '5C:E9:31', '28:EE:52', 'E0:63:DA',
    'FC:EC:DA', 'F0:9F:C2', '74:83:C2', 'AC:84:C6', '44:D9:E7',
    '24:5A:4C', '60:22:32', '68:D7:9A',
}
MIKROTIK_OUI = {
    '08:55:31', '18:FD:74', 'CC:2D:E0', '6C:3B:6B', '48:8F:5A',
    '4C:5E:0C', '00:0C:42', '2C:C8:1B', '64:D1:54', 'D4:01:C3',
    'B8:69:F4', '74:4D:28', 'E4:8D:8C', 'C4:AD:34',
}

def vendor(mac):
    o = mac.upper()[:8]
    if o in UBNT_OUI: return 'UBNT'
    if o in MIKROTIK_OUI: return 'MikroTik'
    if o == '58:C1:7A': return 'Cambium'
    return '?'

def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS,
              timeout=10, look_for_keys=False, allow_agent=False)
    return c

def ssh_cmd(client, cmd, timeout=120):
    _, stdout, _ = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode('utf-8', errors='replace')

print(f"=== Captura LLDP 90s en MKT3 ({HOST}) ===\n")

client = connect()
raw = ssh_cmd(client, "/tool sniffer quick mac-protocol=lldp duration=90", timeout=110)
client.close()

pkt_lines = [l for l in raw.splitlines() if '<-' in l or '->' in l]

# Agrupar por MAC (filtrar duplicados bridge1)
mac_ts = defaultdict(list)
for line in pkt_lines:
    parts = line.split()
    if not parts or parts[0] == 'bridge1':
        continue
    ts = parts[1] if len(parts) > 1 else '?'
    direction = None
    src_mac = None
    for p in parts:
        if p in ('<-', '->'):
            direction = p
        if re.match(r'^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}', p) and ':' in p:
            if src_mac is None and p.count(':') == 5:
                src_mac = p.upper()
    if src_mac and direction == '<-':
        # Excluir destino multicast LLDP (01:80:C2:...)
        if not src_mac.startswith('01:80'):
            mac_ts[src_mac].append(ts)

print(f"Paquetes LLDP únicos (ether7 only): {sum(len(v) for v in mac_ts.values())}")
print(f"MACs emisoras: {len(mac_ts)}\n")

# Calcular intervalo entre broadcasts (ciclo LLDP)
ubnt_found = []
mkt_found  = []
other_found = []

for mac, timestamps in sorted(mac_ts.items(), key=lambda x: -len(x[1])):
    ts_floats = []
    for t in timestamps:
        try:
            ts_floats.append(float(t))
        except ValueError:
            pass

    if len(ts_floats) >= 2:
        intervals = [ts_floats[i+1] - ts_floats[i] for i in range(len(ts_floats)-1)]
        # Filtrar intervalos muy cortos (duplicados dentro de un burst)
        real_intervals = [iv for iv in intervals if iv > 0.5]
        if real_intervals:
            avg = sum(real_intervals) / len(real_intervals)
            cycle = f"ciclo~{avg:.0f}s"
        else:
            cycle = "burst"
    else:
        cycle = "(1 pkt)"

    v = vendor(mac)
    row = f"  {mac}  {v:10s}  {len(timestamps):4d} pkts  {cycle}"

    if v == 'UBNT':
        ubnt_found.append(row)
    elif v == 'MikroTik':
        mkt_found.append(row)
    else:
        other_found.append(row)

print(f"--- UBNT ({len(ubnt_found)}) ---")
if ubnt_found:
    for r in ubnt_found:
        print(r)
else:
    print("  (ningún UBNT detectado via LLDP)")

print(f"\n--- MikroTik ({len(mkt_found)}) ---")
for r in mkt_found:
    print(r)

print(f"\n--- Otros ({len(other_found)}) ---")
for r in other_found:
    print(r)

# Cruzar con neighbor para ver qué UBNT están en neighbor pero NO en LLDP
print(f"\n--- Cruce con /ip neighbor ---")
c2 = connect()
raw_n = ssh_cmd(c2, "/ip neighbor print detail", timeout=15)
c2.close()

lldp_macs = set(mac_ts.keys())

for block in re.split(r'\n\s*\d+\s+', '\n' + raw_n):
    if not block.strip():
        continue
    mac_m = re.search(r'mac-address=([0-9A-Fa-f:]{17})', block)
    if not mac_m:
        continue
    mac = mac_m.group(1).upper()
    if vendor(mac) != 'UBNT':
        continue
    ident = re.search(r'identity="([^"]*)"', block)
    ver   = re.search(r'\bversion="?([^",\s]+)"?', block)
    age   = re.search(r'age=(\S+)', block)

    in_lldp = mac in lldp_macs
    proto = "LLDP ✓" if in_lldp else "no capturado"
    print(f"  {mac}  age={age.group(1) if age else '?':8s}  "
          f"{(ident.group(1) or ''):25s}  {(ver.group(1) if ver else ''):22s}  [{proto}]")

print("\n=== Fin ===")
