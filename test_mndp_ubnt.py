"""
Captura MNDP (UDP:5678) en MKT3 durante 90s para atrapar el ciclo completo UBNT.
Muestra qué MACs UBNT emiten MNDP y el intervalo entre broadcasts.
"""
import sys, io, time, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

import paramiko
from dotenv import load_dotenv
import os
from collections import defaultdict

load_dotenv()

HOST = os.getenv('M2_HOST', '10.10.11.3')
PORT = int(os.getenv('M2_PORT', 22))
USER = os.getenv('M2_USER', 'admin')
PASS = os.getenv('M2_PASS', '')

UBNT_OUI = {
    '68:72:51', '80:2A:A8', 'DC:9F:DB', '24:A4:3C', '20:23:51',
    '24:2F:D0', 'B0:4E:26', '5C:E9:31', '28:EE:52', 'E0:63:DA',
    'FC:EC:DA', 'F0:9F:C2', '74:83:C2', 'AC:84:C6', '44:D9:E7',
    '24:5A:4C', '60:22:32', '68:D7:9A', '78:45:58',
}

MIKROTIK_OUI = {
    '08:55:31', '18:FD:74', 'CC:2D:E0', '6C:3B:6B', '48:8F:5A',
    '4C:5E:0C', '00:0C:42', '2C:C8:1B', '64:D1:54', 'D4:01:C3',
    'B8:69:F4', '74:4D:28', 'E4:8D:8C', 'C4:AD:34',
}

def oui(mac):
    return mac.upper()[:8]

def vendor(mac):
    o = oui(mac)
    if o in UBNT_OUI:
        return 'UBNT'
    if o in MIKROTIK_OUI:
        return 'MikroTik'
    if o == '58:C1:7A':
        return 'Cambium'
    return '?'

def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS,
              timeout=10, look_for_keys=False, allow_agent=False)
    return c

def ssh_cmd(client, cmd, timeout=120):
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode('utf-8', errors='replace')
    return out

print(f"=== Sniffer MNDP UDP:5678 en MKT3 ({HOST}) — 90 segundos ===")
print("(ciclo MNDP de UBNT airOS es ~60s — necesitamos 90s para capturar todos)\n")

client = connect()

raw = ssh_cmd(client,
    "/tool sniffer quick port=5678 duration=90",
    timeout=110)

client.close()

# Parsear líneas con paquetes reales (tienen '<-' o '->')
pkt_lines = [l for l in raw.splitlines() if '<-' in l or '->' in l]

# Estructura: {mac: [(timestamp_str, iface), ...]}
mac_events = defaultdict(list)

for line in pkt_lines:
    # Formato: IFACE   TIME   NUM  DIR  SRC-MAC  DST-MAC
    parts = line.split()
    if len(parts) < 5:
        continue
    iface = parts[0]
    # Ignorar bridge1 (duplicado de ether7)
    if iface == 'bridge1':
        continue
    timestamp = parts[1] if len(parts) > 1 else '?'
    direction = None
    src_mac = None
    for p in parts:
        if p in ('<-', '->'):
            direction = p
        if re.match(r'^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}', p):
            if src_mac is None:
                src_mac = p.upper()
    if src_mac and direction == '<-':
        mac_events[src_mac].append((timestamp, iface))

print(f"Total paquetes únicos capturados (sin duplicados bridge): {sum(len(v) for v in mac_events.values())}")

# Separar por vendor
ubnt_macs = {m: v for m, v in mac_events.items() if vendor(m) == 'UBNT'}
mkt_macs  = {m: v for m, v in mac_events.items() if vendor(m) == 'MikroTik'}
other_macs = {m: v for m, v in mac_events.items()
              if vendor(m) not in ('UBNT', 'MikroTik')}

# ── MikroTik (resumen) ──────────────────────────────────────────────────────
print(f"\n--- MikroTik ({len(mkt_macs)} MACs) ---")
for mac, events in sorted(mkt_macs.items(), key=lambda x: -len(x[1])):
    ts_list = [float(e[0]) for e in events if re.match(r'^\d+\.\d+$', e[0])]
    if len(ts_list) >= 2:
        intervals = [ts_list[i+1] - ts_list[i] for i in range(len(ts_list)-1)]
        avg_interval = sum(intervals) / len(intervals)
        interval_str = f"  intervalo~{avg_interval:.1f}s"
    else:
        interval_str = ""
    print(f"  {mac}  {len(events):3d} pkts{interval_str}")

# ── UBNT ────────────────────────────────────────────────────────────────────
print(f"\n--- UBNT ({len(ubnt_macs)} MACs) ---")
if not ubnt_macs:
    print("  (ningún UBNT emitió MNDP en 90s)")
else:
    for mac, events in sorted(ubnt_macs.items(), key=lambda x: -len(x[1])):
        ts_list = [float(e[0]) for e in events if re.match(r'^\d+\.\d+$', e[0])]
        if len(ts_list) >= 2:
            intervals = [ts_list[i+1] - ts_list[i] for i in range(len(ts_list)-1)]
            avg_interval = sum(intervals) / len(intervals)
            interval_str = f"  intervalo~{avg_interval:.1f}s"
            ts_str = f"  @t={','.join(f'{t:.1f}' for t in ts_list)}"
        else:
            interval_str = ""
            ts_str = f"  @t={ts_list[0]:.1f}" if ts_list else ""
        print(f"  {mac}  ({vendor(mac)})  {len(events)} pkts{interval_str}{ts_str}")

# ── Otros ───────────────────────────────────────────────────────────────────
if other_macs:
    print(f"\n--- Otros ({len(other_macs)} MACs) ---")
    for mac, events in sorted(other_macs.items(), key=lambda x: -len(x[1])):
        print(f"  {mac}  ({vendor(mac)})  {len(events)} pkts")

# ── Neighbor UBNT actuales ───────────────────────────────────────────────────
print(f"\n--- Vecinos UBNT en /ip neighbor (confirma datos del MNDP recibido) ---")
c2 = connect()
raw_n = ssh_cmd(c2, "/ip neighbor print detail", timeout=15)
c2.close()

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
    ver   = re.search(r'version="?([^"\s,]+)"?', block)
    plat  = re.search(r'platform="([^"]*)"', block)
    age   = re.search(r'age=(\S+)', block)
    iface_name = re.search(r'interface-name="([^"]*)"', block)
    in_mndp = mac in ubnt_macs
    flag = "  [MNDP capturado ✓]" if in_mndp else "  [no capturado]"
    print(f"  {mac}  age={age.group(1) if age else '?':8s}  "
          f"{(ident.group(1) or '(sin nombre)'):25s}  "
          f"{(ver.group(1) if ver else ''):20s}  "
          f"{(plat.group(1) if plat else '')}{flag}")

print("\n=== Fin ===")
