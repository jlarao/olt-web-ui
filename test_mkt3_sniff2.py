"""
Captura extendida (35s) en MKT3 para atrapar broadcasts MNDP de UBNT.
También captura todo UDP:10001 para ver si hay discovery UBNT.
"""
import sys, io, time, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

import paramiko
from dotenv import load_dotenv
import os

load_dotenv()

HOST = os.getenv('M2_HOST', '10.10.11.3')
PORT = int(os.getenv('M2_PORT', 22))
USER = os.getenv('M2_USER', 'admin')
PASS = os.getenv('M2_PASS', '')

# MACs UBNT que se ven en bridge/neighbor
UBNT_MACS = {
    'DC:9F:DB:08:CD:F2',  # manzanal ap NanoBridge M900 XM.v6.1.9
    '68:72:51:84:E7:15',  # manzanal station NanoStation Loco M900 XM.v5.6.11
    '24:5A:4C:B5:C2:95',  # UBNT AC (sin identity en neighbor)
    '24:5A:4C:DB:78:60',  # UBNT AC (sin identity en neighbor)
    'E4:38:83:B1:2A:E7',  # desconocido
}

def ssh_cmd(client, cmd, timeout=45):
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode('utf-8', errors='replace')
    err = stderr.read().decode('utf-8', errors='replace')
    return out

def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS,
              timeout=10, look_for_keys=False, allow_agent=False)
    return c

print(f"=== MKT3 {HOST}:{PORT} — Sniffer extendido 35s ===\n")
client = connect()

# Sniffer quick: UDP:5678 (MNDP) por 35 segundos
print("--- Capturando UDP:5678 (MNDP) por 35s (ciclo normal UBNT = 30s) ---")
out_mndp = ssh_cmd(client, "/tool sniffer quick port=5678 duration=35", timeout=50)

mndp_lines = [l for l in out_mndp.splitlines() if '<-' in l or '->' in l]
print(f"  Total paquetes MNDP: {len(mndp_lines)}")
print()

# Agrupar por MAC origen
from collections import Counter
macs_mndp = Counter()
for l in mndp_lines:
    m = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})\s+FF:FF:FF:FF:FF:FF', l)
    if m:
        macs_mndp[m.group(1).upper()] += 1

print("  MACs que enviaron broadcast MNDP (UDP:5678):")
for mac, cnt in sorted(macs_mndp.items(), key=lambda x: -x[1]):
    ubnt_flag = " *** UBNT ***" if mac in UBNT_MACS else ""
    print(f"    {mac}  ({cnt} paquetes){ubnt_flag}")

# Mostrar RAW primeras 30 líneas con paquetes
print("\n  Raw (primeras 30 líneas con paquetes):")
for l in [x for x in out_mndp.splitlines() if '<-' in x or '->' in x][:30]:
    print(" ", l)

# Sniffer quick: UDP:10001 (UBNT discovery) por 15s
print("\n--- Capturando UDP:10001 (UBNT discovery) por 15s ---")
out_ubnt = ssh_cmd(client, "/tool sniffer quick port=10001 duration=15", timeout=30)

ubnt_lines = [l for l in out_ubnt.splitlines() if '<-' in l or '->' in l]
print(f"  Total paquetes UDP:10001: {len(ubnt_lines)}")
for l in ubnt_lines[:20]:
    print(" ", l)

# Neighbor actual con edad
print("\n--- Neighbor table (estado actual) ---")
raw_n = ssh_cmd(client, "/ip neighbor print detail", timeout=15)
# Buscar entradas UBNT
for block in re.split(r'\n\s*\d+\s+', '\n' + raw_n):
    if not block.strip():
        continue
    if any(oui in block.upper() for oui in
           ['DC:9F:DB', '68:72:51', '20:23:51', '24:2F:D0', '80:2A:A8',
            '24:5A:4C', '24:A4:3C', 'B0:4E:26', '5C:E9:31', '28:EE:52']):
        lines = [l.strip() for l in block.splitlines() if l.strip()]
        print("  [UBNT/AC]", " | ".join(lines[:4]))

print("\n=== Fin ===")
client.close()
