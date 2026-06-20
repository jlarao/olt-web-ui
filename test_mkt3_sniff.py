"""
Captura paquetes MNDP (UDP:5678) y UBNT discovery (UDP:10001) en MKT3 (10.10.11.3).
Muestra qué envían los equipos UBNT que aparecen en /ip neighbor allí.
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

def ssh_cmd(client, cmd, timeout=20):
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode('utf-8', errors='replace')
    err = stderr.read().decode('utf-8', errors='replace')
    if err.strip():
        print(f"  [stderr] {err.strip()}")
    return out

def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS,
              timeout=10, look_for_keys=False, allow_agent=False)
    return c

print(f"=== Conectando a MKT3 {HOST}:{PORT} ===\n")
client = connect()

# 1. Interfaces disponibles
print("--- Interfaces ---")
print(ssh_cmd(client, "/interface print terse"))

# 2. Bridge host table (MACs conectadas)
print("\n--- Bridge hosts (primeros 40) ---")
raw_bridge = ssh_cmd(client, "/interface bridge host print terse count-only")
print(f"  Total MACs: {raw_bridge.strip()}")
raw_bridge = ssh_cmd(client, "/interface bridge host print terse")
lines = raw_bridge.splitlines()
print(f"  Mostrando primeras 40 líneas de {len(lines)} total:")
for l in lines[:40]:
    print(" ", l)

# 3. Vecinos MNDP actuales
print("\n--- /ip neighbor print detail ---")
raw_neigh = ssh_cmd(client, "/ip neighbor print detail")
print(raw_neigh[:3000])

# 4. Sniffer en UDP:5678 y UDP:10001 durante 12 segundos
print("\n=== Captura de paquetes MNDP (UDP:5678) y UBNT (UDP:10001) por 12s ===")
print("  Configurando sniffer...")

# Detectar interfaz de bridge
bridge_iface = 'bridge1'
if 'bridge' in raw_bridge.lower():
    m = re.search(r'bridge=(\S+)', raw_bridge)
    if m:
        bridge_iface = m.group(1)

# Configurar y arrancar sniffer
ssh_cmd(client, "/tool sniffer stop", timeout=5)
ssh_cmd(client, f"/tool sniffer set filter-port=5678,10001 file-name=\"\" filter-direction=rx streaming-enabled=no", timeout=5)
ssh_cmd(client, "/tool sniffer start", timeout=5)

print(f"  Capturando 12 segundos en {HOST}...")
time.sleep(12)

ssh_cmd(client, "/tool sniffer stop", timeout=5)

# Leer estadísticas del sniffer
print("\n--- Estadísticas del sniffer ---")
stats = ssh_cmd(client, "/tool sniffer print", timeout=10)
print(stats)

# Leer paquetes capturados
print("\n--- Paquetes capturados (sniffer packet print) ---")
packets = ssh_cmd(client, "/tool sniffer packet print", timeout=15)
if packets.strip():
    for line in packets.splitlines()[:80]:
        print(" ", line)
else:
    print("  (sin paquetes — sniffer puede requerir interfaz específica)")

# 5. Sniffer por interfaz con filter-ip-protocol=udp
print("\n=== Captura alternativa: /tool sniffer quick port=5678,10001 ===")
quick = ssh_cmd(client, "/tool sniffer quick port=5678,10001 duration=10", timeout=25)
if quick.strip():
    for line in quick.splitlines()[:60]:
        print(" ", line)
else:
    print("  (sin resultados con sniffer quick)")

# 6. ARP table para ver IPs de UBNT
print("\n--- ARP table ---")
arp = ssh_cmd(client, "/ip arp print terse")
print(arp[:2000])

client.close()
print("\n=== Fin ===")
