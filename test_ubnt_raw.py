"""
Captura TODO el tráfico sin filtros para ver qué protocolo usa el UBNT "manzanal ap".
MAC: DC:9F:DB:08:CD:F2, IP: 192.168.2.12
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

def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS,
              timeout=10, look_for_keys=False, allow_agent=False)
    return c

def ssh_cmd(client, cmd, timeout=90):
    _, stdout, _ = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode('utf-8', errors='replace')

client = connect()

# 1. Sniffer sin filtro de puerto para DC:9F:DB:08:CD:F2
# RouterOS sniffer quick no tiene filtro por IP, solo por MAC/port/protocol
print("=== Sniffer sin filtro de puerto — todo lo que envía manzanal ap (60s) ===")
out = ssh_cmd(client,
    "/tool sniffer quick filter-mac-address=DC:9F:DB:08:CD:F2 duration=60",
    timeout=75)
lines = [l for l in out.splitlines() if '<-' in l or '->' in l]
if lines:
    for l in lines[:50]:
        print(" ", l)
    print(f"\n  Total paquetes: {len(lines)}")
else:
    print("  NINGÚN paquete")

# 2. Captura con sniffer tradicional (no quick) + packet print
print("\n=== Sniffer con archivo en RAM — UDP desde 192.168.2.12 (15s) ===")
ssh_cmd(client, "/tool sniffer stop", timeout=5)
ssh_cmd(client,
    "/tool sniffer set filter-ip-address=192.168.2.12/32 filter-ip-protocol=udp "
    "filter-direction=rx only-headers=no memory-limit=4096 file-name=\"\"",
    timeout=5)
ssh_cmd(client, "/tool sniffer start", timeout=5)
print("  Capturando 15s...")
time.sleep(15)
ssh_cmd(client, "/tool sniffer stop", timeout=5)

pkt_detail = ssh_cmd(client, "/tool sniffer packet print detail", timeout=15)
if pkt_detail.strip():
    print(pkt_detail[:4000])
else:
    print("  (sin paquetes UDP de 192.168.2.12)")

# 3. Probar: ¿el daemon MNDP hace un request activo y UBNT responde unicast?
# Si el sniffer del MikroTik no ve el tráfico broadcast, puede ser que el
# daemon MNDP usa un socket RAW que no pasa por el sniffer
# Verificar con torch (traffic monitor) — muestra estadísticas de tráfico
print("\n=== /tool torch interface=ether7 src-address=192.168.2.12 duration=10 ===")
torch_out = ssh_cmd(client,
    "/tool torch interface=ether7 src-address=192.168.2.12 duration=10",
    timeout=20)
print(torch_out[:2000] if torch_out.strip() else "  (sin tráfico)")

# 4. Firewall connection tracking para ver si hay sesiones UDP desde UBNT
print("\n=== Connection tracking desde 192.168.2.0/24 ===")
conn = ssh_cmd(client,
    "/ip firewall connection print terse where src-address~\"192.168.2.\"",
    timeout=10)
udp_lines = [l for l in conn.splitlines()
             if 'udp' in l.lower() or '5678' in l or '10001' in l]
if udp_lines:
    for l in udp_lines[:20]:
        print(" ", l)
else:
    print(conn[:1000] if conn.strip() else "  (sin conexiones registradas)")

client.close()
print("\n=== Fin ===")
