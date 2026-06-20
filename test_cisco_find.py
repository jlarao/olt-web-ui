import sys, io, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
import paramiko
from dotenv import load_dotenv
import os

load_dotenv()

HOST = os.getenv('M1_HOST'); PORT = int(os.getenv('M1_PORT', 12222))
USER = os.getenv('M1_USER'); PASS = os.getenv('M1_PASS', '')
CISCO_OUI = 'C0:64:E4'

def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS,
              timeout=10, look_for_keys=False, allow_agent=False)
    return c

def cmd(c, command, timeout=20):
    _, stdout, _ = c.exec_command(command, timeout=timeout)
    return stdout.read().decode('utf-8', errors='replace').strip()

c = connect()

# 1. ARP completo — todas las subredes
print("=== ARP completo (buscando C0:64:E4) ===")
arp = cmd(c, "/ip arp print terse")
cisco_arp = [l for l in arp.splitlines() if 'c0:64:e4' in l.lower()]
if cisco_arp:
    for l in cisco_arp:
        print(" ", l)
else:
    print("  No está en ARP — intentando generar tráfico con ping...")
    # Ping a IPs comunes de Cisco por defecto
    for ip in ['192.168.1.254', '192.168.1.1', '192.168.3.1', '192.168.3.254']:
        cmd(c, f"/ping {ip} count=2", timeout=8)
    arp2 = cmd(c, "/ip arp print terse")
    cisco_arp2 = [l for l in arp2.splitlines() if 'c0:64:e4' in l.lower()]
    if cisco_arp2:
        print("  Encontrado tras ping:")
        for l in cisco_arp2:
            print(" ", l)

# 2. Subredes configuradas en MKT1
print("\n=== Subredes en MKT1 ===")
routes = cmd(c, "/ip address print terse")
print(routes)

# 3. mac-scan en todas las interfaces
print("\n=== mac-scan bridge1 extendido (8s) ===")
ms = cmd(c, "/tool mac-scan interface=bridge1 duration=8", timeout=20)
cisco_ms = [l for l in ms.splitlines() if 'c0:64:e4' in l.lower()]
for l in cisco_ms:
    print(" ", l)
# Mostrar entradas con IP para contexto
with_ip = [l for l in ms.splitlines() if re.search(r'\d+\.\d+\.\d+\.\d+', l)]
print(f"  ({len(with_ip)} dispositivos con IP, {len(ms.splitlines())} total)")

# 4. Neighbor detail completo del Cisco
print("\n=== Neighbor Cisco (detalle completo) ===")
neigh = cmd(c, "/ip neighbor print detail")
for block in re.split(r'\n\s*\d+\s+', '\n' + neigh):
    if 'c0:64:e4' in block.lower() or 'cisco' in block.lower() or 'sg220' in block.lower():
        print(block[:600])

c.close()
