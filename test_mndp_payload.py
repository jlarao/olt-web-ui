"""
Verifica si los paquetes MNDP de los MikroTiks intermedios contienen
datos de vecinos UBNT embebidos (MNDP proxy/relay).

Método: capturar el tráfico UDP:5678 con archivo pcap en el MikroTik,
luego leer los primeros bytes para detectar si hay múltiples TLVs UBNT.
También: capturar ALL traffic desde una MAC UBNT específica para ver si emite algo.
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

# UBNT manzanal ap — visible en neighbor pero nunca capturado en sniffer
UBNT_AP_MAC = 'DC:9F:DB:08:CD:F2'

def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS,
              timeout=10, look_for_keys=False, allow_agent=False)
    return c

def ssh_cmd(client, cmd, timeout=120):
    _, stdout, _ = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode('utf-8', errors='replace')

client = connect()

# 1. ¿Qué envía la MAC UBNT "manzanal ap"? Todo tráfico, no solo MNDP
print(f"=== Todo el tráfico de {UBNT_AP_MAC} (30s) ===")
out = ssh_cmd(client,
    f"/tool sniffer quick filter-mac-address={UBNT_AP_MAC} duration=30",
    timeout=45)
lines = [l for l in out.splitlines() if '<-' in l or '->' in l]
if lines:
    proto_count = {}
    for l in lines:
        print(" ", l[:120])
    print(f"\n  Total: {len(lines)} paquetes desde/hacia {UBNT_AP_MAC}")
else:
    print(f"  NINGÚN paquete detectado desde/hacia {UBNT_AP_MAC} en 30s")

# 2. Comprobar: ¿el MikroTik intermedio (serrano 08:55:31:A3:CE:84) envía MNDP
#    en nombre del UBNT? Capturar SRC=08:55:31:A3:CE:84 en UDP:5678
SERRANO_MAC = '08:55:31:A3:CE:84'  # identity="serrano"
print(f"\n=== Paquetes MNDP de 'serrano' ({SERRANO_MAC}) durante 30s ===")
out2 = ssh_cmd(client,
    f"/tool sniffer quick filter-mac-address={SERRANO_MAC} port=5678 duration=30",
    timeout=45)
lines2 = [l for l in out2.splitlines() if '<-' in l or '->' in l]
print(f"  Total paquetes MNDP de serrano: {len(lines2)}")

# 3. Sniffer con archivo pcap para leer bytes del payload
#    (RouterOS guarda pcap en RAM que podemos leer con /tool sniffer packet print)
print(f"\n=== Capture UDP:5678 con payload (10s) ===")
ssh_cmd(client, "/tool sniffer stop", timeout=5)
ssh_cmd(client,
    "/tool sniffer set filter-port=5678 filter-direction=rx only-headers=no memory-limit=2048",
    timeout=5)
ssh_cmd(client, "/tool sniffer start", timeout=5)
time.sleep(10)
ssh_cmd(client, "/tool sniffer stop", timeout=5)

# Leer paquetes con contenido
raw_pkts = ssh_cmd(client,
    "/tool sniffer packet print detail",
    timeout=20)
print(f"  Bytes capturados (primeros 3000 chars):")
print(raw_pkts[:3000])

# 4. Ver qué interfaces tiene el MikroTik "serrano" directamente
print(f"\n=== MAC scan de la subred (10s) para ver vecinos de serrano ===")
mac_scan = ssh_cmd(client,
    "/tool mac-scan interface=ether7 duration=5",
    timeout=20)
print(mac_scan[:1500])

client.close()
print("\n=== Fin ===")
