"""
Audita la configuración de neighbor discovery en MKT1 vs MKT3.
Busca: settings, firewall, bridge config, versión RouterOS, diferencias.
"""
import sys, io, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
import paramiko
from dotenv import load_dotenv
import os

load_dotenv()

ROUTERS = [
    {
        'label': 'MKT1 (10.10.11.1:12222)',
        'host': os.getenv('M1_HOST', '10.10.11.1'),
        'port': int(os.getenv('M1_PORT', 12222)),
        'user': os.getenv('M1_USER', 'admin'),
        'pass': os.getenv('M1_PASS', ''),
    },
    {
        'label': 'MKT3 (10.10.11.3:22)',
        'host': os.getenv('M2_HOST', '10.10.11.3'),
        'port': int(os.getenv('M2_PORT', 22)),
        'user': os.getenv('M2_USER', 'admin'),
        'pass': os.getenv('M2_PASS', ''),
    },
]

def connect(h):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h['host'], port=h['port'], username=h['user'], password=h['pass'],
              timeout=10, look_for_keys=False, allow_agent=False)
    return c

def cmd(client, command, timeout=15):
    _, stdout, _ = client.exec_command(command, timeout=timeout)
    return stdout.read().decode('utf-8', errors='replace').strip()

CHECKS = [
    ("RouterOS version",
     "/system resource print"),

    ("Neighbor discovery settings",
     "/ip neighbor discovery-settings print"),

    ("Interface-list 'static' (debe incluir bridge1)",
     "/interface list member print terse where list=static"),

    ("Interfaces con discovery habilitado",
     "/ip neighbor print count-only"),

    ("Neighbor discovery por interfaz",
     "/ip neighbor discovery print terse"),

    ("Bridge1 config",
     "/interface bridge print detail where name=bridge1"),

    ("Firewall INPUT — reglas que afectan UDP:5678",
     "/ip firewall filter print terse where dst-port=5678 or src-port=5678 or protocol=udp"),

    ("Firewall RAW — reglas UDP",
     "/ip firewall raw print terse where dst-port=5678 or src-port=5678"),

    ("Neighbors actuales (count)",
     "/ip neighbor print count-only"),

    ("Neighbors por protocolo (detail primeras 5)",
     "/ip neighbor print detail count-only"),

    ("Interfaces del bridge",
     "/interface bridge port print terse"),

    ("Interfaces en interface-list 'all' y 'static'",
     "/interface list print"),

    ("CDP habilitado",
     "/ip neighbor discovery-settings print"),

    ("Parámetros de LLDP (RouterOS 7)",
     "/interface lldp print"),
]

results = {}

for router in ROUTERS:
    print(f"\n{'='*65}")
    print(f"=== {router['label']} ===")
    print(f"{'='*65}")
    results[router['label']] = {}

    try:
        client = connect(router)
    except Exception as e:
        print(f"  [ERROR conexión] {e}")
        continue

    for title, command in CHECKS:
        try:
            out = cmd(client, command)
            results[router['label']][title] = out
            print(f"\n[{title}]")
            if out:
                for line in out.splitlines()[:20]:
                    print(f"  {line}")
            else:
                print("  (sin resultado)")
        except Exception as e:
            results[router['label']][title] = f"ERROR: {e}"
            print(f"\n[{title}]")
            print(f"  ERROR: {e}")

    # Extra: neighbor discovery por interfaz (detalle)
    print(f"\n[Neighbor discovery habilitado por interfaz]")
    try:
        nd = cmd(client, "/ip neighbor discovery print")
        print(nd[:1500] if nd else "  (sin resultado)")
    except Exception as e:
        print(f"  ERROR: {e}")

    # Extra: versión exacta y board
    print(f"\n[Board y versión]")
    try:
        board = cmd(client, "/system routerboard print")
        print(board[:500] if board else "  (sin resultado)")
    except Exception as e:
        print(f"  ERROR: {e}")

    client.close()

# Comparativa de settings clave
print(f"\n\n{'='*65}")
print("=== COMPARATIVA DE SETTINGS CRÍTICOS ===")
print(f"{'='*65}")

key = "Neighbor discovery settings"
for label, data in results.items():
    print(f"\n{label} — {key}:")
    print(data.get(key, 'N/A'))

key2 = "Interface-list 'static' (debe incluir bridge1)"
for label, data in results.items():
    print(f"\n{label} — {key2}:")
    print(data.get(key2, 'N/A'))

key3 = "Firewall INPUT — reglas que afectan UDP:5678"
for label, data in results.items():
    print(f"\n{label} — Firewall UDP:5678:")
    print(data.get(key3, 'N/A') or '  (sin reglas)')

print("\n=== Fin ===")
