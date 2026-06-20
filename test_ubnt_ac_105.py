"""
Detecta si E4:38:83:B0:17:B0 (UBNT AC 192.168.3.105) usa discovery.
Prueba CDP, LLDP, MNDP y UDP:10001 en paralelo via MKT1.
"""
import sys, io, time, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
import paramiko
from dotenv import load_dotenv
import os

load_dotenv()

HOST = os.getenv('M1_HOST'); PORT = int(os.getenv('M1_PORT', 12222))
USER = os.getenv('M1_USER'); PASS = os.getenv('M1_PASS', '')

TARGET_MAC = 'E4:38:83:B0:17:B0'
TARGET_IP  = '192.168.3.105'

def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS,
              timeout=10, look_for_keys=False, allow_agent=False)
    return c

def cmd(c, command, timeout=90):
    _, stdout, _ = c.exec_command(command, timeout=timeout)
    return stdout.read().decode('utf-8', errors='replace').strip()

def found_target(raw, mac=TARGET_MAC):
    return mac.upper() in raw.upper() or TARGET_IP in raw

def parse_pkts(raw, only_rx=True):
    lines = []
    for l in raw.splitlines():
        if ('<-' in l or '->' in l) and 'bridge1' not in l:
            if only_rx and '<-' not in l:
                continue
            lines.append(l)
    return lines

print(f"=== UBNT AC {TARGET_IP} ({TARGET_MAC}) — detección de discovery ===\n")

# ── Ronda 1: CDP (65s) ──────────────────────────────────────────────────────
print("[1] CDP — 65s (ciclo airOS = 60s)")
c = connect()
cdp = cmd(c, "/tool sniffer quick mac-protocol=cdp duration=65", timeout=80)
cdp_pkts = parse_pkts(cdp)
target_cdp = [l for l in cdp_pkts if TARGET_MAC.upper()[:8] in l.upper() or TARGET_MAC.upper() in l.upper()]
print(f"  Total CDP recibidos: {len(cdp_pkts)}")
if target_cdp:
    print(f"  *** UBNT AC encontrado en CDP! ***")
    for l in target_cdp:
        print(" ", l)
else:
    # Mostrar todos los CDP para ver quién sí manda
    macs_cdp = set()
    for l in cdp_pkts:
        m = re.search(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', l)
        if m: macs_cdp.add(m.group(1).upper())
    if macs_cdp:
        print(f"  MACs que enviaron CDP (no el target): {', '.join(sorted(macs_cdp))}")
    else:
        print("  (ningún dispositivo envió CDP)")

# Neighbor check intermedio
neigh_mid = cmd(c, f"/ip neighbor print detail where address={TARGET_IP}")
if neigh_mid.strip():
    print(f"\n  *** Aparecio en neighbor! ***")
    print(neigh_mid[:400])
else:
    print(f"  (no en neighbor todavía)")
c.close()

# ── Ronda 2: LLDP (65s) ─────────────────────────────────────────────────────
print("\n[2] LLDP — 65s")
c = connect()
lldp = cmd(c, "/tool sniffer quick mac-protocol=lldp duration=65", timeout=80)
lldp_pkts = parse_pkts(lldp)
target_lldp = [l for l in lldp_pkts if TARGET_MAC.upper()[:8] in l.upper() or TARGET_MAC.upper() in l.upper()]
print(f"  Total LLDP recibidos: {len(lldp_pkts)}")
if target_lldp:
    print(f"  *** UBNT AC encontrado en LLDP! ***")
    for l in target_lldp:
        print(" ", l)
else:
    macs_lldp = set()
    for l in lldp_pkts:
        m = re.search(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', l)
        if m and not m.group(1).upper().startswith('01:80'):
            macs_lldp.add(m.group(1).upper())
    non_mkt = {m for m in macs_lldp if not m.startswith('CC:2D:E0')}
    if non_mkt:
        print(f"  Otros dispositivos en LLDP: {', '.join(sorted(non_mkt))}")
    else:
        print("  (solo LLDP del propio MKT1 — ningún UBNT AC)")
c.close()

# ── Ronda 3: MNDP UDP:5678 + UDP:10001 (30s cada uno) ─────────────────────
print("\n[3] MNDP UDP:5678 — 30s")
c = connect()
mndp = cmd(c, "/tool sniffer quick port=5678 duration=30", timeout=45)
mndp_rx = [l for l in mndp.splitlines()
           if '<-' in l and 'bridge1' not in l]
target_mndp = [l for l in mndp_rx
               if TARGET_MAC.upper()[:8] in l.upper() or TARGET_MAC.upper() in l.upper()]
print(f"  Total MNDP recibidos: {len(mndp_rx)}")
if target_mndp:
    print(f"  *** UBNT AC encontrado en MNDP! ***")
    for l in target_mndp: print(" ", l)
else:
    macs_mndp = set()
    for l in mndp_rx:
        m = re.search(r'<-\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', l)
        if m: macs_mndp.add(m.group(1).upper())
    non_mkt = {m for m in macs_mndp if not m.startswith('CC:2D:E0')}
    print(f"  Otros en MNDP: {', '.join(sorted(non_mkt)) if non_mkt else '(ninguno)'}")

print("\n[4] UDP:10001 (UBNT discovery) — 30s")
u10001 = cmd(c, "/tool sniffer quick port=10001 duration=30", timeout=45)
u10001_pkts = [l for l in u10001.splitlines() if '<-' in l and 'bridge1' not in l]
print(f"  Total UDP:10001 recibidos: {len(u10001_pkts)}")
if u10001_pkts:
    for l in u10001_pkts[:10]: print(" ", l)

# ── Neighbor final ────────────────────────────────────────────────────────
print(f"\n[5] Neighbor table final")
neigh_final = cmd(c, "/ip neighbor print detail")
if TARGET_IP in neigh_final or TARGET_MAC.upper() in neigh_final.upper():
    for block in re.split(r'\n\s*\d+\s+', '\n' + neigh_final):
        if TARGET_IP in block or TARGET_MAC.upper() in block.upper():
            print("  *** Encontrado en neighbor! ***")
            print(block[:500])
else:
    # Contar UBNT totales
    ubnt_oui = {'FC:EC:DA','68:72:51','80:2A:A8','DC:9F:DB','24:A4:3C',
                '20:23:51','24:5A:4C','E0:63:DA','44:D9:E7','F0:9F:C2',
                'E4:38:83'}
    ubnt_n = sum(1 for b in re.split(r'\n\s*\d+\s+', '\n' + neigh_final)
                 if any(o in b.upper() for o in ubnt_oui))
    print(f"  {TARGET_IP} no en neighbor. UBNT totales en neighbor: {ubnt_n}")

c.close()
print("\n=== Fin ===")
