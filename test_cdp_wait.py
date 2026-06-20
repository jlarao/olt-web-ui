"""
Monitoreo continuo CDP/LLDP en MKT1 para FC:EC:DA:6C:BA:47 (192.168.3.102).
Corre 3 rondas de 65s cada una con neighbor check entre rondas.
"""
import sys, io, time, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
import paramiko
from dotenv import load_dotenv
import os
from collections import Counter

load_dotenv()

HOST = os.getenv('M1_HOST', '10.10.11.1')
PORT = int(os.getenv('M1_PORT', 12222))
USER = os.getenv('M1_USER', 'admin')
PASS = os.getenv('M1_PASS', '')

TARGET_MAC  = 'FC:EC:DA:6C:BA:47'
TARGET_IP   = '192.168.3.102'

def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS,
              timeout=10, look_for_keys=False, allow_agent=False)
    return c

def cmd(c, command, timeout=90):
    _, stdout, _ = c.exec_command(command, timeout=timeout)
    return stdout.read().decode('utf-8', errors='replace').strip()

def check_neighbor(c):
    raw = cmd(c, "/ip neighbor print detail")
    if TARGET_IP in raw or TARGET_MAC.upper() in raw.upper():
        for block in re.split(r'\n\s*\d+\s+', '\n' + raw):
            if TARGET_IP in block or TARGET_MAC.upper() in block.upper():
                return "✓ APARECIO EN NEIGHBOR:\n" + block[:400]
    return f"  (no aparece en neighbor — total vecinos: {raw.count('mac-address=')})"

def parse_macs(sniffer_out, exclude_prefix=None):
    macs = Counter()
    for l in sniffer_out.splitlines():
        if '<-' not in l and '->' not in l:
            continue
        if 'bridge1' in l:
            continue
        parts = l.split()
        for p in parts:
            if re.match(r'^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}', p) and p.count(':') == 5:
                mac = p.upper()
                if exclude_prefix and mac.startswith(exclude_prefix):
                    break
                macs[mac] += 1
                break
    return macs

print(f"=== Monitor CDP/LLDP en MKT1 para UBNT {TARGET_IP} ({TARGET_MAC}) ===")
print(f"    3 rondas x 65s CDP + 30s LLDP cada una\n")

for ronda in range(1, 4):
    print(f"\n{'─'*55}")
    print(f"RONDA {ronda}")
    print(f"{'─'*55}")
    c = connect()

    # Neighbor check antes
    print(f"\n[Neighbor antes]")
    print(check_neighbor(c))

    # CDP 65s
    print(f"\n[Sniffer CDP — 65s]")
    cdp_raw = cmd(c, "/tool sniffer quick mac-protocol=cdp duration=65", timeout=80)
    cdp_pkts = [l for l in cdp_raw.splitlines()
                if ('<-' in l or '->' in l) and 'bridge1' not in l]
    cdp_macs = parse_macs(cdp_raw, exclude_prefix='01:00:0C')
    print(f"  Total paquetes CDP: {len(cdp_pkts)}")
    if TARGET_MAC.upper() in cdp_macs:
        print(f"  *** UBNT {TARGET_MAC} ENVIO CDP: {cdp_macs[TARGET_MAC.upper()]} pkts ***")
    elif cdp_macs:
        for mac, cnt in sorted(cdp_macs.items(), key=lambda x: -x[1])[:5]:
            print(f"  {mac}  ({cnt} pkts)")
    else:
        print("  (ningún dispositivo envió CDP)")

    # LLDP 30s
    print(f"\n[Sniffer LLDP — 30s]")
    lldp_raw = cmd(c, "/tool sniffer quick mac-protocol=lldp duration=30", timeout=45)
    lldp_pkts = [l for l in lldp_raw.splitlines()
                 if ('<-' in l or '->' in l) and 'bridge1' not in l]
    lldp_macs = parse_macs(lldp_raw, exclude_prefix='01:80:C2')
    print(f"  Total paquetes LLDP: {len(lldp_pkts)}")
    if TARGET_MAC.upper() in lldp_macs:
        print(f"  *** UBNT {TARGET_MAC} ENVIO LLDP: {lldp_macs[TARGET_MAC.upper()]} pkts ***")
    else:
        # Mostrar solo los que NO son el propio MKT1
        ubnt_lldp = {m: v for m, v in lldp_macs.items() if not m.startswith('CC:2D:E0')}
        if ubnt_lldp:
            for mac, cnt in sorted(ubnt_lldp.items(), key=lambda x: -x[1])[:5]:
                print(f"  {mac}  ({cnt} pkts)  ← NO es MKT1")
        else:
            print("  (solo LLDP del propio MKT1 — ningún UBNT)")

    # UDP:5678 rápido 15s
    print(f"\n[Sniffer UDP:5678 — 15s]")
    mndp_raw = cmd(c, "/tool sniffer quick port=5678 duration=15", timeout=30)
    mndp_pkts = [l for l in mndp_raw.splitlines()
                 if ('<-' in l or '->' in l) and 'bridge1' not in l]
    mndp_macs = parse_macs(mndp_raw, exclude_prefix='CC:2D:E0')
    mndp_macs_all = parse_macs(mndp_raw)
    incoming = {m: v for m, v in mndp_macs_all.items()
                if any(f' <- {m}' in l for l in mndp_pkts)}
    if TARGET_MAC.upper() in incoming:
        print(f"  *** UBNT {TARGET_MAC} ENVIO MNDP UDP:5678! ***")
    else:
        non_mkt = {m: v for m, v in mndp_macs_all.items()
                   if not m.startswith('CC:2D:E0') and '<-' in mndp_raw}
        if non_mkt:
            for mac, cnt in sorted(non_mkt.items(), key=lambda x: -x[1])[:5]:
                print(f"  {mac}  ({cnt} pkts) recibidos en MKT1")
        else:
            print(f"  {len(mndp_pkts)} pkts total — ninguno de {TARGET_MAC}")

    # Neighbor check final
    print(f"\n[Neighbor después de ronda {ronda}]")
    print(check_neighbor(c))
    c.close()

print("\n=== Fin del monitoreo ===")
print(f"\nResumen: si {TARGET_MAC} no aparece en ninguna ronda,")
print("el UBNT requiere reboot o la configuración CDP/LLDP está en otra interfaz.")
