"""
Captura CDP y LLDP en MKT1 y MKT3.
UBNT airOS usa CDP/LLDP (no MNDP) para anunciarse en el neighbor de RouterOS.
"""
import sys, io, time, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

import paramiko
from dotenv import load_dotenv
import os

load_dotenv()

ROUTERS = [
    {
        'label': 'MKT1 (10.10.11.1)',
        'host': os.getenv('M1_HOST', '10.10.11.1'),
        'port': int(os.getenv('M1_PORT', 12222)),
        'user': os.getenv('M1_USER', 'admin'),
        'pass': os.getenv('M1_PASS', ''),
    },
    {
        'label': 'MKT3 (10.10.11.3)',
        'host': os.getenv('M2_HOST', '10.10.11.3'),
        'port': int(os.getenv('M2_PORT', 22)),
        'user': os.getenv('M2_USER', 'admin'),
        'pass': os.getenv('M2_PASS', ''),
    },
]

def ssh_cmd(client, cmd, timeout=45):
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode('utf-8', errors='replace')
    return out

def connect(h):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(h['host'], port=h['port'], username=h['user'], password=h['pass'],
              timeout=10, look_for_keys=False, allow_agent=False)
    return c

def mac_vendor(mac):
    oui = mac.upper()[:8]
    vendors = {
        '08:55:31': 'MikroTik', '18:FD:74': 'MikroTik', 'CC:2D:E0': 'MikroTik',
        '6C:3B:6B': 'MikroTik', '48:8F:5A': 'MikroTik', '4C:5E:0C': 'MikroTik',
        '00:0C:42': 'MikroTik', '2C:C8:1B': 'MikroTik',
        '68:72:51': 'UBNT-Legacy', '80:2A:A8': 'UBNT-Legacy', 'DC:9F:DB': 'UBNT-Legacy',
        '24:A4:3C': 'UBNT-Legacy', '20:23:51': 'UBNT-Legacy', '24:2F:D0': 'UBNT-Legacy',
        'B0:4E:26': 'UBNT-Legacy', '5C:E9:31': 'UBNT-Legacy', '28:EE:52': 'UBNT-Legacy',
        '24:5A:4C': 'UBNT-AC', '60:22:32': 'UBNT-AC', '68:D7:9A': 'UBNT-AC',
        '58:C1:7A': 'Cambium',
    }
    return vendors.get(oui, '?')

for router in ROUTERS:
    print(f"\n{'='*60}")
    print(f"=== {router['label']} ===")
    print(f"{'='*60}")

    try:
        client = connect(router)
    except Exception as e:
        print(f"  [ERROR] No se pudo conectar: {e}")
        continue

    # ── CDP capture via sniffer quick (EtherType / CDP multicast) ──
    print(f"\n[1] Sniffer CDP (mac-protocol=cdp, 20s)...")
    # CDP multicast destination: 01:00:0C:CC:CC:CC
    # RouterOS sniffer: mac-protocol=cdp captura CDP
    cdp_out = ssh_cmd(client,
        "/tool sniffer quick mac-protocol=cdp duration=20",
        timeout=35)
    cdp_lines = [l for l in cdp_out.splitlines() if '<-' in l or '->' in l]
    print(f"  Paquetes CDP: {len(cdp_lines)}")

    from collections import Counter
    cdp_macs = Counter()
    for l in cdp_lines:
        m = re.search(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', l)
        if m:
            mac = m.group(1).upper()
            # Excluir destino multicast CDP
            if mac != '01:00:0C:CC:CC:CC':
                cdp_macs[mac] += 1
    for mac, cnt in sorted(cdp_macs.items(), key=lambda x: -x[1]):
        print(f"    {mac}  {mac_vendor(mac):15s} ({cnt} pkts)")

    # ── LLDP capture ──
    print(f"\n[2] Sniffer LLDP (mac-protocol=lldp, 20s)...")
    lldp_out = ssh_cmd(client,
        "/tool sniffer quick mac-protocol=lldp duration=20",
        timeout=35)
    lldp_lines = [l for l in lldp_out.splitlines() if '<-' in l or '->' in l]
    print(f"  Paquetes LLDP: {len(lldp_lines)}")

    lldp_macs = Counter()
    for l in lldp_lines:
        m = re.search(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', l)
        if m:
            mac = m.group(1).upper()
            if ':80:C2:' not in mac and mac != '01:80:C2:00:00:0E':
                lldp_macs[mac] += 1
    for mac, cnt in sorted(lldp_macs.items(), key=lambda x: -x[1]):
        print(f"    {mac}  {mac_vendor(mac):15s} ({cnt} pkts)")

    # ── IP neighbor con discovered-by ──
    print(f"\n[3] Neighbor table completo (con discovered-by)...")
    neigh_raw = ssh_cmd(client, "/ip neighbor print detail", timeout=15)

    # Parsear bloques
    discovered = {'mndp': [], 'cdp': [], 'lldp': [], 'other': []}
    for block in re.split(r'\n\s*\d+\s+', '\n' + neigh_raw):
        if not block.strip():
            continue
        disc = re.search(r'discovered-by=(\S+)', block)
        mac = re.search(r'mac-address=([0-9A-Fa-f:]{17})', block)
        ident = re.search(r'identity="([^"]*)"', block)
        ver = re.search(r'version="?([^"\s]+)"?', block)
        plat = re.search(r'platform="([^"]*)"', block)
        age = re.search(r'age=(\S+)', block)

        proto = disc.group(1) if disc else 'mndp'  # default asumido
        entry = {
            'mac': mac.group(1).upper() if mac else '?',
            'identity': ident.group(1) if ident else '',
            'version': ver.group(1) if ver else '',
            'platform': plat.group(1) if plat else '',
            'age': age.group(1) if age else '',
            'proto': proto,
        }
        bucket = proto if proto in discovered else 'other'
        discovered[bucket].append(entry)

    for proto, entries in discovered.items():
        if not entries:
            continue
        print(f"\n  Protocolo: {proto.upper()} ({len(entries)} equipos)")
        for e in entries:
            vendor = mac_vendor(e['mac'])
            print(f"    {e['mac']}  {vendor:15s}  age={e['age']:8s}  {e['identity'] or '(sin nombre)'}  {e['platform']}  {e['version']}")

    client.close()

print("\n=== Fin ===")
