"""
Prueba completa del scanner contra MKT1 (10.10.11.1).
Fases:
  1. MNDP via /ip neighbor (SSH)
  2. mac-scan bridge1
  3. ARP table
  4. Bridge host table
  5. UDP:10001 discovery — Linux envia query, MikroTik captura respuestas
  6. Clasificación final y resumen
"""
import sys, io, time, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

import os
import paramiko
from dotenv import load_dotenv
from collections import defaultdict

load_dotenv()

# ── Credenciales ───────────────────────────────────────────────────────────
MKT = {
    'host': os.getenv('M1_HOST', '10.10.11.1'),
    'port': int(os.getenv('M1_PORT', 12222)),
    'user': os.getenv('M1_USER', 'admin'),
    'pass': os.getenv('M1_PASS', ''),
}
LINUX = {
    'host': os.getenv('LINUX_IP', '10.10.11.2'),
    'port': int(os.getenv('LINUX_PORT', 22)),
    'user': os.getenv('LINUX_USER', ''),
    'pass': os.getenv('LINUX_PASS', ''),
    'iface': os.getenv('LINUX_IFACE', 'tun0'),
}

# ── OUI ────────────────────────────────────────────────────────────────────
UBNT_LEGACY_OUI = {
    '00:15:6D','00:27:22','04:18:D6','0A:18:D6','18:E8:29','20:23:51',
    '24:2F:D0','24:A4:3C','28:EE:52','44:D9:E7','5C:E9:31','68:72:51',
    '70:4F:57','74:83:C2','78:8A:20','80:2A:A8','AC:84:C6','B0:4E:26',
    'B0:BE:76','B4:FB:E4','DC:9F:DB','E0:63:DA','F0:9F:C2','FC:EC:DA',
}
UBNT_AC_OUI = {
    '00:AA:23','24:5A:4C','60:22:32','68:D7:9A','74:AC:B9','78:45:58',
    'B4:FB:E4','C4:AD:34','E4:38:83','F4:92:BF',
}
MIKROTIK_OUI = {
    '00:0C:42','04:F4:1C','08:55:31','18:FD:74','2C:C8:1B','48:8F:5A',
    '4C:5E:0C','64:D1:54','6C:3B:6B','74:4D:28','B8:69:F4','C4:AD:34',
    'CC:2D:E0','D4:01:C3','DC:2C:6E','E4:8D:8C',
}

def oui(mac): return mac.upper()[:8]

def classify(mac, version=''):
    o = oui(mac)
    # Por versión de firmware primero
    if version:
        v = version.strip()
        if re.match(r'^WA\.(v[89]|ar)', v, re.I): return 'ubnt_ac'
        if re.match(r'^(XC|XA|TI|BZ)\.', v, re.I): return 'ubnt_ac'
        if re.match(r'^(XM|XW)\.v', v, re.I): return 'ubnt_legacy'
    if o in UBNT_AC_OUI: return 'ubnt_ac'
    if o in UBNT_LEGACY_OUI: return 'ubnt_legacy'
    if o in MIKROTIK_OUI: return 'mikrotik'
    return 'unknown'

def ssh_connect(cfg):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(cfg['host'], port=cfg['port'], username=cfg['user'],
              password=cfg['pass'], timeout=10,
              look_for_keys=False, allow_agent=False)
    return c

def run(c, cmd, timeout=20):
    _, stdout, _ = c.exec_command(cmd, timeout=timeout)
    return stdout.read().decode('utf-8', errors='replace')

def norm_mac(mac): return mac.upper().replace('-', ':')

# ── Almacén de dispositivos ────────────────────────────────────────────────
devices = {}   # mac → {mac, ip, name, version, platform, source, type}

def upsert(mac, **kwargs):
    mac = norm_mac(mac)
    if not mac or len(mac) != 17: return
    if mac not in devices:
        devices[mac] = {'mac': mac, 'ip': '', 'name': '', 'version': '',
                        'platform': '', 'source': set(), 'type': 'unknown'}
    d = devices[mac]
    for k, v in kwargs.items():
        if k == 'source':
            d['source'].add(v)
        elif v and not d.get(k):
            d[k] = v
        elif v and k in ('version', 'name', 'platform') and len(str(v)) > len(str(d.get(k,''))):
            d[k] = v
    d['type'] = classify(mac, d.get('version', ''))

# ══════════════════════════════════════════════════════════════════════════
print(f"\n{'='*60}")
print(f"  Scanner MKT1 — {MKT['host']}:{MKT['port']}")
print(f"{'='*60}\n")

mkt = ssh_connect(MKT)

# ── Fase 1: MNDP via /ip neighbor ─────────────────────────────────────────
print("[ Fase 1 ] MNDP — /ip neighbor print detail")
raw_n = run(mkt, "/ip neighbor print detail", timeout=15)
for block in re.split(r'\n\s*\d+\s+', '\n' + raw_n):
    if not block.strip(): continue
    mac_m  = re.search(r'mac-address=([0-9A-Fa-f:]{17})', block)
    addr_m = re.search(r'\baddress=(\d+\.\d+\.\d+\.\d+)', block)
    iden_m = re.search(r'identity="([^"]*)"', block)
    ver_m  = re.search(r'\bversion="?([^"\s,]+)"?', block)
    plat_m = re.search(r'platform="([^"]*)"', block)
    if mac_m:
        upsert(mac_m.group(1),
               ip=addr_m.group(1) if addr_m else '',
               name=iden_m.group(1) if iden_m else '',
               version=ver_m.group(1) if ver_m else '',
               platform=plat_m.group(1) if plat_m else '',
               source='mndp')
n_mndp = sum(1 for d in devices.values() if 'mndp' in d['source'])
print(f"  → {n_mndp} dispositivos via MNDP\n")

# ── Fase 2: mac-scan ───────────────────────────────────────────────────────
print("[ Fase 2 ] mac-scan bridge1 (8s)")
raw_ms = run(mkt, "/tool mac-scan interface=bridge1 duration=8", timeout=20)
for line in raw_ms.splitlines():
    mac_m = re.match(r'\s*([0-9A-Fa-f:]{17})\s+(\d+\.\d+\.\d+\.\d+)?', line)
    if mac_m:
        upsert(mac_m.group(1), ip=mac_m.group(2) or '', source='macscan')
n_ms = sum(1 for d in devices.values() if 'macscan' in d['source'])
print(f"  → {n_ms} dispositivos via mac-scan\n")

# ── Fase 3: ARP ───────────────────────────────────────────────────────────
print("[ Fase 3 ] ARP table")
raw_arp = run(mkt, "/ip arp print terse", timeout=10)
for line in raw_arp.splitlines():
    ip_m  = re.search(r'address=(\d+\.\d+\.\d+\.\d+)', line)
    mac_m = re.search(r'mac-address=([0-9A-Fa-f:]{17})', line)
    if ip_m and mac_m:
        upsert(mac_m.group(1), ip=ip_m.group(1), source='arp')
n_arp = sum(1 for d in devices.values() if 'arp' in d['source'])
print(f"  → {n_arp} dispositivos via ARP\n")

# ── Fase 4: Bridge host table ──────────────────────────────────────────────
print("[ Fase 4 ] Bridge host table")
raw_bh = run(mkt, "/interface bridge host print terse", timeout=10)
for line in raw_bh.splitlines():
    if ' L ' in line: continue   # excluir MACs locales
    mac_m = re.search(r'mac-address=([0-9A-Fa-f:]{17})', line)
    if mac_m:
        upsert(mac_m.group(1), source='bridge')
n_bridge = sum(1 for d in devices.values() if 'bridge' in d['source'])
print(f"  → {n_bridge} MACs en bridge host table\n")

# ── Fase 5: UDP:10001 — sniffer en MKT1 mientras Linux envía query ─────────
print("[ Fase 5 ] UDP:10001 discovery")
print(f"  Iniciando sniffer en MKT1 y enviando query desde Linux {LINUX['host']}...")

# Script Python para Linux: envía magic UBNT v1 y v2, escucha respuestas
UBNT_SCRIPT = r"""
import socket, struct, time, json, sys

IFACE  = sys.argv[1]
BCAST  = '192.168.3.255'
BCAST2 = '192.168.2.255'
PORT   = 10001

results = {}

def send_recv(magic, label):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(0.3)
    try: s.bind(('', PORT))
    except: pass
    for dst in [BCAST, BCAST2, '255.255.255.255']:
        try: s.sendto(magic, (dst, PORT))
        except: pass
    deadline = time.time() + 8
    while time.time() < deadline:
        try:
            data, addr = s.recvfrom(4096)
            ip = addr[0]
            mac = ''
            # Parsear TLV
            pos = 4
            while pos + 4 <= len(data):
                t = struct.unpack('>H', data[pos:pos+2])[0]
                l = struct.unpack('>H', data[pos+2:pos+4])[0]
                v = data[pos+4:pos+4+l]
                if t == 1 and l == 6:
                    mac = ':'.join(f'{b:02X}' for b in v)
                pos += 4 + l
            key = mac or ip
            if key and key not in results:
                results[key] = {'ip': ip, 'mac': mac, 'proto': label}
        except socket.timeout:
            break
        except Exception:
            pass
    s.close()

send_recv(b'\x01\x00\x00\x00', 'ubnt_legacy')
time.sleep(1)
send_recv(b'\x02\x0a\x00\x00', 'ubnt_ac')

print(json.dumps(list(results.values())))
"""

ubnt_from_linux = []
try:
    lx = ssh_connect(LINUX)
    # Subir script
    sftp = lx.open_sftp()
    with sftp.open('/tmp/_ubnt_q.py', 'w') as f:
        f.write(UBNT_SCRIPT)
    sftp.close()
    raw_ubnt = run(lx, f"python3 /tmp/_ubnt_q.py {LINUX['iface']}", timeout=25)
    lx.close()
    import json
    for entry in json.loads(raw_ubnt.strip() or '[]'):
        if entry.get('mac'):
            upsert(entry['mac'], ip=entry.get('ip',''),
                   source='udp10001',
                   **({'type': entry['proto']} if entry.get('proto') else {}))
            ubnt_from_linux.append(entry)
    print(f"  → {len(ubnt_from_linux)} respuestas UDP:10001 desde Linux\n")
except Exception as e:
    print(f"  [Linux UDP:10001] {e}\n")

# También capturar con sniffer en MKT1 lo que llega en bridge1
print("  Capturando UDP:10001 en MKT1 (15s)...")
raw_sniff = run(mkt, "/tool sniffer quick ip-protocol=udp port=10001 "
                     "interface=bridge1 duration=15", timeout=30)
sniff_macs = set()
for line in raw_sniff.splitlines():
    if '<-' not in line: continue
    m = re.search(r'<-\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', line)
    if m:
        mac = norm_mac(m.group(1))
        if mac not in sniff_macs:
            sniff_macs.add(mac)
            upsert(mac, source='udp10001_sniff')

print(f"  → {len(sniff_macs)} MACs únicas en sniffer UDP:10001\n")

mkt.close()

# ══════════════════════════════════════════════════════════════════════════
# Resumen final
# ══════════════════════════════════════════════════════════════════════════
print(f"{'='*60}")
print(f"  RESUMEN FINAL")
print(f"{'='*60}\n")

by_type = defaultdict(list)
for d in devices.values():
    by_type[d['type']].append(d)

type_labels = {
    'ubnt_ac':     'UBNT AC',
    'ubnt_legacy': 'UBNT Legacy',
    'mikrotik':    'MikroTik',
    'unknown':     'Desconocido',
}

for typ in ['ubnt_ac', 'ubnt_legacy', 'mikrotik', 'unknown']:
    devs = by_type.get(typ, [])
    if not devs: continue
    print(f"\n── {type_labels[typ]} ({len(devs)}) ──────────────────────────")
    for d in sorted(devs, key=lambda x: x.get('ip','') or x['mac']):
        src = ','.join(sorted(d['source']))
        print(f"  {d['mac']}  {d.get('ip',''):16s}  "
              f"{d.get('name',''):22s}  {d.get('version',''):25s}  [{src}]")

print(f"\n{'─'*60}")
stats = {t: len(v) for t, v in by_type.items()}
total = sum(stats.values())
print(f"  Total: {total}  |  "
      f"UBNT AC: {stats.get('ubnt_ac',0)}  |  "
      f"UBNT Legacy: {stats.get('ubnt_legacy',0)}  |  "
      f"MikroTik: {stats.get('mikrotik',0)}  |  "
      f"Desconocido: {stats.get('unknown',0)}")
print()
