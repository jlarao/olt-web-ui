"""
Auditoría profunda: verifica si bridge1 está en el interface-list static,
compara neighbor discovery por interfaz, y busca cualquier diferencia de config.
"""
import sys, io, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
import paramiko
from dotenv import load_dotenv
import os

load_dotenv()

ROUTERS = [
    {'label': 'MKT1', 'host': os.getenv('M1_HOST'), 'port': int(os.getenv('M1_PORT', 12222)),
     'user': os.getenv('M1_USER'), 'pass': os.getenv('M1_PASS')},
    {'label': 'MKT3', 'host': os.getenv('M2_HOST'), 'port': int(os.getenv('M2_PORT', 22)),
     'user': os.getenv('M2_USER'), 'pass': os.getenv('M2_PASS')},
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

for router in ROUTERS:
    print(f"\n{'='*60}")
    print(f"=== {router['label']} ({router['host']}) ===")
    print(f"{'='*60}")

    try:
        c = connect(router)
    except Exception as e:
        print(f"  ERROR: {e}")
        continue

    # ── ¿bridge1 está en la lista static? ──────────────────────────
    print("\n[1] ¿bridge1 aparece en interface-list static?")
    # En RouterOS 6.x, la lista "static" incluye automáticamente las interfaces estáticas
    # Verificamos qué interfaces tiene el router que son estáticas
    ifaces = cmd(c, "/interface print terse where !dynamic")
    bridge_in = 'bridge1' in ifaces
    print(f"  {'✓ bridge1 es estático → está en static list' if bridge_in else '✗ bridge1 NO encontrado como estático'}")
    iface_names = re.findall(r'name=(\S+)', ifaces)
    print(f"  Interfaces estáticas: {', '.join(iface_names[:15])}")

    # ── Neighbor discovery por interfaz (qué interfaces escuchan) ──
    print(f"\n[2] Interfaces con neighbor discovery activo")
    # RouterOS 6: /ip neighbor discovery
    nd_ifaces = cmd(c, "/ip neighbor discovery print")
    print(nd_ifaces[:800] if nd_ifaces else "  (sin resultado)")

    # ── ¿Hay alguna regla que filtre UDP 5678 en bridge? ────────────
    print(f"\n[3] Firewall INPUT/FORWARD para bridge1")
    fw = cmd(c, "/ip firewall filter print terse where in-interface=bridge1 or out-interface=bridge1")
    print(fw[:500] if fw else "  (sin reglas en bridge1)")

    # ── Bridge filter (bridge-level firewall) ──────────────────────
    print(f"\n[4] Bridge firewall rules")
    bfw = cmd(c, "/interface bridge filter print terse")
    print(bfw[:500] if bfw else "  (sin bridge filter rules)")

    # ── Hardware offload status ────────────────────────────────────
    print(f"\n[5] Hardware switch / offload status")
    sw = cmd(c, "/interface ethernet switch print")
    print(sw[:500] if sw else "  (sin switch entries)")

    # ── ¿bridge1 tiene HW offload activo? ──────────────────────────
    bridge_ports = cmd(c, "/interface bridge port print terse")
    hw_active = 'H ' in bridge_ports or ' H ' in bridge_ports
    hw_set = 'hw=yes' in bridge_ports
    print(f"\n[6] Bridge HW offload")
    print(f"  hw=yes en config: {'sí' if hw_set else 'no'}")
    print(f"  Flag H activo:    {'sí ← hardware forwarding activo' if hw_active else 'no ← todo por CPU (sniffer ve todo)'}")

    # ── Neighbor discovery settings completos ──────────────────────
    print(f"\n[7] Neighbor discovery — settings completos")
    nd_settings = cmd(c, "/ip neighbor discovery-settings print")
    print(nd_settings)

    # ── ¿Qué interface-lists existen? ─────────────────────────────
    print(f"\n[8] Interface-list members (todas las listas)")
    il_members = cmd(c, "/interface list member print terse")
    print(il_members[:1000] if il_members else "  (sin custom members)")

    # ── Sniffer rápido: ¿algo en UDP:5678 en MKT1? ────────────────
    if router['label'] == 'MKT1':
        print(f"\n[9] Sniffer UDP:5678 en MKT1 — 20s")
        sniffer = cmd(c, "/tool sniffer quick port=5678 duration=20", timeout=35)
        pkts = [l for l in sniffer.splitlines() if '<-' in l or '->' in l and 'bridge1' not in l]
        print(f"  Total paquetes: {len(pkts)}")
        for l in pkts[:20]:
            print(" ", l)

        print(f"\n[10] Sniffer LLDP en MKT1 — 20s")
        lldp = cmd(c, "/tool sniffer quick mac-protocol=lldp duration=20", timeout=35)
        lldp_pkts = [l for l in lldp.splitlines() if ('<-' in l or '->' in l) and 'bridge1' not in l]
        print(f"  Total paquetes LLDP: {len(lldp_pkts)}")
        for l in lldp_pkts[:20]:
            print(" ", l)

    c.close()
