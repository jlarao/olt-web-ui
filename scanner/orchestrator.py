"""
Orquestador del scanner de red.
Estrategia multi-fuente con degradación elegante:

  1. MNDP via RouterOS /ip neighbor     → CPEs con identidad/versión/board
  2. mac-scan activo                    → todos los hosts en el bridge
  2b. ARP table                         → IP→MAC para todos los subnets
  2c. Bridge host table                 → MACs sin IP (station mode, etc.)
  ── UDP:10001 (tres opciones redundantes, se usan las que estén disponibles) ──
  A. Firewall log del MikroTik          → acumulativo desde la última rotación
  B. Sniffer pasivo en MikroTik         → ventana fija, requiere SW bridge
  C. Historial SQLite local             → persistente entre scans (30 días)
  ── Complemento externo (si Linux configurado) ──────────────────────────────
  D. MNDP UDP activo desde Linux        → MikroTiks en subred VPN
  E. UBNT UDP activo desde Linux        → UBNT que alcance el servidor
"""
import os
import logging
from dotenv import load_dotenv

from scanner.mikrotik_ssh import get_neighbors, get_arp_table, get_bridge_hosts, get_mac_scan
from scanner.oui import classify_by_oui, classify_by_version
from scanner.mndp_discovery import scan_via_linux as mndp_active_scan
from scanner.ubnt_discovery import scan_via_linux as ubnt_scan
from scanner.firewall_log import ensure_firewall_rules, read_firewall_log, passive_sniffer
from scanner.ubnt_history import init_db, update_seen, get_recent

load_dotenv()
logger = logging.getLogger(__name__)

init_db()

DEFAULT_MKT = {
    'host': os.getenv('M1_HOST', '10.10.11.1'),
    'port': int(os.getenv('M1_PORT', 12222)),
    'user': os.getenv('M1_USER', 'admin'),
    'pass': os.getenv('M1_PASS', ''),
}

LINUX = {
    'host':  os.getenv('LINUX_IP', ''),
    'port':  int(os.getenv('LINUX_PORT', 22)),
    'user':  os.getenv('LINUX_USER', ''),
    'pass':  os.getenv('LINUX_PASS', ''),
    'iface': os.getenv('LINUX_IFACE', 'tun0'),
}


def _normalize_mac(mac: str) -> str:
    if not mac:
        return ''
    return mac.upper().replace('-', ':')


def _device_type_final(device: dict) -> str:
    """
    Determina el tipo final con prioridad:
      1. Protocolo UDP UBNT confirmado
      2. Versión/board anunciada en MNDP (XM.v, XW.v, WA.ar934x, XC.qca…)
      3. OUI de la MAC
      4. Plataforma anunciada en MNDP
    """
    proto = device.get('protocol_version') or device.get('protocol', '')

    if proto == 'ubnt_legacy':
        return 'ubnt_legacy'
    if proto == 'ubnt_ac':
        return 'ubnt_ac'

    version  = device.get('version', '')
    board    = device.get('board', '')
    ver_type = classify_by_version(version, board)
    if ver_type:
        return ver_type

    mac      = device.get('mac') or device.get('mac-address', '')
    oui_type = classify_by_oui(mac)
    platform = str(device.get('platform', '')).lower()

    if 'mikrotik' in platform or oui_type == 'mikrotik' or proto == 'mndp':
        if oui_type in ('ubnt_ac', 'ubnt_legacy', 'ubnt', 'cambium'):
            pass
        else:
            return 'mikrotik'

    if oui_type == 'ubnt_legacy':
        return 'ubnt_legacy'
    if oui_type == 'ubnt_ac':
        return 'ubnt_ac'
    if oui_type == 'ubnt':
        return 'ubnt_legacy'
    if oui_type == 'cambium':
        return 'cambium'
    if oui_type in ('huawei_ont', 'zte_ont'):
        return oui_type
    if 'mikrotik' in platform:
        return 'mikrotik'

    return 'unknown'


def _merge_devices(lists: list[list[dict]]) -> list[dict]:
    """
    Une listas deduplicando por MAC. La entrada más rica (más campos no vacíos)
    gana en caso de colisión; los campos de identidad del perdedor se preservan
    si el ganador no los tiene.
    """
    merged: dict[str, dict] = {}
    for device_list in lists:
        for dev in device_list:
            mac = _normalize_mac(dev.get('mac') or dev.get('mac-address', ''))
            ip  = dev.get('ip') or dev.get('address') or dev.get('ipv4', '')
            key = mac if mac else ip
            if not key:
                continue

            dev['mac'] = mac
            dev['ip']  = ip
            dev['device_type'] = _device_type_final(dev)
            dev['name'] = (
                dev.get('identity')
                or dev.get('hostname')
                or dev.get('name')
                or ip
            )

            if key not in merged:
                merged[key] = dev
            else:
                existing_score = sum(1 for v in merged[key].values() if v)
                new_score      = sum(1 for v in dev.values() if v)
                if new_score > existing_score:
                    for field in ('identity', 'platform', 'version', 'board', 'device_type'):
                        if not dev.get(field) and merged[key].get(field):
                            dev[field] = merged[key][field]
                    merged[key] = dev

    return list(merged.values())


def run_scan(
    mkt_host:       str  = None,
    mkt_port:       int  = None,
    mkt_user:       str  = None,
    mkt_pass:       str  = None,
    listen_sec:     int  = 5,
    sniffer_sec:    int  = 20,
    history_days:   int  = 30,
    include_onts:   bool = False,
    setup_firewall: bool = True,
    neighbors_only: bool = False,
) -> dict:
    """
    Ejecuta el scan completo (o solo /ip neighbor si neighbors_only=True).

    Parámetros:
      neighbors_only — solo ejecuta la fase MNDP (/ip neighbor). Más rápido.
      sniffer_sec    — duración del sniffer pasivo (Opción B). 0 = desactivar.
      history_days   — ventana del historial SQLite (Opción C). 0 = desactivar.
      setup_firewall — intentar crear las reglas de firewall si no existen.

    Retorna: {devices, stats, errors, sources}
    """
    host   = mkt_host or DEFAULT_MKT['host']
    port   = mkt_port or DEFAULT_MKT['port']
    user   = mkt_user or DEFAULT_MKT['user']
    passwd = mkt_pass or DEFAULT_MKT['pass']

    errors   = []
    all_lists = []
    sources  = {}   # fuente → cantidad encontrada

    # ── Fase 1: MNDP via RouterOS ──────────────────────────────────────────
    logger.info(f"[scan] Fase 1 — MNDP RouterOS {host}:{port}")
    try:
        neighbors = get_neighbors(host, port, user, passwd)
        for n in neighbors:
            n.update({
                'protocol': 'mndp',
                'ip':       n.get('address', ''),
                'mac':      n.get('mac-address', ''),
                'identity': n.get('identity', ''),
                'platform': n.get('platform', 'MikroTik'),
                'version':  n.get('version', ''),
                'iface':    n.get('interface-name', n.get('interface', '')),
            })
        all_lists.append(neighbors)
        sources['mndp'] = len(neighbors)
        logger.info(f"  → {len(neighbors)} vecinos MNDP")
    except Exception as e:
        errors.append(f"MNDP RouterOS: {e}")
        logger.error(e)

    # ── Modo rápido: solo neighbor ─────────────────────────────────────────
    if neighbors_only:
        devices = _merge_devices(all_lists)
        if not include_onts:
            devices = [d for d in devices
                       if d.get('device_type') not in ('huawei_ont', 'zte_ont')]
        _order = {'mikrotik': 0, 'ubnt_ac': 1, 'ubnt_legacy': 2, 'ubnt': 2,
                  'cambium': 3, 'unknown': 9}
        devices.sort(key=lambda d: _order.get(d.get('device_type', ''), 5))
        stats = {
            'total':       len(devices),
            'mikrotik':    sum(1 for d in devices if d.get('device_type') == 'mikrotik'),
            'ubnt_legacy': sum(1 for d in devices if d.get('device_type') in ('ubnt_legacy', 'ubnt')),
            'ubnt_ac':     sum(1 for d in devices if d.get('device_type') == 'ubnt_ac'),
            'huawei_ont':  0, 'zte_ont': 0,
            'unknown':     sum(1 for d in devices if d.get('device_type') == 'unknown'),
        }
        return {'devices': devices, 'stats': stats, 'errors': errors, 'sources': sources}

    # ── Fase 2: mac-scan activo ────────────────────────────────────────────
    logger.info(f"[scan] Fase 2 — mac-scan {host}:{port}")
    try:
        mac_scan_results = get_mac_scan(host, port, user, passwd,
                                        interface='bridge1', duration=8)
        all_lists.append(mac_scan_results)
        sources['mac_scan'] = len(mac_scan_results)
        logger.info(f"  → {len(mac_scan_results)} hosts via mac-scan")
    except Exception as e:
        errors.append(f"mac-scan: {e}")
        logger.error(e)

    # ── Fase 2b: ARP table ─────────────────────────────────────────────────
    logger.info(f"[scan] Fase 2b — ARP {host}:{port}")
    try:
        arp = get_arp_table(host, port, user, passwd)
        for a in arp:
            a['protocol'] = 'arp'
        all_lists.append(arp)
        sources['arp'] = len(arp)
        logger.info(f"  → {len(arp)} entradas ARP")
    except Exception as e:
        errors.append(f"ARP: {e}")
        logger.error(e)

    # ── Fase 2c: Bridge host table ─────────────────────────────────────────
    logger.info(f"[scan] Fase 2c — Bridge hosts {host}:{port}")
    try:
        bridge = get_bridge_hosts(host, port, user, passwd)
        bridge_filtered = [
            b for b in bridge
            if classify_by_oui(b['mac']) not in ('unknown', 'huawei_ont', 'zte_ont')
        ]
        all_lists.append(bridge_filtered)
        sources['bridge'] = len(bridge_filtered)
        logger.info(f"  → {len(bridge_filtered)} MACs relevantes en bridge ({len(bridge)} total)")
    except Exception as e:
        errors.append(f"Bridge hosts: {e}")
        logger.error(e)

    # ── Opción A: Firewall log ─────────────────────────────────────────────
    logger.info(f"[scan] Opción A — Firewall log UDP:10001 en {host}")
    if setup_firewall:
        ensure_firewall_rules(host, port, user, passwd)
    try:
        fw_devs = read_firewall_log(host, port, user, passwd)
        all_lists.append(fw_devs)
        sources['fw_log'] = len(fw_devs)
        logger.info(f"  → {len(fw_devs)} entradas en log de firewall")
    except Exception as e:
        errors.append(f"Firewall log: {e}")
        logger.error(e)

    # ── Opción B: Sniffer pasivo en MikroTik ──────────────────────────────
    if sniffer_sec > 0:
        logger.info(f"[scan] Opción B — Sniffer pasivo {sniffer_sec}s en {host}")
        try:
            sniff_devs = passive_sniffer(host, port, user, passwd,
                                         interface='bridge1', duration=sniffer_sec)
            all_lists.append(sniff_devs)
            sources['sniffer'] = len(sniff_devs)
            logger.info(f"  → {len(sniff_devs)} MACs via sniffer")
        except Exception as e:
            errors.append(f"Sniffer pasivo: {e}")
            logger.error(e)

    # ── Opción C: Historial SQLite ─────────────────────────────────────────
    if history_days > 0:
        logger.info(f"[scan] Opción C — Historial SQLite ({history_days}d)")
        try:
            hist_devs = get_recent(days=history_days)
            all_lists.append(hist_devs)
            sources['history'] = len(hist_devs)
            logger.info(f"  → {len(hist_devs)} MACs del historial")
        except Exception as e:
            errors.append(f"Historial SQLite: {e}")
            logger.error(e)

    # ── Complemento D+E: Linux MNDP + UBNT UDP ────────────────────────────
    if LINUX['host'] and LINUX['user']:
        logger.info(f"[scan] Fase D — MNDP UDP activo desde Linux {LINUX['host']}")
        try:
            mndp_devs = mndp_active_scan(
                linux_host=LINUX['host'], linux_port=LINUX['port'],
                linux_user=LINUX['user'], linux_pass=LINUX['pass'],
                iface=LINUX['iface'], listen_sec=listen_sec,
            )
            all_lists.append(mndp_devs)
            sources['linux_mndp'] = len(mndp_devs)
            logger.info(f"  → {len(mndp_devs)} MNDP UDP desde Linux")
        except Exception as e:
            errors.append(f"MNDP UDP Linux: {e}")

        logger.info(f"[scan] Fase E — UBNT UDP activo desde Linux {LINUX['host']}")
        try:
            ubnt_devs = ubnt_scan(
                linux_host=LINUX['host'], linux_port=LINUX['port'],
                linux_user=LINUX['user'], linux_pass=LINUX['pass'],
                iface=LINUX['iface'], listen_sec=listen_sec,
            )
            all_lists.append(ubnt_devs)
            sources['linux_ubnt'] = len(ubnt_devs)
            logger.info(f"  → {len(ubnt_devs)} UBNT UDP desde Linux")
        except Exception as e:
            errors.append(f"UBNT UDP Linux: {e}")
    else:
        logger.info("[scan] Linux server no configurado — omitiendo fases D+E")

    # ── Merge y clasificación final ────────────────────────────────────────
    devices = _merge_devices(all_lists)

    linux_ip = LINUX.get('host', '')
    if linux_ip:
        devices = [d for d in devices if d.get('ip') != linux_ip]

    if not include_onts:
        devices = [d for d in devices
                   if d.get('device_type') not in ('huawei_ont', 'zte_ont')]

    _order = {'mikrotik': 0, 'ubnt_ac': 1, 'ubnt_legacy': 2, 'ubnt': 2,
              'cambium': 3, 'unknown': 9}
    devices.sort(key=lambda d: _order.get(d.get('device_type', ''), 5))

    # ── Opción C: actualizar historial con todos los UBNT encontrados ──────
    ubnt_found = [
        d for d in devices
        if d.get('device_type') in ('ubnt_ac', 'ubnt_legacy', 'ubnt')
    ]
    if ubnt_found:
        saved = update_seen(ubnt_found, router_host=host)
        logger.info(f"[scan] Historial actualizado: {saved} UBNT guardados")

    stats = {
        'total':       len(devices),
        'mikrotik':    sum(1 for d in devices if d.get('device_type') == 'mikrotik'),
        'ubnt_legacy': sum(1 for d in devices if d.get('device_type') in ('ubnt_legacy', 'ubnt')),
        'ubnt_ac':     sum(1 for d in devices if d.get('device_type') == 'ubnt_ac'),
        'huawei_ont':  sum(1 for d in devices if d.get('device_type') == 'huawei_ont'),
        'zte_ont':     sum(1 for d in devices if d.get('device_type') == 'zte_ont'),
        'unknown':     sum(1 for d in devices if d.get('device_type') == 'unknown'),
    }
    logger.info(f"[scan] Completo: {stats} | fuentes: {sources}")
    return {
        'devices': devices,
        'stats':   stats,
        'errors':  errors,
        'sources': sources,
    }
