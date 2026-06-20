"""
Captura UDP:10001 directamente en el MikroTik — dos estrategias:

  A. Firewall log (persistente): regla action=log en el router, el log
     se acumula entre scans sin intervención. Lee con /log print.

  B. Sniffer pasivo (por ventana): /tool sniffer quick durante N segundos.
     Captura el discovery orgánico en esa ventana. No funciona en
     MikroTik con hardware switch activo (RB3011/QCA-8337).
"""
import re
import logging
from scanner.mikrotik_ssh import connect, run_command

logger = logging.getLogger(__name__)

_PORT    = 10001
_PREFIX  = "U10001"
_COMMENT = "ubnt-disc-log"


# ── Opción A ── Firewall logging ──────────────────────────────────────────

def ensure_firewall_rules(host: str, port: int, user: str, password: str) -> bool:
    """
    Crea las reglas de log UDP:10001 en el MikroTik si no existen.
    Idempotente — verifica por el comentario antes de crear.
    Retorna True si las reglas quedaron activas.
    """
    client = None
    try:
        client = connect(host, port, user, password)
        existing = run_command(
            client,
            f'/ip firewall filter print terse where comment="{_COMMENT}"',
            timeout=10,
        )
        if _COMMENT in existing:
            logger.info(f"[firewall_log] Reglas ya existen en {host}")
            return True
        for chain in ('input', 'forward'):
            run_command(
                client,
                f'/ip firewall filter add chain={chain} protocol=udp port={_PORT} '
                f'action=log log-prefix="{_PREFIX}" comment="{_COMMENT}" place-before=0',
                timeout=10,
            )
        logger.info(f"[firewall_log] Reglas UDP:{_PORT} creadas en {host}")
        return True
    except Exception as e:
        logger.error(f"[firewall_log] Error configurando firewall en {host}: {e}")
        return False
    finally:
        if client:
            client.close()


def read_firewall_log(host: str, port: int, user: str, password: str) -> list[dict]:
    """
    Opción A: Lee el log de RouterOS y extrae MACs/IPs de UDP:10001.
    Formato de línea esperado:
      ... U10001 forward: in:bridge1 ..., src-mac fc:ec:da:6c:ba:47,
          proto UDP ..., 192.168.3.102:10001->192.168.3.255:10001 ...
    Retorna lista de dicts {mac, ip, source='fw_log'}.
    Falla silenciosamente si las reglas no existen (retorna []).
    """
    client = None
    try:
        client = connect(host, port, user, password)
        raw = run_command(
            client,
            f'/log print terse where message~"{_PREFIX}"',
            timeout=10,
        )
    except Exception as e:
        logger.error(f"[firewall_log] Error leyendo log en {host}: {e}")
        return []
    finally:
        if client:
            client.close()

    seen: dict[str, dict] = {}
    for line in raw.splitlines():
        mac_m = re.search(r'src-mac\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', line)
        # IP origen: primer XX.XX.XX.XX antes de ":puerto->"
        ip_m  = re.search(r'(\d{1,3}(?:\.\d{1,3}){3}):\d+->(?!255)', line)
        if not ip_m:
            ip_m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3}):\d+->', line)

        mac = mac_m.group(1).upper() if mac_m else ''
        ip  = ip_m.group(1)          if ip_m  else ''
        key = mac or ip
        if key and key not in seen:
            seen[key] = {'mac': mac, 'ip': ip, 'source': 'fw_log'}

    logger.info(f"[firewall_log] {len(seen)} entradas en log de {host}")
    return list(seen.values())


# ── Opción B ── Sniffer pasivo ────────────────────────────────────────────

def passive_sniffer(host: str, port: int, user: str, password: str,
                    interface: str = 'bridge1', duration: int = 20) -> list[dict]:
    """
    Opción B: sniffer pasivo sobre el bridge durante `duration` segundos.
    Captura MACs/IPs que emiten en UDP:10001 en esa ventana de tiempo.

    Limitación: no captura tráfico conmutado por hardware (QCA-8337 en
    RB3011, RB4011, etc.). Funciona bien en CCR y routers sin HW switch.
    Retorna lista de dicts {mac, ip, source='sniffer'}.
    """
    client = None
    try:
        client = connect(host, port, user, password)
        raw = run_command(
            client,
            f"/tool sniffer quick ip-protocol=udp port={_PORT} "
            f"interface={interface} duration={duration}",
            timeout=duration + 15,
        )
    except Exception as e:
        logger.error(f"[firewall_log] Error sniffer en {host}: {e}")
        return []
    finally:
        if client:
            client.close()

    seen: dict[str, dict] = {}
    for line in raw.splitlines():
        if '<-' not in line:
            continue
        mac_m = re.search(r'<-\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', line)
        ip_m  = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})\s+->', line)
        if mac_m:
            mac = mac_m.group(1).upper()
            ip  = ip_m.group(1) if ip_m else ''
            if mac not in seen:
                seen[mac] = {'mac': mac, 'ip': ip, 'source': 'sniffer'}

    logger.info(f"[firewall_log] Sniffer: {len(seen)} MACs UDP:{_PORT} en {host} ({duration}s)")
    return list(seen.values())
