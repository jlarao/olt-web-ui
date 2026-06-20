"""
Conexión SSH a MikroTik RouterOS y ejecución de comandos de descubrimiento.
"""
import paramiko
import re
import logging

logger = logging.getLogger(__name__)

NEIGHBOR_FIELDS = [
    "interface", "address", "mac-address", "identity",
    "platform", "version", "board", "uptime", "discovered-by",
]


def connect(host: str, port: int, username: str, password: str, timeout: int = 10) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    logger.info(f"SSH conectado a {host}:{port}")
    return client


def run_command(client: paramiko.SSHClient, command: str, timeout: int = 15) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if err.strip():
        logger.debug(f"stderr [{command}]: {err.strip()}")
    return output


def parse_neighbor_detail(raw: str) -> list[dict]:
    """
    Parsea la salida de '/ip neighbor print detail' en lista de dicts.
    Cada bloque de vecino comienza con una línea que tiene número de índice.
    """
    devices = []
    # Dividir en bloques por número de índice (ej. " 0 ", " 1 ")
    blocks = re.split(r'\n\s*\d+\s+', '\n' + raw)
    for block in blocks:
        if not block.strip():
            continue
        device = {}
        # Extraer pares key=value (RouterOS usa espacios y saltos de línea)
        for match in re.finditer(r'(\S[\w-]*)=("(?:[^"\\]|\\.)*"|\S+)', block):
            key = match.group(1)
            val = match.group(2).strip('"')
            device[key] = val
        if device:
            devices.append(device)
    return devices


def get_neighbors(host: str, port: int, username: str, password: str) -> list[dict]:
    """Retorna lista de vecinos MNDP descubiertos por el MikroTik."""
    client = None
    try:
        client = connect(host, port, username, password)
        raw = run_command(client, "/ip neighbor print detail")
        neighbors = parse_neighbor_detail(raw)
        logger.info(f"MNDP: {len(neighbors)} vecinos encontrados en {host}")
        return neighbors
    except Exception as e:
        logger.error(f"Error obteniendo vecinos de {host}:{port} — {e}")
        return []
    finally:
        if client:
            client.close()


def get_mac_scan(host: str, port: int, username: str, password: str,
                 interface: str = 'bridge1', duration: int = 8) -> list[dict]:
    """
    Ejecuta /tool mac-scan en la interfaz indicada.
    Retorna lista de dicts {mac, ip, interface} deduplicada por MAC.
    Más completo que la ARP table (que expira a los 30s).
    """
    client = None
    try:
        client = connect(host, port, username, password)
        raw = run_command(
            client,
            f"/tool mac-scan interface={interface} duration={duration}",
            timeout=duration + 10,
        )
        seen: dict[str, dict] = {}
        for line in raw.splitlines():
            parts = line.split()
            if not parts:
                continue
            mac_match = re.match(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', parts[0])
            if not mac_match:
                continue
            mac = mac_match.group(1).upper()
            ip = ''
            # Segunda columna puede ser IP o AGE (número)
            if len(parts) >= 2 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[1]):
                ip = parts[1]
            entry = {'mac': mac, 'ip': ip, 'interface': interface, 'protocol': 'mac-scan'}
            # Prefiere la entrada que tiene IP sobre la que no la tiene
            if mac not in seen or (ip and not seen[mac]['ip']):
                seen[mac] = entry
        result = list(seen.values())
        logger.info(f"mac-scan {interface}: {len(result)} hosts únicos en {host}")
        return result
    except Exception as e:
        logger.error(f"Error mac-scan {host}:{port} — {e}")
        return []
    finally:
        if client:
            client.close()


def get_bridge_hosts(host: str, port: int, username: str, password: str) -> list[dict]:
    """
    Retorna MACs aprendidas en el bridge (sin necesidad de IP).
    Útil para detectar dispositivos que no responden ARP (UniFi, etc.)
    """
    client = None
    try:
        client = connect(host, port, username, password)
        raw = run_command(client, "/interface bridge host print terse", timeout=10)
        entries = []
        for line in raw.splitlines():
            mac_match = re.search(
                r'mac-address=([0-9A-Fa-f:]{17})', line)
            iface_match = re.search(r'interface=(\S+)', line)
            bridge_match = re.search(r'bridge=(\S+)', line)
            if not mac_match:
                continue
            mac = mac_match.group(1).upper()
            # Excluir MACs del propio MikroTik (flag L = local)
            if ' L ' in line:
                continue
            entries.append({
                'mac': mac,
                'interface': iface_match.group(1) if iface_match else '',
                'bridge': bridge_match.group(1) if bridge_match else '',
                'protocol': 'bridge',
            })
        logger.info(f"Bridge hosts: {len(entries)} MACs en {host}")
        return entries
    except Exception as e:
        logger.error(f"Error bridge hosts {host}:{port} — {e}")
        return []
    finally:
        if client:
            client.close()


def get_arp_table(host: str, port: int, username: str, password: str) -> list[dict]:
    """Retorna la tabla ARP del MikroTik como lista de dicts."""
    client = None
    try:
        client = connect(host, port, username, password)
        raw = run_command(client, "/ip arp print terse")
        entries = []
        # Formato: FLAGS ADDRESS MAC-ADDRESS INTERFACE
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("Flags"):
                continue
            parts = line.split()
            # terse puede tener flags al inicio (D, H, etc.)
            # buscamos ip y mac
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            mac_match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', line)
            iface_match = re.search(r'interface=(\S+)', line) or re.search(r'\s+(ether\S+|bridge\S+|wlan\S+)\s*$', line)
            if ip_match and mac_match:
                entries.append({
                    "address": ip_match.group(1),
                    "mac-address": mac_match.group(1).upper(),
                    "interface": iface_match.group(1) if iface_match else "",
                })
        logger.info(f"ARP: {len(entries)} entradas en {host}")
        return entries
    except Exception as e:
        logger.error(f"Error obteniendo ARP de {host}:{port} — {e}")
        return []
    finally:
        if client:
            client.close()
