"""
Descubrimiento activo MNDP (MikroTik Neighbor Discovery Protocol).
Se ejecuta en el servidor Linux vía SSH para alcanzar la red interna.

MNDP usa UDP puerto 5678. El paquete de discovery es 4 bytes nulos.
La respuesta contiene TLVs con identidad, IP, MAC, versión RouterOS, etc.
"""
import paramiko
import json
import logging

logger = logging.getLogger(__name__)

MNDP_PORT = 5678
BROADCAST_ADDR = '255.255.255.255'

# Script Python que corre en el Linux remoto para MNDP activo
REMOTE_MNDP_SCRIPT = r'''
import socket, struct, json, time

MNDP_PORT = 5678
BROADCAST = '255.255.255.255'
LISTEN_SEC = {listen_sec}
IFACE = '{iface}'

# TLV types del protocolo MNDP
MNDP_TLV = {{
    1:  'mac_address',
    5:  'identity',
    7:  'version',
    8:  'platform',
    10: 'uptime',
    11: 'software_id',
    12: 'board',
    14: 'unpack',
    15: 'ipv6_address',
    16: 'interface_name',
    17: 'ipv4_address',
}}

def parse_mndp(data, src_ip):
    device = {{'ip': src_ip, 'protocol': 'mndp', 'raw_fields': {{}}}}
    # Header MNDP: 2 bytes tipo (siempre 0), 2 bytes TTL, luego TLVs
    if len(data) < 4:
        return device
    offset = 4
    while offset + 4 <= len(data):
        try:
            ftype = struct.unpack('>H', data[offset:offset+2])[0]
            flen  = struct.unpack('>H', data[offset+2:offset+4])[0]
            offset += 4
            val = data[offset:offset+flen]
            offset += flen
            fname = MNDP_TLV.get(ftype, f'field_{{ftype}}')
            if ftype == 1:  # MAC (6 bytes)
                device['raw_fields'][fname] = ':'.join(f'{{b:02X}}' for b in val)
            elif ftype == 10:  # uptime (4 bytes uint32)
                device['raw_fields'][fname] = struct.unpack('>I', val)[0] if len(val)==4 else 0
            elif ftype == 17:  # IPv4 (4 bytes)
                device['raw_fields'][fname] = '.'.join(str(b) for b in val[:4]) if len(val)>=4 else ''
            elif ftype == 15:  # IPv6 (16 bytes)
                device['raw_fields'][fname] = val.hex(':') if val else ''
            else:
                device['raw_fields'][fname] = val.decode('utf-8', errors='replace')
        except Exception:
            break
    rf = device['raw_fields']
    device['mac']      = rf.get('mac_address', '')
    device['identity'] = rf.get('identity', '')
    device['version']  = rf.get('version', '')
    device['platform'] = rf.get('platform', '')
    device['board']    = rf.get('board', '')
    device['iface']    = rf.get('interface_name', '')
    device['ipv4']     = rf.get('ipv4_address', src_ip)
    return device

results = {{}}
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    if IFACE:
        try:
            sock.setsockopt(socket.SOL_SOCKET, 25, IFACE.encode())
        except:
            pass
    sock.bind(('', MNDP_PORT))
    sock.settimeout(0.5)

    # Paquete de discovery: type=0, TTL=0
    discovery_pkt = b'\x00\x00\x00\x00'
    sock.sendto(discovery_pkt, (BROADCAST, MNDP_PORT))

    deadline = time.time() + LISTEN_SEC
    while time.time() < deadline:
        try:
            data, (src_ip, _) = sock.recvfrom(4096)
        except socket.timeout:
            continue
        dev = parse_mndp(data, src_ip)
        key = dev.get('mac') or src_ip
        results[key] = dev
    sock.close()
except Exception as e:
    results['__error__'] = str(e)

print(json.dumps(list(results.values())))
'''


def scan_via_linux(
    linux_host: str,
    linux_port: int,
    linux_user: str,
    linux_pass: str,
    iface: str = 'tun0',
    listen_sec: int = 5,
) -> list[dict]:
    """
    Envía MNDP discovery desde el Linux remoto y retorna los MikroTiks encontrados.
    Complementa a /ip neighbor print que solo muestra vecinos ya aprendidos.
    """
    script = REMOTE_MNDP_SCRIPT.format(listen_sec=listen_sec, iface=iface)
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=linux_host,
            port=linux_port,
            username=linux_user,
            password=linux_pass,
            timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
        logger.info(f"SSH Linux para MNDP activo OK ({linux_host})")

        escaped = script.replace("'", "'\\''")
        cmd = f"python3 -c '{escaped}'"
        _, stdout, stderr = client.exec_command(cmd, timeout=listen_sec + 20)
        raw_out = stdout.read().decode("utf-8", errors="replace").strip()
        raw_err = stderr.read().decode("utf-8", errors="replace").strip()

        if raw_err:
            logger.warning(f"MNDP activo stderr: {raw_err}")
        if not raw_out:
            return []

        devices = json.loads(raw_out)
        devices = [d for d in devices if '__error__' not in d]
        logger.info(f"MNDP activo: {len(devices)} dispositivos")
        return devices

    except json.JSONDecodeError as e:
        logger.error(f"MNDP JSON parse error: {e}")
        return []
    except Exception as e:
        logger.error(f"Error MNDP scan via Linux: {e}")
        return []
    finally:
        if client:
            client.close()
