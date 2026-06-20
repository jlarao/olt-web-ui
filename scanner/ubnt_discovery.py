"""
Descubrimiento de equipos Ubiquiti via UDP puerto 10001.
Soporta protocolo Legacy (v1) y nuevo protocolo AC (v2).

Se ejecuta REMOTAMENTE en el servidor Linux via SSH para alcanzar
la red interna a través del túnel VPN (tun0).
"""
import paramiko
import struct
import logging
import json

logger = logging.getLogger(__name__)

# Magic bytes para cada versión del protocolo UBNT
UBNT_MAGIC_V1 = b'\x01\x00\x00\x00'  # Legacy: airMAX M, NanoStation, etc.
UBNT_MAGIC_V2 = b'\x02\x0a\x00\x00'  # AC: airMAX AC, airFiber, UniFi

UBNT_PORT = 10001
BROADCAST_ADDR = '255.255.255.255'
LISTEN_TIMEOUT = 5  # segundos esperando respuestas

# TLV field types conocidos del protocolo UBNT
UBNT_TLV_TYPES = {
    0x01: 'mac_address',
    0x02: 'mac_and_ip',
    0x03: 'firmware',
    0x06: 'username',
    0x0a: 'uptime',
    0x0b: 'hostname',
    0x0c: 'platform',
    0x0d: 'essid',
    0x0f: 'wmode',
    0x10: 'seq',
    0x13: 'source_ip',
    0x16: 'model',
    0x17: 'model_short',
    0x1a: 'ip_info',
}

# Script Python que se ejecutará en el servidor Linux remoto
REMOTE_SCANNER_SCRIPT = r'''
import socket, struct, json, time, sys, select

UBNT_PORT = 10001
BROADCAST = '255.255.255.255'
MAGIC_V1 = b'\x01\x00\x00\x00'
MAGIC_V2 = b'\x02\x0a\x00\x00'
LISTEN_SEC = {listen_sec}
IFACE = '{iface}'

TLV_TYPES = {{
    0x01:'mac_address', 0x02:'mac_and_ip', 0x03:'firmware',
    0x06:'username', 0x0a:'uptime', 0x0b:'hostname',
    0x0c:'platform', 0x0d:'essid', 0x0f:'wmode',
    0x13:'source_ip', 0x16:'model', 0x17:'model_short',
}}

def parse_ubnt_packet(data, src_ip, version):
    device = {{'ip': src_ip, 'protocol_version': version, 'raw_fields': {{}}}}
    offset = 4  # skip magic (4 bytes)
    try:
        payload_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        end = offset + payload_len
        while offset + 4 <= end and offset + 4 <= len(data):
            ftype = data[offset]
            flen = struct.unpack('>H', data[offset+1:offset+3])[0]
            offset += 3
            val = data[offset:offset+flen]
            offset += flen
            fname = TLV_TYPES.get(ftype, f'field_{{hex(ftype)}}')
            if ftype in (0x01,):
                device['raw_fields'][fname] = ':'.join(f'{{b:02X}}' for b in val)
            elif ftype == 0x02 and len(val) >= 10:
                mac = ':'.join(f'{{b:02X}}' for b in val[:6])
                ip = '.'.join(str(b) for b in val[6:10])
                device['raw_fields']['mac_address'] = mac
                device['raw_fields']['ip_from_tlv'] = ip
            elif ftype == 0x0a and len(val) == 4:
                device['raw_fields'][fname] = struct.unpack('>I', val)[0]
            else:
                try:
                    device['raw_fields'][fname] = val.decode('utf-8', errors='replace')
                except:
                    device['raw_fields'][fname] = val.hex()
    except Exception as e:
        device['parse_error'] = str(e)
    # Aplanar campos útiles
    rf = device['raw_fields']
    device['mac'] = rf.get('mac_address', '')
    device['hostname'] = rf.get('hostname', '')
    device['model'] = rf.get('model', rf.get('platform', ''))
    device['firmware'] = rf.get('firmware', '')
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
    sock.bind(('', UBNT_PORT))
    sock.settimeout(0.5)

    # Enviar discovery activo
    for magic in (MAGIC_V1, MAGIC_V2):
        pkt = magic + b'\x00\x00'
        sock.sendto(pkt, (BROADCAST, UBNT_PORT))

    deadline = time.time() + LISTEN_SEC
    while time.time() < deadline:
        try:
            data, (src_ip, _) = sock.recvfrom(4096)
        except socket.timeout:
            continue
        if len(data) < 6:
            continue
        if data[:4] == MAGIC_V1:
            version = 'ubnt_legacy'
        elif data[:4] == MAGIC_V2:
            version = 'ubnt_ac'
        else:
            continue
        dev = parse_ubnt_packet(data, src_ip, version)
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
    listen_sec: int = LISTEN_TIMEOUT,
) -> list[dict]:
    """
    Ejecuta el scanner UBNT en el servidor Linux remoto vía SSH.
    Retorna lista de dispositivos Ubiquiti encontrados.
    """
    script = REMOTE_SCANNER_SCRIPT.format(listen_sec=listen_sec, iface=iface)
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
        logger.info(f"SSH al servidor Linux {linux_host}:{linux_port} OK")

        # Escapar comillas simples en el script para el comando
        escaped = script.replace("'", "'\\''")
        cmd = f"python3 -c '{escaped}'"

        _, stdout, stderr = client.exec_command(cmd, timeout=listen_sec + 20)
        raw_out = stdout.read().decode("utf-8", errors="replace").strip()
        raw_err = stderr.read().decode("utf-8", errors="replace").strip()

        if raw_err:
            logger.warning(f"UBNT scanner stderr: {raw_err}")

        if not raw_out:
            logger.warning("UBNT scanner no retornó datos")
            return []

        devices = json.loads(raw_out)
        # Filtrar el posible campo de error global
        devices = [d for d in devices if '__error__' not in d]
        logger.info(f"UBNT: {len(devices)} dispositivos encontrados")
        return devices

    except json.JSONDecodeError as e:
        logger.error(f"Error parseando respuesta UBNT JSON: {e} — raw: {raw_out[:200]}")
        return []
    except Exception as e:
        logger.error(f"Error en scan UBNT via Linux: {e}")
        return []
    finally:
        if client:
            client.close()
