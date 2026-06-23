"""
Pool de túneles SSH bajo demanda.

Arquitectura: Flask (esta máquina) → SSH → MikroTik hub → LAN → equipo destino

El MikroTik hub es el que el usuario ingresa en el form de network-scan.
Sus credenciales se guardan en la sesión Flask y se pasan al crear el túnel.
El servidor Linux NO es un jump host; Flask corre directamente en él en producción.

Clave del pool: (target_ip, target_port, hub_host) — permite múltiples hubs.
El túnel se cierra automáticamente tras TIMEOUT_MIN minutos de inactividad.
"""
import os
import socket
import threading
import time
import logging

import paramiko
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)
logging.getLogger('paramiko').setLevel(logging.WARNING)
logging.getLogger('paramiko.transport').setLevel(logging.ERROR)

# Credenciales por defecto (MikroTik #1) — usadas si no hay sesión activa
_M1_HOST = os.getenv('M1_HOST', '')
_M1_PORT = int(os.getenv('M1_PORT', 12222))
_M1_USER = os.getenv('M1_USER', 'admin')
_M1_PASS = os.getenv('M1_PASS', '')

TIMEOUT_MIN = int(os.getenv('TUNNEL_IDLE_TIMEOUT_MIN', '30'))  # minutos de inactividad antes de cerrar el túnel
SSH_CONNECT_TIMEOUT = float(os.getenv('TUNNEL_SSH_CONNECT_TIMEOUT', '20'))
OPEN_CHANNEL_TIMEOUT = float(os.getenv('TUNNEL_OPEN_CHANNEL_TIMEOUT', '60'))
TUNNEL_BIND_HOST = os.getenv('TUNNEL_BIND_HOST', '127.0.0.1')
TUNNEL_PUBLIC_HOST = os.getenv('TUNNEL_PUBLIC_HOST', '127.0.0.1')
_DEFAULT_ALLOWED_PORTS = '43117,47291,50983,53821,56439,59207,61381,62743,64109,65327'
TUNNEL_ALLOWED_PORTS = [
    int(p.strip())
    for p in os.getenv('TUNNEL_ALLOWED_PORTS', _DEFAULT_ALLOWED_PORTS).split(',')
    if p.strip()
]


# ── Clase de túnel individual ─────────────────────────────────────────────

class _SSHTunnel:
    """
    Túnel TCP sobre SSH usando paramiko.
    SSH directo al hub MikroTik; el hub forwardea a remote_host:remote_port en su LAN.
    """

    def __init__(self, transport, remote_host, remote_port, bind_host, local_port):
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.is_active   = False
        self.local_port  = None
        self._transport  = transport
        self._srv_sock   = None

        self._srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv_sock.bind((bind_host, local_port))
        self._srv_sock.listen(10)
        self.local_port = self._srv_sock.getsockname()[1]
        self.is_active  = True

        threading.Thread(
            target=self._accept_loop,
            daemon=True,
            name=f'Tunnel-{remote_host}:{remote_port}',
        ).start()

    def _accept_loop(self):
        transport = self._transport
        while self.is_active:
            if transport is None or not transport.is_active():
                logger.warning(
                    f"[tunnel] transporte SSH muerto {self.remote_host}:{self.remote_port} — marcando inactivo"
                )
                self.is_active = False
                break
            self._srv_sock.settimeout(1.0)
            try:
                client_sock, _ = self._srv_sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            threading.Thread(
                target=self._forward,
                args=(client_sock, transport),
                daemon=True,
            ).start()

    def _forward(self, local_sock, transport):
        try:
            chan = transport.open_channel(
                'direct-tcpip',
                (self.remote_host, self.remote_port),
                local_sock.getpeername(),
                timeout=OPEN_CHANNEL_TIMEOUT,
            )
        except Exception as e:
            logger.error(
                f"[tunnel] open_channel FALLO {self.remote_host}:{self.remote_port} — {e}"
            )
            local_sock.close()
            return

        def _pump(src, dst, close_both):
            try:
                while True:
                    data = src.recv(16384)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                if close_both:
                    try: src.close()
                    except Exception: pass
                    try: dst.close()
                    except Exception: pass

        threading.Thread(target=_pump, args=(local_sock, chan, False), daemon=True).start()
        threading.Thread(target=_pump, args=(chan, local_sock, True),  daemon=True).start()

    def stop(self):
        self.is_active = False
        try: self._srv_sock.close()
        except Exception: pass


# ── Pool de túneles ───────────────────────────────────────────────────────

class TunnelManager:
    """
    Pool thread-safe de _SSHTunnel activos.
    Clave: (target_ip, target_port, hub_host)
    """

    def __init__(self):
        self._pool: dict = {}
        self._ssh_pool: dict = {}
        self._lock = threading.Lock()
        threading.Thread(target=self._cleanup_loop, daemon=True, name='TunnelGC').start()

    def get_local_port(self, target_ip: str, target_port: int,
                       hub_host: str = None, hub_port: int = None,
                       hub_user: str = None, hub_pass: str = None) -> int:
        """
        Retorna el puerto local del túnel hacia (target_ip, target_port) via el hub.
        hub_host/port/user/pass: credenciales SSH del MikroTik hub (del form de scan).
        Si no se pasan, usa M1 del .env como fallback.
        """
        ssh_host = hub_host or _M1_HOST
        ssh_port = hub_port or _M1_PORT
        ssh_user = hub_user or _M1_USER
        ssh_pass = hub_pass or _M1_PASS

        info = self.get_local_port_info(
            target_ip, target_port,
            hub_host=ssh_host,
            hub_port=ssh_port,
            hub_user=ssh_user,
            hub_pass=ssh_pass,
        )
        return info['local_port']

    def get_local_port_info(self, target_ip: str, target_port: int,
                            hub_host: str = None, hub_port: int = None,
                            hub_user: str = None, hub_pass: str = None) -> dict:
        ssh_host = hub_host or _M1_HOST
        ssh_port = hub_port or _M1_PORT
        ssh_user = hub_user or _M1_USER
        ssh_pass = hub_pass or _M1_PASS

        key = (target_ip, target_port, ssh_host)
        with self._lock:
            entry = self._pool.get(key)
            if entry and self._is_alive(entry['tunnel']):
                entry['last_used'] = time.time()
                logger.info(
                    f"[tunnel] REUSADO {target_ip}:{target_port} via {ssh_host}"
                    f" -> localhost:{entry['tunnel'].local_port}"
                )
                return {
                    'local_port': entry['tunnel'].local_port,
                    'connect_to': self._connect_to(entry['tunnel'].local_port),
                    'public_host': TUNNEL_PUBLIC_HOST,
                    'public_url': self._public_url(entry['tunnel'].local_port, target_port),
                    'expires_in_sec': TIMEOUT_MIN * 60,
                    'reused': True,
                }
            if entry:
                self._stop(key)
            local_port = self._create(key, ssh_host, ssh_port, ssh_user, ssh_pass,
                                      target_ip, target_port)
            return {
                'local_port': local_port,
                'connect_to': self._connect_to(local_port),
                'public_host': TUNNEL_PUBLIC_HOST,
                'public_url': self._public_url(local_port, target_port),
                'expires_in_sec': TIMEOUT_MIN * 60,
                'reused': False,
            }

    def close(self, target_ip: str, target_port: int, hub_host: str = None) -> None:
        key = (target_ip, target_port, hub_host or _M1_HOST)
        with self._lock:
            self._stop(key)

    def list_active(self) -> list:
        with self._lock:
            return [
                {
                    'ip':         k[0],
                    'port':       k[1],
                    'hub':        k[2],
                    'local_port': v['tunnel'].local_port,
                    'connect_to': self._connect_to(v['tunnel'].local_port),
                    'public_host': TUNNEL_PUBLIC_HOST,
                    'public_url': self._public_url(v['tunnel'].local_port, k[1]),
                    'idle_sec':   int(time.time() - v['last_used']),
                    'active':     self._is_alive(v['tunnel']),
                }
                for k, v in self._pool.items()
            ]

    def _create(self, key, ssh_host, ssh_port, ssh_user, ssh_pass,
                target_ip, target_port) -> int:
        hub_key = (ssh_host, ssh_port, ssh_user)
        transport = self._get_hub_transport(
            hub_key, ssh_host, ssh_port, ssh_user, ssh_pass
        )
        last_error = None
        tunnel = None
        for local_port in self._available_ports():
            try:
                tunnel = _SSHTunnel(
                    transport, target_ip, target_port, TUNNEL_BIND_HOST, local_port
                )
                break
            except OSError as e:
                last_error = e
                logger.warning(
                    f"[tunnel] puerto local ocupado/no disponible {TUNNEL_BIND_HOST}:{local_port} — {e}"
                )
        if tunnel is None:
            raise RuntimeError(
                f'No hay puertos disponibles en TUNNEL_ALLOWED_PORTS: {last_error}'
            )

        self._pool[key] = {
            'tunnel': tunnel,
            'last_used': time.time(),
            'hub_key': hub_key,
        }
        logger.info(
            f"[tunnel] ABIERTO {target_ip}:{target_port} via {ssh_host}:{ssh_port}"
            f" -> localhost:{tunnel.local_port}"
        )
        return tunnel.local_port

    def _available_ports(self) -> list[int]:
        if not TUNNEL_ALLOWED_PORTS:
            raise RuntimeError('TUNNEL_ALLOWED_PORTS no tiene puertos configurados')

        used = {
            entry['tunnel'].local_port
            for entry in self._pool.values()
            if self._is_alive(entry['tunnel'])
        }
        return [port for port in TUNNEL_ALLOWED_PORTS if port not in used]

    def _public_url(self, local_port: int, target_port: int) -> str:
        scheme = 'http' if int(target_port) == 80 else 'https'
        return f'{scheme}://{TUNNEL_PUBLIC_HOST}:{local_port}/'

    def _connect_to(self, local_port: int) -> str:
        return f'{TUNNEL_PUBLIC_HOST}:{local_port}'

    def _is_alive(self, tunnel) -> bool:
        if not tunnel or not tunnel.is_active:
            return False
        try:
            transport = tunnel._transport
            return bool(transport and transport.is_active())
        except Exception:
            return False

    def _get_hub_transport(self, hub_key, ssh_host, ssh_port, ssh_user, ssh_pass):
        entry = self._ssh_pool.get(hub_key)
        if entry and self._transport_alive(entry.get('transport')):
            entry['last_used'] = time.time()
            logger.info(f"[ssh] REUSADO {ssh_host}:{ssh_port} usuario {ssh_user}")
            return entry['transport']

        if entry:
            self._close_hub(hub_key)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            ssh_host, port=ssh_port,
            username=ssh_user, password=ssh_pass,
            look_for_keys=False, allow_agent=False,
            timeout=SSH_CONNECT_TIMEOUT,
        )
        # RouterOS no soporta SSH keepalive — no llamar set_keepalive()
        transport = client.get_transport()
        self._ssh_pool[hub_key] = {
            'client': client,
            'transport': transport,
            'last_used': time.time(),
        }
        logger.info(f"[ssh] ABIERTO {ssh_host}:{ssh_port} usuario {ssh_user}")
        return transport

    def _transport_alive(self, transport) -> bool:
        try:
            return bool(transport and transport.is_active())
        except Exception:
            return False

    def _close_hub(self, hub_key) -> None:
        entry = self._ssh_pool.pop(hub_key, None)
        if entry:
            try:
                entry['client'].close()
            except Exception:
                pass
            logger.info(f"[ssh] CERRADO {hub_key[0]}:{hub_key[1]} usuario {hub_key[2]}")

    def _close_hub_if_unused(self, hub_key) -> None:
        if not hub_key:
            return
        for entry in self._pool.values():
            if entry.get('hub_key') == hub_key:
                return
        self._close_hub(hub_key)

    def _stop(self, key) -> None:
        entry = self._pool.pop(key, None)
        if entry:
            entry['tunnel'].stop()
            logger.info(f"[tunnel] CERRADO {key[0]}:{key[1]} (hub {key[2]})")
            self._close_hub_if_unused(entry.get('hub_key'))

    def _cleanup_loop(self) -> None:
        while True:
            time.sleep(60)
            cutoff = TIMEOUT_MIN * 60
            with self._lock:
                stale = [k for k, v in self._pool.items()
                         if time.time() - v['last_used'] > cutoff
                         or not self._is_alive(v['tunnel'])]
                for k in stale:
                    self._stop(k)


tunnel_manager = TunnelManager()
