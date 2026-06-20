"""
Opción C: historial acumulativo de dispositivos UDP:10001 en SQLite.

Tabla ubnt_seen:
  mac         — clave primaria (normalizada a mayúsculas)
  ip          — última IP conocida
  router_host — MikroTik donde se vio por última vez
  first_seen  — primera detección
  last_seen   — última detección
  seen_count  — cuántas veces se ha visto entre scans

Los MACs de esta tabla se inyectan en el scanner como fuente 'history',
complementando los resultados en vivo cuando la ventana del sniffer o el
log de firewall no alcanzan a capturar un dispositivo.
"""
import sqlite3
import os
import logging

logger = logging.getLogger(__name__)

_DB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'ubnt_seen.db',
)


def _connect() -> sqlite3.Connection:
    c = sqlite3.connect(_DB)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    """Crea la tabla si no existe. Llamar una vez al inicio de la app."""
    with _connect() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS ubnt_seen (
                mac          TEXT PRIMARY KEY,
                ip           TEXT    DEFAULT '',
                router_host  TEXT    DEFAULT '',
                first_seen   TEXT    DEFAULT (datetime('now')),
                last_seen    TEXT    DEFAULT (datetime('now')),
                seen_count   INTEGER DEFAULT 1
            )
        ''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_last_seen ON ubnt_seen (last_seen)')


def update_seen(devices: list[dict], router_host: str) -> int:
    """
    Inserta o actualiza los dispositivos detectados en el scan actual.
    Retorna el número de filas afectadas.
    """
    count = 0
    try:
        with _connect() as db:
            for dev in devices:
                mac = (dev.get('mac') or '').upper().strip()
                if len(mac) != 17:
                    continue
                ip = dev.get('ip') or ''
                db.execute('''
                    INSERT INTO ubnt_seen (mac, ip, router_host)
                    VALUES (?, ?, ?)
                    ON CONFLICT(mac) DO UPDATE SET
                        ip          = CASE WHEN excluded.ip != '' THEN excluded.ip ELSE ip END,
                        router_host = excluded.router_host,
                        last_seen   = datetime('now'),
                        seen_count  = seen_count + 1
                ''', (mac, ip, router_host))
                count += 1
    except Exception as e:
        logger.error(f"[ubnt_history] Error actualizando historial: {e}")
    return count


def get_recent(days: int = 30) -> list[dict]:
    """
    Opción C: retorna MACs vistas en los últimos `days` días.
    Cada entrada tiene source='history' para distinguirla en el merge.
    """
    try:
        with _connect() as db:
            rows = db.execute('''
                SELECT mac, ip, router_host, first_seen, last_seen, seen_count
                FROM ubnt_seen
                WHERE last_seen >= datetime('now', ?)
                ORDER BY last_seen DESC
            ''', (f'-{days} days',)).fetchall()
        return [
            {
                'mac':         r['mac'],
                'ip':          r['ip'],
                'router_host': r['router_host'],
                'first_seen':  r['first_seen'],
                'last_seen':   r['last_seen'],
                'seen_count':  r['seen_count'],
                'source':      'history',
            }
            for r in rows
        ]
    except Exception as e:
        logger.error(f"[ubnt_history] Error leyendo historial: {e}")
        return []


def purge_old(days: int = 90) -> int:
    """Elimina registros más antiguos de `days` días. Retorna filas borradas."""
    try:
        with _connect() as db:
            cur = db.execute(
                "DELETE FROM ubnt_seen WHERE last_seen < datetime('now', ?)",
                (f'-{days} days',),
            )
            return cur.rowcount
    except Exception as e:
        logger.error(f"[ubnt_history] Error en purge: {e}")
        return 0
