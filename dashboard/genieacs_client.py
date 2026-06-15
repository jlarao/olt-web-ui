import json
import logging
import os
import time as _time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
import streamlit as st

from config import (
    GENIEACS_NBI_URL,
    GENIEACS_USERNAME,
    GENIEACS_PASSWORD,
    OFFLINE_THRESHOLD_HOURS,
)

# ──────────────────────────────────────────────
# Logger → app.log del proyecto raíz
# ──────────────────────────────────────────────

_LOG_FILE = Path(__file__).parent.parent / "app.log"

def _get_nbi_logger() -> logging.Logger:
    logger = logging.getLogger("genieacs_nbi")
    if not logger.handlers:
        handler = logging.FileHandler(_LOG_FILE, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "[%(asctime)s] %(levelname)s [NBI] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
    return logger


# ──────────────────────────────────────────────
# Log en memoria para Streamlit (session_state)
# ──────────────────────────────────────────────

_MAX_LOG_ENTRIES = 50

def _st_log_append(entry: dict):
    if "nbi_log" not in st.session_state:
        st.session_state.nbi_log = []
    st.session_state.nbi_log.insert(0, entry)
    st.session_state.nbi_log = st.session_state.nbi_log[:_MAX_LOG_ENTRIES]


def render_nbi_log(location="sidebar"):
    """
    Muestra el log de peticiones NBI en el sidebar o en la página principal.
    Llámalo desde cualquier página: render_nbi_log() o render_nbi_log("page")
    """
    entries = st.session_state.get("nbi_log", [])

    def _draw():
        if not entries:
            st.caption("Sin peticiones registradas aún.")
            return

        col_clear, _ = st.columns([1, 3])
        with col_clear:
            if st.button("🗑 Limpiar", key="clear_nbi_log"):
                st.session_state.nbi_log = []
                st.rerun()

        for e in entries:
            status = e.get("status")
            error  = e.get("error")
            elapsed = e.get("elapsed_ms")
            params  = e.get("params") or {}

            if error:
                icon = "🔴"
                status_txt = error
            elif status and status < 300:
                icon = "🟢"
                status_txt = str(status)
            else:
                icon = "🟡"
                status_txt = str(status or "?")

            elapsed_txt = f"{elapsed}ms" if elapsed is not None else ""
            label = f"{icon} `{e['ts']}` **{e['method']}** `{e['endpoint']}`  {status_txt}  {elapsed_txt}"
            with st.expander(label, expanded=False):
                st.markdown(f"**URL completa:**")
                st.code(e["url"], language=None)
                if params:
                    st.markdown("**Parámetros:**")
                    st.json(params)
                if error:
                    st.error(e.get("detail", error))
                elif e.get("count") is not None:
                    st.caption(f"Registros devueltos: {e['count']}")

    if location == "sidebar":
        with st.sidebar:
            st.markdown("---")
            st.markdown("#### 📋 Log NBI GenieACS")
            _draw()
    else:
        with st.expander("📋 Log de peticiones NBI GenieACS", expanded=False):
            _draw()


# ──────────────────────────────────────────────
# Cliente HTTP
# ──────────────────────────────────────────────

class GenieACSClient:
    def __init__(self, base_url=GENIEACS_NBI_URL, username=GENIEACS_USERNAME, password=GENIEACS_PASSWORD):
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password) if username or password else None
        self.session = requests.Session()
        if self.auth:
            self.session.auth = self.auth
        self.session.headers.update({"Accept": "application/json"})

    def _get(self, endpoint: str, params: dict = None) -> list:
        url = f"{self.base_url}{endpoint}"
        logger = _get_nbi_logger()

        logger.info("→ GET %s | params=%s", url, json.dumps(params or {}))

        log_entry = {
            "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "method": "GET",
            "endpoint": endpoint,
            "url": url,
            "params": params or {},
            "status": None,
            "elapsed_ms": None,
            "error": None,
            "count": None,
        }

        try:
            t0 = _time.monotonic()
            r = self.session.get(url, params=params, timeout=15)
            elapsed_ms = int((_time.monotonic() - t0) * 1000)
            r.raise_for_status()
            data = r.json()

            log_entry.update(status=r.status_code, elapsed_ms=elapsed_ms, count=len(data) if isinstance(data, list) else None)
            logger.info("← %s %dms | %s registros | %s",
                        r.status_code, elapsed_ms,
                        len(data) if isinstance(data, list) else "N/A",
                        url)
            _st_log_append(log_entry)
            return data

        except requests.exceptions.ConnectionError as exc:
            log_entry.update(error="ConnectionError", detail=str(exc))
            logger.error("ConnectionError GET %s → %s", url, exc)
            _st_log_append(log_entry)
            st.error(f"No se puede conectar a GenieACS en **{self.base_url}**")
            return []

        except requests.exceptions.Timeout as exc:
            log_entry.update(error="Timeout", detail=str(exc))
            logger.error("Timeout GET %s → %s", url, exc)
            _st_log_append(log_entry)
            st.error(f"Timeout al conectar con GenieACS en **{self.base_url}**")
            return []

        except requests.exceptions.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else "?"
            log_entry.update(error=f"HTTP {code}", status=code, detail=str(exc))
            logger.error("HTTP %s GET %s → %s", code, url, exc)
            _st_log_append(log_entry)
            st.error(f"Error HTTP **{code}** de GenieACS: {exc}")
            return []

        except Exception as exc:
            log_entry.update(error=type(exc).__name__, detail=str(exc))
            logger.exception("Error inesperado GET %s", url)
            _st_log_append(log_entry)
            st.error(f"Error inesperado al consultar GenieACS: {exc}")
            return []

    def get_devices(self, query=None, projection=None, limit=1000, skip=0, sort=None) -> list[dict]:
        params = {"limit": limit, "skip": skip}
        if query:
            params["query"] = json.dumps(query)
        if projection:
            params["projection"] = projection if isinstance(projection, str) else ",".join(projection)
        if sort:
            params["sort"] = json.dumps(sort)
        return self._get("/devices", params)

    def get_faults(self, query=None, limit=500) -> list[dict]:
        params = {"limit": limit}
        if query:
            params["query"] = json.dumps(query)
        return self._get("/faults", params)

    def get_tasks(self, query=None, limit=200) -> list[dict]:
        params = {"limit": limit}
        if query:
            params["query"] = json.dumps(query)
        return self._get("/tasks", params)

    def get_files(self) -> list[dict]:
        return self._get("/files")

    def create_task(self, device_id: str, task_body: dict, connection_request: bool = True, timeout: int = 3000) -> dict | None:
        """
        POST /devices/{device_id}/tasks
        Con connection_request=True GenieACS despierta al dispositivo y ejecuta el task de inmediato.
        Devuelve el task creado (dict) o None si falló.
        """
        import urllib.parse
        url = f"{self.base_url}/devices/{urllib.parse.quote(device_id, safe='')}/tasks"
        params = {}
        if connection_request:
            params["connection_request"] = ""   # parámetro sin valor, solo presencia
        if timeout:
            params["timeout"] = timeout

        logger = _get_nbi_logger()
        logger.info("→ POST %s | body=%s | params=%s", url, task_body, params)

        log_entry = {
            "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "method": "POST",
            "endpoint": f"/devices/.../tasks",
            "url": url,
            "params": {**params, **task_body},
            "status": None,
            "elapsed_ms": None,
            "error": None,
            "count": None,
        }

        try:
            t0 = _time.monotonic()
            r = self.session.post(url, json=task_body, params=params, timeout=timeout / 1000 + 5)
            elapsed_ms = int((_time.monotonic() - t0) * 1000)
            log_entry.update(status=r.status_code, elapsed_ms=elapsed_ms)

            if r.status_code in (200, 201, 202):
                data = r.json() if r.content else {}
                data["_http_status"] = r.status_code   # 200 = ejecutado, 202 = encolado
                logger.info("← %s %dms | task=%s", r.status_code, elapsed_ms, data.get("_id", "?"))
                _st_log_append(log_entry)
                return data
            else:
                log_entry.update(error=f"HTTP {r.status_code}", detail=r.text[:200])
                logger.error("← %s POST task %s → %s", r.status_code, url, r.text[:200])
                _st_log_append(log_entry)
                return None

        except requests.exceptions.Timeout:
            # GenieACS devuelve 200 antes de que el CPE responda si el timeout expira;
            # aquí significa que el requests.post tardó más que nuestro timeout de socket.
            log_entry.update(error="Timeout", detail="El dispositivo no respondió en el tiempo límite")
            logger.warning("Timeout POST task %s", url)
            _st_log_append(log_entry)
            return None
        except Exception as exc:
            log_entry.update(error=type(exc).__name__, detail=str(exc))
            logger.exception("Error POST task %s", url)
            _st_log_append(log_entry)
            return None

    def ping(self) -> bool:
        url = f"{self.base_url}/devices"
        logger = _get_nbi_logger()
        logger.debug("ping → GET %s?limit=1", url)
        try:
            t0 = _time.monotonic()
            r = self.session.get(url, params={"limit": 1}, timeout=5)
            elapsed_ms = int((_time.monotonic() - t0) * 1000)
            ok = r.status_code == 200
            logger.info("ping ← %s %dms | url=%s", r.status_code, elapsed_ms, url)
            return ok
        except Exception as exc:
            logger.error("ping FAIL %s → %s", url, exc)
            return False


# ──────────────────────────────────────────────
# Helpers de extracción y transformación
# ──────────────────────────────────────────────

def safe_get(device: dict, *path: str, default=None):
    current = device
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def get_device_status(last_inform_str: str, threshold_hours: int = OFFLINE_THRESHOLD_HOURS) -> str:
    if not last_inform_str:
        return "unknown"
    try:
        last = datetime.fromisoformat(last_inform_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        hours_ago = (now - last).total_seconds() / 3600
        if hours_ago < threshold_hours:
            return "online"
        elif hours_ago < 24:
            return "stale"
        else:
            return "offline"
    except Exception:
        return "unknown"


def format_uptime(seconds) -> str:
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        return "N/A"
    if seconds <= 0:
        return "N/A"
    d = seconds // 86400
    h = (seconds % 86400) // 3600
    m = (seconds % 3600) // 60
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    return " ".join(parts) or "< 1m"


def format_last_seen(last_inform_str: str) -> str:
    if not last_inform_str:
        return "Nunca"
    try:
        last = datetime.fromisoformat(last_inform_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        delta = now - last
        total_seconds = int(delta.total_seconds())
        if total_seconds < 60:
            return "hace un momento"
        elif total_seconds < 3600:
            return f"hace {total_seconds // 60}m"
        elif total_seconds < 86400:
            return f"hace {total_seconds // 3600}h {(total_seconds % 3600) // 60}m"
        else:
            return f"hace {total_seconds // 86400}d"
    except Exception:
        return last_inform_str


def hours_offline(last_inform_str: str) -> float:
    if not last_inform_str:
        return float("inf")
    try:
        last = datetime.fromisoformat(last_inform_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return (now - last).total_seconds() / 3600
    except Exception:
        return float("inf")


def parse_vp_one(raw) -> str:
    """VirtualParameters.one devuelve '-16,xsd:int'; extrae solo el número."""
    if raw is None:
        return ""
    val = str(raw).split(",")[0].strip()
    return val


def _iter_wan_connections(d: dict, conn_type: str):
    """
    Generador que recorre WANDevice.N.WANConnectionDevice.M.{conn_type}.K
    y devuelve (wan_idx, cd_idx, conn_idx, conn_val) para cada entrada numérica.
    conn_type: 'WANPPPConnection' | 'WANIPConnection'
    """
    wan_device = safe_get(d, "InternetGatewayDevice", "WANDevice") or {}
    for wan_idx, wan_val in sorted(wan_device.items()):
        if wan_idx.startswith("_") or not isinstance(wan_val, dict):
            continue
        wcd = wan_val.get("WANConnectionDevice") or {}
        for cd_idx, cd_val in sorted(wcd.items()):
            if cd_idx.startswith("_") or not isinstance(cd_val, dict):
                continue
            conn_parent = cd_val.get(conn_type) or {}
            for conn_idx, conn_val in sorted(conn_parent.items()):
                if conn_idx.startswith("_") or not isinstance(conn_val, dict):
                    continue
                yield wan_idx, cd_idx, conn_idx, conn_val


def _find_ppp_connection(d: dict) -> dict:
    """
    Busca en todos los índices de WANConnectionDevice el primer WANPPPConnection
    que tenga Username o ExternalIPAddress con valor cacheado.
    """
    for _, _, _, ppp_val in _iter_wan_connections(d, "WANPPPConnection"):
        if safe_get(ppp_val, "Username", "_value") or safe_get(ppp_val, "ExternalIPAddress", "_value"):
            return ppp_val
    return {}


def _find_ip_connection(d: dict) -> dict:
    """
    Busca en todos los índices el primer WANIPConnection con ExternalIPAddress.
    Se usa como fallback cuando PPPoE no tiene IP cacheada.
    """
    for _, _, _, ip_val in _iter_wan_connections(d, "WANIPConnection"):
        if safe_get(ip_val, "ExternalIPAddress", "_value"):
            return ip_val
    return {}


def flatten_device(d: dict, threshold_hours: int = OFFLINE_THRESHOLD_HOURS) -> dict:
    last_inform = safe_get(d, "_lastInform")
    serial = safe_get(d, "DeviceID", "SerialNumber", "_value") or d.get("_id", "")
    model = safe_get(d, "DeviceID", "ProductClass", "_value", default="")
    manufacturer = safe_get(d, "DeviceID", "Manufacturer", "_value", default="")
    firmware = safe_get(d, "InternetGatewayDevice", "DeviceInfo", "SoftwareVersion", "_value", default="")
    uptime_sec = safe_get(d, "InternetGatewayDevice", "DeviceInfo", "UpTime", "_value")

    # Buscar WANPPPConnection en cualquier índice de WANConnectionDevice
    ppp = _find_ppp_connection(d)
    pppoe_user  = safe_get(ppp, "Username",         "_value", default="")
    conn_status = safe_get(ppp, "ConnectionStatus", "_value", default="")
    x_hw_vlan   = safe_get(ppp, "X_HW_VLAN",        "_value", default="")
    # IP: preferir PPPoE; si no tiene, fallback a WANIPConnection (dispositivos IPoE)
    ip_wan = safe_get(ppp, "ExternalIPAddress", "_value", default="")
    if not ip_wan:
        ip_conn = _find_ip_connection(d)
        ip_wan  = safe_get(ip_conn, "ExternalIPAddress", "_value", default="")

    # X_GponInterafceConfig — TXPower y RXPower (typo real en el firmware Huawei: "Interafce")
    _gpon = ("InternetGatewayDevice", "WANDevice", "1", "X_GponInterafceConfig")
    tx_power_raw = safe_get(d, *_gpon, "TXPower", "_value")
    rx_power_raw = safe_get(d, *_gpon, "RXPower", "_value")
    tx_power = str(tx_power_raw) if tx_power_raw is not None else ""
    rx_power = str(rx_power_raw) if rx_power_raw is not None else ""

    # VirtualParameters.one → potencia óptica calculada (formato "-16,xsd:int")
    vp_one_raw = safe_get(d, "VirtualParameters", "one", "_value")
    vp_txpower = parse_vp_one(vp_one_raw)

    tags = d.get("_tags", [])
    status = get_device_status(last_inform, threshold_hours)

    return {
        "id": d.get("_id", ""),
        "serial": serial,
        "model": model,
        "manufacturer": manufacturer,
        "firmware": firmware,
        "ip_wan": ip_wan,
        "pppoe_user": pppoe_user,
        "conn_status": conn_status,
        "x_hw_vlan": x_hw_vlan,
        "tx_power": tx_power,          # X_GponInterafceConfig.TXPower (raw int)
        "rx_power": rx_power,          # X_GponInterafceConfig.RXPower (raw int, dBm)
        "vp_txpower": vp_txpower,      # VirtualParameters.one → dBm
        "uptime_sec": uptime_sec,
        "uptime_fmt": format_uptime(uptime_sec),
        "last_inform": last_inform,
        "last_seen": format_last_seen(last_inform),
        "hours_offline": hours_offline(last_inform),
        "status": status,
        "tags": ", ".join(tags) if tags else "",
        "registered": safe_get(d, "_registered", default=""),
    }


# ──────────────────────────────────────────────
# Funciones cacheadas para Streamlit
# ──────────────────────────────────────────────

@st.cache_data(ttl=10)
def cached_get_devices(threshold_hours: int = OFFLINE_THRESHOLD_HOURS) -> list[dict]:
    client = GenieACSClient()
    raw = client.get_devices(limit=2000)
    return [flatten_device(d, threshold_hours) for d in raw]


@st.cache_data(ttl=10)
def cached_get_faults() -> list[dict]:
    client = GenieACSClient()
    return client.get_faults()


@st.cache_data(ttl=10)
def cached_get_files() -> list[dict]:
    client = GenieACSClient()
    return client.get_files()


@st.cache_data(ttl=10)
def cached_get_tasks() -> list[dict]:
    client = GenieACSClient()
    return client.get_tasks()
