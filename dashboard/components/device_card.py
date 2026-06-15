import streamlit as st
from genieacs_client import (
    GenieACSClient,
    safe_get, format_uptime, format_last_seen,
    get_device_status, parse_vp_one,
    _find_ppp_connection, _find_ip_connection,
)
from config import STATUS_EMOJI, OFFLINE_THRESHOLD_HOURS

# Parámetros GPON que se piden al dispositivo en el task de refresh
_GPON_PARAMS = [
    "InternetGatewayDevice.WANDevice.1.X_GponInterafceConfig.RXPower",
    "InternetGatewayDevice.WANDevice.1.X_GponInterafceConfig.TXPower",
    "VirtualParameters.one",
]


def _signal_color(dbm_str: str) -> str:
    """Devuelve un emoji de nivel de señal según el valor en dBm."""
    try:
        v = float(dbm_str)
        if v >= -20:
            return "🟢"
        elif v >= -25:
            return "🟡"
        else:
            return "🔴"
    except (TypeError, ValueError):
        return "⚪"


def render_device_card(raw_device: dict, threshold_hours: int = OFFLINE_THRESHOLD_HOURS):
    d = raw_device
    last_inform = safe_get(d, "_lastInform")
    status      = get_device_status(last_inform, threshold_hours)
    emoji       = STATUS_EMOJI.get(status, "❓")

    serial       = safe_get(d, "DeviceID", "SerialNumber", "_value") or d.get("_id", "N/A")
    model        = safe_get(d, "DeviceID", "ProductClass",  "_value", default="N/A")
    manufacturer = safe_get(d, "DeviceID", "Manufacturer",  "_value", default="N/A")
    oui          = safe_get(d, "DeviceID", "OUI",           "_value", default="N/A")
    firmware     = safe_get(d, "InternetGatewayDevice", "DeviceInfo", "SoftwareVersion", "_value", default="N/A")
    hardware     = safe_get(d, "InternetGatewayDevice", "DeviceInfo", "HardwareVersion", "_value", default="N/A")
    uptime_sec   = safe_get(d, "InternetGatewayDevice", "DeviceInfo", "UpTime", "_value")
    registered   = safe_get(d, "_registered", default="N/A")
    tags         = d.get("_tags", [])
    device_id    = d.get("_id", "")

    ppp         = _find_ppp_connection(d)
    pppoe_user  = safe_get(ppp, "Username",         "_value", default="—")
    conn_status = safe_get(ppp, "ConnectionStatus", "_value", default="—")
    x_hw_vlan   = safe_get(ppp, "X_HW_VLAN",        "_value", default="—")
    ip_wan      = safe_get(ppp, "ExternalIPAddress", "_value", default="")
    if not ip_wan:
        ip_conn = _find_ip_connection(d)
        ip_wan  = safe_get(ip_conn, "ExternalIPAddress", "_value", default="—")

    _gpon = ("InternetGatewayDevice", "WANDevice", "1", "X_GponInterafceConfig")
    tx_raw = safe_get(d, *_gpon, "TXPower", "_value")
    rx_raw = safe_get(d, *_gpon, "RXPower", "_value")
    tx_power = str(tx_raw) if tx_raw is not None else "—"
    rx_power = str(rx_raw) if rx_raw is not None else "—"

    vp_one_raw = safe_get(d, "VirtualParameters", "one", "_value")
    vp_txpower = parse_vp_one(vp_one_raw) or "—"

    with st.container(border=True):
        st.subheader(f"{emoji} {serial}")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown("**Identificación**")
            st.write(f"Modelo: `{model}`")
            st.write(f"Fabricante: `{manufacturer}`")
            st.write(f"OUI: `{oui}`")
            st.write(f"Estado: `{status.upper()}`")
            st.write(f"Registrado: `{registered}`")

        with col2:
            st.markdown("**Software / Hardware**")
            st.write(f"Firmware: `{firmware}`")
            st.write(f"Hardware: `{hardware}`")
            st.write(f"Uptime: `{format_uptime(uptime_sec)}`")
            st.write(f"Último contacto: `{format_last_seen(last_inform)}`")

        with col3:
            st.markdown("**Conectividad WAN**")
            st.write(f"IP WAN: `{ip_wan}`")
            st.write(f"Usuario PPPoE: `{pppoe_user}`")
            st.write(f"Estado conexión: `{conn_status}`")
            st.write(f"VLAN (X_HW_VLAN): `{x_hw_vlan}`")

        st.divider()

        # ── Señal GPON + botón de refresh ────────────────────────────────────
        col_signal, col_btn = st.columns([3, 1])

        with col_signal:
            st.markdown("**Señal GPON**")
            rx_icon = _signal_color(rx_power)
            st.write(f"RX Power (X_GponInterafceConfig): {rx_icon} `{rx_power} dBm`")
            st.write(f"TX Power (X_GponInterafceConfig): `{tx_power} dBm`")
            st.write(f"Potencia óptica (VirtualParameters.one): `{vp_txpower} dBm`")

        with col_btn:
            st.markdown("&nbsp;", unsafe_allow_html=True)   # alinear verticalmente
            refresh_key = f"refresh_gpon_{device_id}"
            if st.button("🔄 Actualizar GPON", key=refresh_key, use_container_width=True,
                         help="Envía un getParameterValues al dispositivo para leer la señal en tiempo real"):
                _refresh_gpon(device_id)

        if tags:
            st.divider()
            st.write("Tags: " + " ".join(f"`{t}`" for t in tags))


def _refresh_gpon(device_id: str):
    """
    Crea un task getParameterValues en GenieACS con connection_request.
    GenieACS contacta al dispositivo, lee los valores y responde 200 cuando termina.
    Luego limpia el caché y recarga la página automáticamente.
    """
    client = GenieACSClient()

    with st.spinner("Contactando dispositivo, espere…"):
        result = client.create_task(
            device_id=device_id,
            task_body={
                "name": "getParameterValues",
                "parameterNames": _GPON_PARAMS,
            },
            connection_request=True,
            timeout=10000,
        )

    if result is None:
        st.error("No se pudo ejecutar el task. Revisa el log NBI.")
        return

    http_status = result.get("_http_status")
    task_id     = result.get("_id", "?")

    if http_status == 200:
        st.success(f"✅ Valores actualizados — recargando…")
    else:
        # 202 = task encolado, el dispositivo no respondió en el timeout
        st.warning(f"⚠️ Task encolado (dispositivo no respondió aún) — ID: `{task_id}`")

    st.cache_data.clear()
    st.rerun()
