import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import io
import streamlit as st
import pandas as pd

from config import DASHBOARD_TITLE, OFFLINE_THRESHOLD_HOURS, STATUS_EMOJI
from genieacs_client import cached_get_devices, GenieACSClient, render_nbi_log

st.set_page_config(
    page_title=f"Dispositivos — {DASHBOARD_TITLE}",
    page_icon="📋",
    layout="wide",
)

st.title("📋 Dispositivos")

# ── Sidebar filtros ───────────────────────────────────────────────────────────
with st.sidebar:
    st.header("Filtros")

    threshold = st.slider(
        "Umbral offline (horas)",
        min_value=1, max_value=72, value=OFFLINE_THRESHOLD_HOURS, step=1,
        help="ONUs sin contacto más de N horas se consideran offline"
    )

    filter_status = st.multiselect(
        "Estado",
        options=["online", "stale", "offline", "unknown"],
        default=[],
        format_func=lambda s: f"{STATUS_EMOJI.get(s, '❓')} {s.capitalize()}",
    )

    search_text = st.text_input(
        "Buscar",
        placeholder="Serial, IP, usuario PPPoE...",
    )

# ── Cargar datos ─────────────────────────────────────────────────────────────
client = GenieACSClient()
if not client.ping():
    st.error("⚠️ No se puede conectar a GenieACS.")
    st.stop()

with st.spinner("Cargando dispositivos..."):
    devices = cached_get_devices(threshold)

if not devices:
    st.warning("No se encontraron dispositivos.")
    st.stop()

# ── Filtros dinámicos (modelo y tags) ─────────────────────────────────────────
all_models = sorted(set(d["model"] for d in devices if d["model"]))
all_tags_raw = []
for d in devices:
    all_tags_raw.extend(d["tags"].split(", ") if d["tags"] else [])
all_tags = sorted(set(t for t in all_tags_raw if t))

with st.sidebar:
    filter_model = st.multiselect("Modelo", options=all_models, default=[])
    filter_tags = st.multiselect("Tags", options=all_tags, default=[])

# ── Aplicar filtros ──────────────────────────────────────────────────────────
filtered = devices

if filter_status:
    filtered = [d for d in filtered if d["status"] in filter_status]

if filter_model:
    filtered = [d for d in filtered if d["model"] in filter_model]

if filter_tags:
    filtered = [
        d for d in filtered
        if any(t in d["tags"].split(", ") for t in filter_tags)
    ]

if search_text:
    q = search_text.lower()
    filtered = [
        d for d in filtered
        if q in d["serial"].lower()
        or q in d["ip_wan"].lower()
        or q in d["pppoe_user"].lower()
    ]

st.caption(f"Mostrando {len(filtered)} de {len(devices)} dispositivos")

# ── Construir DataFrame ───────────────────────────────────────────────────────
rows = []
for d in filtered:
    emoji = STATUS_EMOJI.get(d["status"], "❓")
    rx  = d.get("rx_power", "")
    tx  = d.get("tx_power", "")
    vp  = d.get("vp_txpower", "")
    rows.append({
        "Estado": f"{emoji} {d['status'].capitalize()}",
        "Serial": d["serial"],
        "Modelo": d["model"],
        "Fabricante": d["manufacturer"],
        "Firmware": d["firmware"],
        "VLAN": d.get("x_hw_vlan", ""),
        "IP WAN": d["ip_wan"],
        "Usuario PPPoE": d["pppoe_user"],
        "RX Power (dBm)": f"{rx} dBm" if rx else "—",
        "TX Power (dBm)": f"{tx} dBm" if tx else "—",
        "VP Señal (dBm)": f"{vp} dBm" if vp else "—",
        "Uptime": d["uptime_fmt"],
        "Último contacto": d["last_seen"],
        "Tags": d["tags"],
        "_id": d["id"],
        "_status_raw": d["status"],
    })

df = pd.DataFrame(rows)

# Columnas opcionales (ocultas por defecto)
_OPTIONAL_COLS = ["Modelo", "Fabricante", "Firmware"]
_ALL_VISIBLE   = [c for c in df.columns if not c.startswith("_")]
_DEFAULT_COLS  = [c for c in _ALL_VISIBLE if c not in _OPTIONAL_COLS]

with st.sidebar:
    extra_cols = st.multiselect(
        "Columnas adicionales",
        options=_OPTIONAL_COLS,
        default=[],
    )

display_cols = _DEFAULT_COLS + [c for c in _OPTIONAL_COLS if c in extra_cols]

# ── Tabla interactiva ─────────────────────────────────────────────────────────
st.subheader("Tabla de dispositivos")

selection = st.dataframe(
    df[display_cols],
    use_container_width=True,
    hide_index=True,
    selection_mode="single-row",
    on_select="rerun",
    key="device_table",
)

# ── Detalle de fila seleccionada ─────────────────────────────────────────────
selected_rows = selection.selection.rows if selection else []
if selected_rows:
    idx = selected_rows[0]
    if idx >= len(df):
        # Selección anterior fuera de rango tras filtrar — ignorar
        selected_rows = []
    else:
        device_id = df.iloc[idx]["_id"]

if selected_rows:
    # Buscar el raw device original
    raw_match = next((d for d in devices if d["id"] == device_id), None)
    if raw_match:
        st.divider()
        st.subheader(f"Detalle: {raw_match['serial']}")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown("**Identificación**")
            st.write(f"ID: `{raw_match['id']}`")
            st.write(f"Serial: `{raw_match['serial']}`")
            st.write(f"Modelo: `{raw_match['model']}`")
            st.write(f"Fabricante: `{raw_match['manufacturer']}`")
            st.write(f"Estado: `{raw_match['status'].upper()}`")
            st.write(f"Tags: `{raw_match['tags']}`")
        with col2:
            st.markdown("**Software / Uptime**")
            st.write(f"Firmware: `{raw_match['firmware']}`")
            st.write(f"Uptime: `{raw_match['uptime_fmt']}`")
            st.write(f"Registrado: `{raw_match['registered']}`")
            st.write(f"Último contacto: `{raw_match['last_seen']}`")
        with col3:
            st.markdown("**Conectividad WAN**")
            st.write(f"IP WAN: `{raw_match['ip_wan']}`")
            st.write(f"Usuario PPPoE: `{raw_match['pppoe_user']}`")
            st.write(f"Estado conexión: `{raw_match['conn_status']}`")
            st.write(f"VLAN (X_HW_VLAN): `{raw_match.get('x_hw_vlan', '—')}`")

        col4, col5 = st.columns([2, 1])
        with col4:
            st.markdown("**Señal GPON**")
            rx  = raw_match.get("rx_power", "")
            txp = raw_match.get("tx_power", "")
            vp  = raw_match.get("vp_txpower", "")
            st.write(f"RX Power: `{rx} dBm`" if rx else "RX Power: `—`")
            st.write(f"TX Power: `{txp} dBm`" if txp else "TX Power: `—`")
            st.write(f"VP Señal: `{vp} dBm`" if vp else "VP Señal: `—`")
        with col5:
            st.markdown("&nbsp;", unsafe_allow_html=True)
            from components.device_card import _refresh_gpon
            if st.button("🔄 Actualizar GPON", key=f"ref_{raw_match['id']}", use_container_width=True):
                _refresh_gpon(raw_match["id"])

render_nbi_log()

# ── Exportar CSV ─────────────────────────────────────────────────────────────
st.divider()
csv_buffer = io.StringIO()
df[display_cols].to_csv(csv_buffer, index=False)
st.download_button(
    label="⬇️ Exportar CSV",
    data=csv_buffer.getvalue(),
    file_name="dispositivos_onu.csv",
    mime="text/csv",
)
