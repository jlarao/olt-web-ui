import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime, timezone, timedelta

from config import DASHBOARD_TITLE, OFFLINE_THRESHOLD_HOURS, STATUS_COLORS
from genieacs_client import (
    GenieACSClient,
    cached_get_devices,
    cached_get_faults,
)
from components.metrics import render_kpi_row, last_update_caption
from genieacs_client import render_nbi_log

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title=DASHBOARD_TITLE,
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Header ───────────────────────────────────────────────────────────────────
col_title, col_btn = st.columns([6, 1])
with col_title:
    st.title(f"📡 {DASHBOARD_TITLE}")
with col_btn:
    if st.button("🔄 Actualizar", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

last_update_caption()

# ── Conectividad con GenieACS ─────────────────────────────────────────────────
client = GenieACSClient()
if not client.ping():
    st.error("⚠️ No se puede conectar a GenieACS. Verifica la URL en `.env`.")
    st.stop()

# ── Cargar datos ─────────────────────────────────────────────────────────────
with st.spinner("Cargando datos de GenieACS..."):
    devices = cached_get_devices(OFFLINE_THRESHOLD_HOURS)
    faults = cached_get_faults()

if not devices:
    st.warning("No se encontraron dispositivos en GenieACS.")
    st.stop()

# ── KPIs ─────────────────────────────────────────────────────────────────────
st.subheader("Resumen general")
total = len(devices)
online_count = sum(1 for d in devices if d["status"] == "online")
offline_count = sum(1 for d in devices if d["status"] in ("offline", "unknown"))
stale_count = sum(1 for d in devices if d["status"] == "stale")
fault_count = len(faults)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total ONUs", total)
col2.metric("Online", online_count, help="Últimas 4 horas")
col3.metric("Offline / Desconocido", offline_count)
col4.metric("Con faults activos", fault_count)

st.divider()

# ── Gráficos fila 2 ──────────────────────────────────────────────────────────
col_pie, col_bar = st.columns(2)

with col_pie:
    st.subheader("Estado de conectividad")
    status_counts = {
        "Online": online_count,
        "Stale (4-24h)": stale_count,
        "Offline (>24h)": sum(1 for d in devices if d["status"] == "offline"),
        "Desconocido": sum(1 for d in devices if d["status"] == "unknown"),
    }
    fig_pie = px.pie(
        names=list(status_counts.keys()),
        values=list(status_counts.values()),
        color=list(status_counts.keys()),
        color_discrete_map={
            "Online": STATUS_COLORS["online"],
            "Stale (4-24h)": STATUS_COLORS["stale"],
            "Offline (>24h)": STATUS_COLORS["offline"],
            "Desconocido": STATUS_COLORS["unknown"],
        },
        hole=0.35,
    )
    fig_pie.update_traces(textposition="inside", textinfo="percent+label")
    fig_pie.update_layout(showlegend=True, height=320, margin=dict(t=10, b=10))
    st.plotly_chart(fig_pie, use_container_width=True)

with col_bar:
    st.subheader("Top modelos de ONU")
    model_counts = {}
    for d in devices:
        m = d["model"] or "Desconocido"
        model_counts[m] = model_counts.get(m, 0) + 1
    top_models = sorted(model_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    if top_models:
        fig_bar = px.bar(
            x=[m for m, _ in top_models],
            y=[c for _, c in top_models],
            labels={"x": "Modelo", "y": "Cantidad"},
            color_discrete_sequence=["#3498db"],
        )
        fig_bar.update_layout(height=320, margin=dict(t=10, b=10))
        st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.info("No hay datos de modelos disponibles.")

st.divider()

# ── Línea de tiempo de faults (últimos 7 días) ────────────────────────────────
st.subheader("Faults por día — últimos 7 días")
if faults:
    now_utc = datetime.now(timezone.utc)
    seven_days_ago = now_utc - timedelta(days=7)
    fault_dates = []
    for f in faults:
        ts = f.get("timestamp")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt >= seven_days_ago:
                    fault_dates.append(dt.date())
            except Exception:
                pass

    if fault_dates:
        df_faults = pd.DataFrame({"fecha": fault_dates})
        df_grouped = df_faults.groupby("fecha").size().reset_index(name="cantidad")
        fig_timeline = px.line(
            df_grouped,
            x="fecha",
            y="cantidad",
            markers=True,
            labels={"fecha": "Fecha", "cantidad": "Faults"},
            color_discrete_sequence=["#e74c3c"],
        )
        fig_timeline.update_layout(height=280, margin=dict(t=10, b=10))
        st.plotly_chart(fig_timeline, use_container_width=True)
    else:
        st.info("No hay faults en los últimos 7 días.")
else:
    st.info("No hay faults registrados.")

st.divider()

# ── Tabla: ONUs offline más tiempo ───────────────────────────────────────────
st.subheader("ONUs offline más tiempo")
offline_devices = [
    d for d in devices if d["status"] in ("offline", "stale", "unknown")
]
offline_devices.sort(key=lambda d: d["hours_offline"], reverse=True)
top_offline = offline_devices[:10]

if top_offline:
    rows = []
    for d in top_offline:
        hours = d["hours_offline"]
        hours_str = f"{hours:.1f}h" if hours != float("inf") else "∞"
        rows.append({
            "Serial": d["serial"],
            "Modelo": d["model"],
            "Última vez online": d["last_seen"],
            "Horas offline": hours_str,
            "Estado": d["status"].upper(),
            "Tags": d["tags"],
        })
    df_offline = pd.DataFrame(rows)

    def highlight_long_offline(row):
        hours_str = row["Horas offline"]
        try:
            hours = float(hours_str.replace("h", "").replace("∞", "9999"))
        except Exception:
            hours = 0
        color = "background-color: #fdd;" if hours > 24 else ""
        return [color] * len(row)

    styled = df_offline.style.apply(highlight_long_offline, axis=1)
    st.dataframe(styled, use_container_width=True, hide_index=True)
else:
    st.success("Todas las ONUs están en línea.")

render_nbi_log()
