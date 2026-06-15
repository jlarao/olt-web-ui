import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import streamlit as st
import plotly.express as px
import pandas as pd
from datetime import datetime, timezone

from config import DASHBOARD_TITLE, FAULT_CODE_DESCRIPTIONS
from genieacs_client import cached_get_faults, GenieACSClient, render_nbi_log

st.set_page_config(
    page_title=f"Faults — {DASHBOARD_TITLE}",
    page_icon="🚨",
    layout="wide",
)

st.title("🚨 Faults y Errores")

# ── Conectividad ─────────────────────────────────────────────────────────────
client = GenieACSClient()
if not client.ping():
    st.error("⚠️ No se puede conectar a GenieACS.")
    st.stop()

with st.spinner("Cargando faults..."):
    faults = cached_get_faults()

if not faults:
    st.success("✅ No hay faults activos en GenieACS.")
    st.stop()

# ── KPIs ─────────────────────────────────────────────────────────────────────
total = len(faults)
provision = sum(1 for f in faults if f.get("channel") == "provision")
offline_f = sum(1 for f in faults if f.get("code") == "device_offline")

col1, col2, col3 = st.columns(3)
col1.metric("Total faults activos", total)
col2.metric("Canal provision", provision)
col3.metric("device_offline", offline_f)

st.divider()

# ── Gráficos ─────────────────────────────────────────────────────────────────
col_pie, col_bar = st.columns(2)

with col_pie:
    st.subheader("Distribución por tipo de fault")
    code_counts = {}
    for f in faults:
        code = f.get("code", "unknown")
        code_counts[code] = code_counts.get(code, 0) + 1
    fig_pie = px.pie(
        names=list(code_counts.keys()),
        values=list(code_counts.values()),
        hole=0.3,
    )
    fig_pie.update_traces(textposition="inside", textinfo="percent+label")
    fig_pie.update_layout(height=320, margin=dict(t=10, b=10))
    st.plotly_chart(fig_pie, use_container_width=True)

with col_bar:
    st.subheader("Top 10 dispositivos con más faults")
    device_fault_counts = {}
    for f in faults:
        dev = f.get("device", "unknown")
        device_fault_counts[dev] = device_fault_counts.get(dev, 0) + 1
    top_devices = sorted(device_fault_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    if top_devices:
        labels = [d[:30] + "..." if len(d) > 30 else d for d, _ in top_devices]
        fig_bar = px.bar(
            x=[c for _, c in top_devices],
            y=labels,
            orientation="h",
            labels={"x": "Faults", "y": "Dispositivo"},
            color_discrete_sequence=["#e74c3c"],
        )
        fig_bar.update_layout(height=320, margin=dict(t=10, b=10), yaxis={"autorange": "reversed"})
        st.plotly_chart(fig_bar, use_container_width=True)

st.divider()

# ── Tabla de faults ───────────────────────────────────────────────────────────
st.subheader("Listado de faults")

rows = []
for f in faults:
    ts = f.get("timestamp", "")
    rows.append({
        "Dispositivo": f.get("device", ""),
        "Canal": f.get("channel", ""),
        "Código": f.get("code", ""),
        "Mensaje": f.get("message", ""),
        "Fecha": ts,
        "Reintentos": f.get("retries", 0),
    })

df_faults = pd.DataFrame(rows)
if not df_faults.empty:
    df_faults = df_faults.sort_values("Fecha", ascending=False)

    def highlight_retries(row):
        if row["Reintentos"] > 3:
            return ["background-color: #fdd;"] * len(row)
        return [""] * len(row)

    styled = df_faults.style.apply(highlight_retries, axis=1)
    st.dataframe(styled, use_container_width=True, hide_index=True)
else:
    st.info("No hay faults para mostrar.")

render_nbi_log()

# ── Referencia de códigos ─────────────────────────────────────────────────────
with st.expander("📖 Referencia de códigos de fault"):
    for code, desc in FAULT_CODE_DESCRIPTIONS.items():
        st.markdown(f"- **`{code}`** — {desc}")
