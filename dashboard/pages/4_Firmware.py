import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import streamlit as st
import plotly.express as px
import pandas as pd

from config import DASHBOARD_TITLE, OFFLINE_THRESHOLD_HOURS
from genieacs_client import cached_get_devices, cached_get_files, GenieACSClient, render_nbi_log

st.set_page_config(
    page_title=f"Firmware — {DASHBOARD_TITLE}",
    page_icon="💾",
    layout="wide",
)

st.title("💾 Firmware")

# ── Conectividad ─────────────────────────────────────────────────────────────
client = GenieACSClient()
if not client.ping():
    st.error("⚠️ No se puede conectar a GenieACS.")
    st.stop()

with st.spinner("Cargando datos de firmware..."):
    devices = cached_get_devices(OFFLINE_THRESHOLD_HOURS)
    files = cached_get_files()

# ── Gráfico: versiones de firmware por modelo ─────────────────────────────────
st.subheader("Distribución de versiones de firmware")

firmware_data = []
for d in devices:
    if d["firmware"] and d["model"]:
        firmware_data.append({"modelo": d["model"], "firmware": d["firmware"]})

if firmware_data:
    df_fw = pd.DataFrame(firmware_data)
    df_grouped = (
        df_fw.groupby(["firmware", "modelo"])
        .size()
        .reset_index(name="cantidad")
        .sort_values("firmware")
    )
    fig = px.bar(
        df_grouped,
        x="firmware",
        y="cantidad",
        color="modelo",
        barmode="group",
        labels={"firmware": "Versión de firmware", "cantidad": "Dispositivos", "modelo": "Modelo"},
    )
    fig.update_layout(height=380, margin=dict(t=10, b=10), xaxis_tickangle=-30)
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No hay datos de firmware disponibles.")

st.divider()

# ── Tabla: archivos disponibles en GenieACS ───────────────────────────────────
st.subheader("Archivos disponibles en GenieACS")

if files:
    file_rows = []
    for f in files:
        size_bytes = f.get("length", 0)
        size_mb = f"{size_bytes / 1_048_576:.2f} MB" if size_bytes else "N/A"
        file_rows.append({
            "Nombre": f.get("filename") or f.get("_id", ""),
            "Tipo": f.get("contentType", ""),
            "Versión": f.get("version", ""),
            "Modelo": f.get("productClass", ""),
            "OUI": f.get("oui", ""),
            "Tamaño": size_mb,
            "MD5": (f.get("md5") or "")[:12] + "..." if f.get("md5") else "",
        })
    df_files = pd.DataFrame(file_rows)
    st.dataframe(df_files, use_container_width=True, hide_index=True)
else:
    st.info("No hay archivos de firmware registrados en GenieACS.")

st.divider()

# ── Tabla: dispositivos con firmware desactualizado ───────────────────────────
st.subheader("Dispositivos con firmware desactualizado")

if devices:
    # Determinar versión "latest" por modelo (la más nueva = mayor string sort)
    model_firmware_map: dict[str, set] = {}
    for d in devices:
        if d["model"] and d["firmware"]:
            model_firmware_map.setdefault(d["model"], set()).add(d["firmware"])

    latest_by_model: dict[str, str] = {}
    for model, versions in model_firmware_map.items():
        latest_by_model[model] = sorted(versions)[-1]

    outdated = []
    for d in devices:
        if not d["model"] or not d["firmware"]:
            continue
        latest = latest_by_model.get(d["model"])
        if latest and d["firmware"] != latest:
            outdated.append({
                "Serial": d["serial"],
                "Modelo": d["model"],
                "Versión actual": d["firmware"],
                "Versión disponible": latest,
                "Último contacto": d["last_seen"],
                "Estado": d["status"].upper(),
            })

    if outdated:
        df_outdated = pd.DataFrame(outdated)
        st.caption(f"{len(outdated)} dispositivo(s) con firmware desactualizado")
        st.dataframe(df_outdated, use_container_width=True, hide_index=True)
    else:
        st.success("✅ Todos los dispositivos tienen la versión de firmware más reciente detectada.")
else:
    st.info("No hay dispositivos disponibles.")

render_nbi_log()
