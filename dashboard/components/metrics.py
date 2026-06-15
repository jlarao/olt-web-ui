import streamlit as st
from datetime import datetime, timezone


def render_kpi_row(devices: list[dict]):
    total = len(devices)
    online = sum(1 for d in devices if d["status"] == "online")
    offline = sum(1 for d in devices if d["status"] in ("offline", "unknown"))
    stale = sum(1 for d in devices if d["status"] == "stale")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total ONUs", total)
    col2.metric("Online", online, help="Contacto en las últimas 4 horas")
    col3.metric("Offline", offline, help="Sin contacto > 24 horas o desconocido")
    col4.metric("Stale (4-24h)", stale, help="Sin contacto entre 4 y 24 horas")


def render_faults_kpi(faults: list[dict]):
    total = len(faults)
    provision = sum(1 for f in faults if f.get("channel") == "provision")
    offline_f = sum(1 for f in faults if f.get("code") == "device_offline")

    col1, col2, col3 = st.columns(3)
    col1.metric("Total faults activos", total)
    col2.metric("Faults provision", provision)
    col3.metric("device_offline", offline_f)


def connection_status_badge(status: str) -> str:
    badges = {
        "online": "🟢 Online",
        "stale": "🟡 Stale",
        "offline": "🔴 Offline",
        "unknown": "⚫ Unknown",
    }
    return badges.get(status, status)


def last_update_caption():
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    st.caption(f"Última actualización: {now}")
