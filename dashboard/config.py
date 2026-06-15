import os
from dotenv import load_dotenv

load_dotenv()

GENIEACS_NBI_URL = os.getenv("GENIEACS_NBI_URL", "http://localhost:7557")
GENIEACS_USERNAME = os.getenv("GENIEACS_USERNAME", "")
GENIEACS_PASSWORD = os.getenv("GENIEACS_PASSWORD", "")
OFFLINE_THRESHOLD_HOURS = int(os.getenv("OFFLINE_THRESHOLD_HOURS", "4"))
REFRESH_INTERVAL_SECONDS = int(os.getenv("REFRESH_INTERVAL_SECONDS", "60"))
DASHBOARD_TITLE = os.getenv("DASHBOARD_TITLE", "NOC - Monitoreo ONUs")

STATUS_COLORS = {
    "online": "#2ecc71",
    "stale": "#f39c12",
    "offline": "#e74c3c",
    "unknown": "#95a5a6",
}

STATUS_EMOJI = {
    "online": "✅",
    "stale": "⚠️",
    "offline": "❌",
    "unknown": "❓",
}

FAULT_CODE_DESCRIPTIONS = {
    "device_offline": "ONU sin contacto con el ACS",
    "script_error": "Error en script de provisioning Lua",
    "download_fault": "Fallo al descargar firmware",
    "upload_fault": "Fallo al subir configuración",
    "cpe_fault": "Error reportado por la propia ONU",
}
