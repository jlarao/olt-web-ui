"""
Lanzador para desarrollo local en Windows (gunicorn no corre en Windows).

Usa waitress como servidor WSGI y arranca el dashboard Streamlit,
igual que hace el bloque __main__ de app.py en el flujo viejo.

Uso:
    venv\Scripts\python run_local.py

Requiere LOCAL_DEV=true en .env (Streamlit sin SSL ni base path).
En producción (Ubuntu) NO se usa este archivo: ver deploy/DEPLOY.md (gunicorn + systemd).
"""
from waitress import serve

from app import app, start_streamlit

if __name__ == "__main__":
    start_streamlit()
    print("Sirviendo en http://0.0.0.0:8080 (waitress, 16 threads)")
    serve(app, host="0.0.0.0", port=8080, threads=16)
