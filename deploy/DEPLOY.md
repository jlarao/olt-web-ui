# Despliegue en producción (Ubuntu) con gunicorn

## Por qué este cambio

La app corría en producción con el servidor de desarrollo de Flask
(`app.run(..., ssl_context=...)`). Ese servidor hace el handshake TLS dentro
de `accept()`, en un solo hilo y sin timeout: un cliente que abre la conexión
TCP y nunca completa el handshake (escáner de puertos, celular que pierde
señal) **congela el servidor entero de forma silenciosa** — proceso "active",
sin errores en el log, hasta reiniciar. Gunicorn (worker `gthread`) maneja
cada handshake en su propio thread con timeout, así que ese bloqueo ya no
puede ocurrir.

## Pasos en el servidor

Rutas del servidor: proyecto en `/home/pisujo/olt-web-ui-huawei`, venv en
`/home/pisujo/venv`. Los dos archivos `.service` ya traen estas rutas.

### 1. Instalar gunicorn en el venv

```bash
/home/pisujo/venv/bin/pip install gunicorn
```

### 2. Verificar .env de producción

```
LOCAL_DEV=false        # (o eliminar la línea; default es false)
```

### 3. Prueba manual en primer plano (opcional pero recomendado)

```bash
cd /home/pisujo/olt-web-ui-huawei
/home/pisujo/venv/bin/gunicorn \
  --workers 1 --threads 16 --worker-class gthread \
  --timeout 120 --graceful-timeout 30 --keep-alive 5 \
  --certfile fullchain.pem --keyfile privkey.pem \
  --bind 0.0.0.0:8080 app:app
```

Abrir la URL, hacer login, probar una consulta de potencia. Ctrl+C para parar.

IMPORTANTE: `--workers 1` es obligatorio. La app guarda estado en memoria del
proceso (pool de túneles SSH, sesiones proxy, y `secret_key` aleatoria por
proceso). Con más workers los logins fallarían aleatoriamente y los túneles
chocarían entre sí. La concurrencia viene de `--threads` (subir a 32 si se
notan esperas).

### 4. Instalar los servicios systemd

Streamlit ya no lo arranca app.py (eso solo pasaba con `python app.py`);
ahora es un servicio aparte.

```bash
sudo cp deploy/olt-web.service deploy/olt-streamlit.service /etc/systemd/system/
sudo systemctl daemon-reload

# Desactivar el servicio viejo que corría "python3 app.py":
sudo systemctl disable --now NOMBRE_SERVICIO_VIEJO

sudo systemctl enable --now olt-streamlit olt-web
systemctl status olt-web olt-streamlit
```

Si el `.env` define `STREAMLIT_PORT` o `STREAMLIT_BASE_PATH` distintos a
8501 / `/noc-dash`, ajustar los flags en `olt-streamlit.service`.

### 5. Verificación (incluye la prueba del bug original)

```bash
# Responde:
curl -k https://localhost:8080/

# Prueba clave — el cliente colgado que antes congelaba todo:
nc localhost 8080        # abrir y DEJAR colgado, no escribir nada
# ...en otra terminal, con el nc todavía abierto:
curl -k https://localhost:8080/   # debe responder normal
```

Con el servidor viejo, ese `nc` colgado congelaba la app. Con gunicorn debe
seguir respondiendo.

### 6. Logs

- `journalctl -u olt-web -f` — errores del servidor y arranque de gunicorn.
- `app.log` (en el directorio del proyecto) — logging de la aplicación, igual
  que antes.
- `journalctl -u olt-streamlit -f` — dashboard NOC.

## Desarrollo local en Windows

Gunicorn no corre en Windows. Usar el lanzador con waitress:

```powershell
venv\Scripts\pip install waitress
venv\Scripts\python run_local.py
```

Requiere `LOCAL_DEV=true` en `.env`. Sirve en http://localhost:8080 sin SSL
y arranca Streamlit automáticamente.
