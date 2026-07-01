from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3,time
import os
import sys
import logging
import subprocess
import atexit
from logging.handlers import RotatingFileHandler
import json
import uuid
from functools import wraps
from dotenv import load_dotenv
from datetime import datetime, timedelta
import re
import ssl as _ssl
import unicodedata
import threading as _threading
import requests as _req
import urllib3
from urllib.parse import urljoin, urlparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class _LenientSSLAdapter(_req.adapters.HTTPAdapter):
    """
    HTTPAdapter que acepta dispositivos UBNT con firmware antiguo:
    TLS 1.0/1.1, cifradores débiles, certificados autofirmados.
    """

    def __init__(self, *args, **kwargs):
        import warnings
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = _ssl.CERT_NONE
        ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', DeprecationWarning)
                ctx.minimum_version = _ssl.TLSVersion.TLSv1
        except AttributeError:
            pass
        try:
            ctx.options |= getattr(_ssl, 'OP_LEGACY_SERVER_CONNECT', 0)
        except Exception:
            pass
        try:
            ctx.options |= getattr(_ssl, 'OP_IGNORE_UNEXPECTED_EOF', 0)
        except Exception:
            pass
        try:
            ctx.maximum_version = _ssl.TLSVersion.TLSv1_2
        except AttributeError:
            pass
        self._ctx = ctx
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, num_pools, maxsize, block=False, **kw):
        kw['ssl_context'] = self._ctx
        super().init_poolmanager(num_pools, maxsize, block=block, **kw)

    def send(self, request, **kwargs):
        # Forzar siempre verify=False; urllib3 puede ignorar el ctx.verify_mode
        kwargs['verify'] = False
        return super().send(request, **kwargs)


# Pool de sesiones HTTP persistentes por túnel (ip, port) → Session.
# Reutiliza la conexión HTTPS ya negociada; evita pagar el handshake SSL
# (~500-800 ms) en cada petición de status.cgi/getcfg.cgi.
_proxy_sessions: dict = {}
_proxy_sessions_lock = _threading.Lock()

def _new_proxy_session(pool_maxsize: int = 1) -> _req.Session:
    s = _req.Session()
    adapter = _LenientSSLAdapter(
        pool_connections=1, pool_maxsize=pool_maxsize, max_retries=0,
        pool_block=True,
    )
    s.mount('https://', adapter)
    s.mount('http://',  adapter)
    return s


def _proxy_session(ip: str, port: int) -> _req.Session:
    key = (ip, port)
    with _proxy_sessions_lock:
        if key not in _proxy_sessions:
            _proxy_sessions[key] = _new_proxy_session(pool_maxsize=1)
        return _proxy_sessions[key]


def _drop_proxy_session(ip: str, port: int) -> None:
    with _proxy_sessions_lock:
        sess = _proxy_sessions.pop((ip, port), None)
    if sess:
        try:
            sess.close()
        except Exception:
            pass

load_dotenv()

from scanner.tunnel_manager import tunnel_manager

# Mapa hub_ip → credenciales SSH. Clave es el IP del router MikroTik hub.
# Cuando llega una petición de WinBox con hub_ip, se busca aquí primero.
_HUB_CREDS: dict[str, dict] = {}
for _pfx in ('M1', 'M2', 'M3', 'M4'):
    _h = os.getenv(f'{_pfx}_HOST', '')
    if _h:
        _HUB_CREDS[_h] = {
            'port': int(os.getenv(f'{_pfx}_PORT', 12222)),
            'user': os.getenv(f'{_pfx}_USER', 'admin'),
            'pass': os.getenv(f'{_pfx}_PASS', ''),
        }

def _session_hub_creds() -> dict:
    """Lee las credenciales SSH del hub MikroTik guardadas en la sesión.
    Fallback a M1 del .env si no hay sesión activa (acceso directo sin scan previo)."""
    return {
        'host': session.get('hub_host') or os.getenv('M1_HOST', ''),
        'port': session.get('hub_port') or int(os.getenv('M1_PORT', 12222)),
        'user': session.get('hub_user') or os.getenv('M1_USER', 'admin'),
        'pass': session.get('hub_pass') or os.getenv('M1_PASS', ''),
    }

def to_genieacs_tag(name):
    if not name:
        return ""
    normalized = unicodedata.normalize("NFKD", str(name))
    ascii_str = normalized.encode("ascii", "ignore").decode("ascii")
    words = [w for w in re.split(r'[^a-zA-Z0-9]+', ascii_str) if w]
    if not words:
        return ""
    return words[0].lower() + "".join(w.capitalize() for w in words[1:])

# --- Configuracion de logging ---
LOG_FILE = os.getenv("LOG_FILE", "app.log")
LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG")

logger = logging.getLogger()
logger.setLevel(getattr(logging, LOG_LEVEL, logging.DEBUG))

# Formato del log
formatter = logging.Formatter(
    "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Handler archivo con rotacion (5 MB max, 5 archivos de respaldo)
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5, encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Handler consola (para cuando se ejecuta manualmente)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Redirigir print() y errores al log
class LogStream:
    def __init__(self, log_func):
        self.log_func = log_func
        self.buffer = ""
    def write(self, msg):
        if msg and msg.strip():
            self.log_func(msg.rstrip())
    def flush(self):
        pass

# Configurar loggers para stdout/stderr con los mismos handlers
for name in ("stdout", "stderr"):
    sub_logger = logging.getLogger(name)
    sub_logger.setLevel(logging.DEBUG)
    sub_logger.addHandler(file_handler)
    sub_logger.addHandler(console_handler)
    sub_logger.propagate = False

sys.stdout = LogStream(logging.getLogger("stdout").info)
sys.stderr = LogStream(logging.getLogger("stderr").error)

# Silenciar warnings internos de Werkzeug/Flask
logging.getLogger("werkzeug").setLevel(logging.ERROR)

from olt_telnet import alta_ont, consultar_potencia, descargar_config, guardar_sqlite, conectar, obtener_ultimo_config, parse_ont_info, limpiar_salida_olt, extraer_service_ports, delete_sp, delete_ont_cont, guardar_tabla, get_potencia, alta_ont_versiontwo, delete_ont_sn, alta_ont_version_three, send_cmd_telnet_add_onu_two, alta_ont_version_three_ma, conectar_ma, delete_ont_sn_ma

LINE_PROFILE = os.getenv("LINE_PROFILE_ID", "500")
SRV_PROFILE = os.getenv("SRV_PROFILE_ID", "500")
VLAN = os.getenv("VLAN", "100")
PASSWORD_PPPOE = os.getenv("PASSWORD_PPPOE", "1234")
SERVICE_PPPOE = os.getenv("SERVICE_PPP", "pppoe")

HOST_MKT = os.getenv("HOST_MKT", "LOCALHOST")
USERNAME_MKT = os.getenv("USERNAME_MKT", "admin")
PASSWORD_MKT =  os.getenv("PASSWORD_MKT", "admin")
SERVER_ACS = os.getenv("SERVER_ACS", "192.168.1.7:7557")
PWD_INSERT_OLT = os.getenv("PWD_INSERT_OLT", "")
STREAMLIT_PORT = int(os.getenv("STREAMLIT_PORT", "8501"))
STREAMLIT_PUBLIC_URL = os.getenv("STREAMLIT_PUBLIC_URL", "")  # si se define, sobreescribe la URL del iframe
PROXY_UPSTREAM_TIMEOUT = float(os.getenv("PROXY_UPSTREAM_TIMEOUT", "90"))
PROXY_AJAX_TIMEOUT_MS = int(os.getenv("PROXY_AJAX_TIMEOUT_MS", "120000"))

# ── Streamlit subprocess ──────────────────────────────────────────────────────
_streamlit_proc = None

def start_streamlit():
    global _streamlit_proc
    dashboard_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard", "app.py")
    if not os.path.exists(dashboard_path):
        logging.warning("Dashboard Streamlit no encontrado en %s", dashboard_path)
        return

    local_dev = os.getenv("LOCAL_DEV", "false").lower() == "true"
    base_dir  = os.path.dirname(os.path.abspath(__file__))
    ssl_cert  = os.path.join(base_dir, "fullchain.pem")
    ssl_key   = os.path.join(base_dir, "privkey.pem")
    use_ssl   = (not local_dev) and os.path.exists(ssl_cert) and os.path.exists(ssl_key)
    base_path = "" if local_dev else os.getenv("STREAMLIT_BASE_PATH", "/noc-dash")

    cmd = [
        sys.executable, "-m", "streamlit", "run", dashboard_path,
        "--server.port",                 str(STREAMLIT_PORT),
        "--server.headless",             "true",
        "--server.enableCORS",           "false",
        "--server.enableXsrfProtection", "false",
        "--browser.gatherUsageStats",    "false",
    ]
    if use_ssl:
        cmd += ["--server.sslCertFile", ssl_cert, "--server.sslKeyFile", ssl_key]
    if base_path:
        cmd += ["--server.baseUrlPath", base_path]

    _streamlit_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=os.path.dirname(os.path.abspath(__file__)),
    )
    logging.info("Streamlit NOC iniciado en puerto %s (PID %s)", STREAMLIT_PORT, _streamlit_proc.pid)

def _stop_streamlit():
    if _streamlit_proc and _streamlit_proc.poll() is None:
        _streamlit_proc.terminate()
        logging.info("Streamlit NOC detenido")

atexit.register(_stop_streamlit)

# Cargar variables del archivo .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

from flask_cors import CORS
CORS(app, supports_credentials=True)

# Configurar login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

DATABASE = "users.db"


def _init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)
    for col, definition in [('full_name', "TEXT NOT NULL DEFAULT ''"), ('role', "TEXT NOT NULL DEFAULT 'user'")]:
        try:
            c.execute(f"ALTER TABLE users ADD COLUMN {col} {definition}")
        except Exception:
            pass
    # El primer usuario registrado es admin
    c.execute("UPDATE users SET role='admin' WHERE id=1 AND role='user'")
    c.execute("""
        CREATE TABLE IF NOT EXISTS api_tokens (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            token      TEXT NOT NULL UNIQUE,
            name       TEXT NOT NULL DEFAULT 'Mobile',
            created_at TEXT NOT NULL,
            last_used  TEXT,
            expires_at TEXT,
            revoked    INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_api_tokens_token ON api_tokens(token)")
    conn.commit()
    conn.close()


_init_db()


# ── Autenticación con token Bearer ───────────────────────────────────────────

def _get_valid_token(token_val: str):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, user_id, expires_at FROM api_tokens WHERE token=? AND revoked=0", (token_val,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    if row['expires_at'] and datetime.fromisoformat(row['expires_at']) < datetime.utcnow():
        return None
    return dict(row)


def _touch_token(token_id: int):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("UPDATE api_tokens SET last_used=? WHERE id=?", (datetime.utcnow().isoformat(), token_id))
    conn.commit()
    conn.close()


def api_required(f):
    """Decorator que acepta sesión web (cookie) O Bearer token para la app mobile."""
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask_login import current_user
        if current_user.is_authenticated:
            return f(*args, **kwargs)
        auth = request.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            row = _get_valid_token(auth[7:].strip())
            if row:
                _touch_token(row['id'])
                return f(*args, **kwargs)
        return jsonify({'error': 'No autorizado'}), 401
    return decorated


class User(UserMixin):
    def __init__(self, id_, username, password_hash, full_name='', role='user'):
        self.id = id_
        self.username = username
        self.password_hash = password_hash
        self.full_name = full_name
        self.role = role

    @staticmethod
    def get(username):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, full_name, role FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return User(*row)
        return None


@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, full_name, role FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return User(*row)
    return None

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.get(username)
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect("/dashboard")
        return render_template("login.html", error="Credenciales incorrectas")
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS configuration (
        id INTEGER PRIMARY KEY AUTOINCREMENT ,
        fecha TEXT,
        datos TEXT,
        tipo TEXT
        )
    """)
    c.execute("SELECT fecha,datos FROM configuration order by id desc LIMIT 1 ")
    row = c.fetchone()

    c.execute("""
        CREATE TABLE IF NOT EXISTS onus(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        card_id INTEGER,
        slot_id INTEGER,
        port_id INTEGER, 
        ont_id INTEGER,
        state TEXT,
        uptime TEXT,
        downtime TEXT,
        cause TEXT,
        SN TEXT,
        type TEXT,
        distance TEXT,
        rx_tx TEXT,
        description TEXT,
        sp INTEGER, 
        cmd TEXT,
        cadena TEXT,
        config TEXT,
        deleted BOOLEAN
        )
    """)

    c.execute("select count(*) from onus where deleted = 0")
    rowc = c.fetchone()
    conn.close()
    if row:
        fecha_actualizacion = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
        segundos_transcurridos = int(time.time() - fecha_actualizacion.timestamp())
        contenido = row[1]
    else:
        fecha_actualizacion = None
        segundos_transcurridos = None
        contenido = None
    
    total = 0;
    if rowc:
        total = rowc[0]
    return render_template("dashboard.html", fecha_actualizacion=fecha_actualizacion, segundos_transcurridos=segundos_transcurridos, contenido=contenido, total=total)

@app.route("/alta-ont", methods=["GET", "POST"])
# @login_required
def alta_ont_web():
    if request.method == "POST":
        frame = request.form["frame"]
        slot = request.form["slot"]
        port = request.form["port"]
        ontid = request.form["ontid"]
        sn = request.form["sn"]
        desc = request.form["desc"]
        sp = request.form["sp"]
        profile = request.form["profile"]
        pppoe = request.form["pppoe"]

        # vlan = request.form["vlan"]
        # resultado = alta_ont(frame, slot, port, ontid, sn, vlan)
        resultado = alta_ont(frame, slot, port, ontid, sn, desc, sp)
        # interface_cmd = f"interface gpon {frame}/{slot}\n"
        # add_ont_cmd = (
        #         f"ont add {port} {ontid} sn-auth \"{sn}\" omci "
        #         f"ont-lineprofile-id {LINE_PROFILE} ont-srvprofile-id {SRV_PROFILE} desc \"{desc}\"\n"
        #     )
        # service_cmd = (
        #         f"service-port {sp} vlan { VLAN } gpon {frame}/{slot}/{port} ont {ontid} "
        #         f"gemport 37 multi-service user-vlan { VLAN } tag-transform translate\n"
        #     )
        # resultado = interface_cmd + add_ont_cmd + service_cmd
        profile = '25M'
        call_mkt(pppoe,profile,desc)#name ps0001, password 1234, service pppoe, profile 25M, comment nombre cliente
        return render_template("resultado_alta.html", resultado=resultado)

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT sp FROM onus order by sp desc LIMIT 1")
    sp = c.fetchone()
    conn.close()
    print(sp)
    if sp:
        sp = sp[0]+1
    else:
        sp = 0

    return render_template("alta_ont.html", sp=sp)

@app.route("/potencia", methods=["GET", "POST"])
@login_required
def potencia():
    if request.method == "POST":
        frame = request.form["frame"]
        slot = request.form["slot"]
        port = request.form["port"]
        # ontid = 0 #request.form["ontid"]
        # raw_text = obtener_ultimo_config()
        # texto_limpio = limpiar_salida_olt(raw_text)
        # datos_por_puerto, errores = parse_ont_info(texto_limpio)
        # Mostrar errores si los hubo
        # if errores:
        #     print("\nLíneas descartadas:")
        #     for err in errores:
        #         print(err)
        onus =get_potencia()
        # Decodificar el JSON
        lista_final = []  # Inicializa la lista

        for ont in onus:
            ont_dict = dict(ont)
            id_valor = ont_dict['SN']
            # ont_dict['acciones'] = [f"borrar_ont_sn = {id_valor}"]  # o el nombre de tu campo
            ont_dict['acciones'] = [{'borrar_ont_sn': id_valor}, {'editar_ont_id': id_valor}]
            ont_dict['cmd'] =  ont_dict['cmd']==None or json.loads(ont_dict['cmd'])
            lista_final.append(ont_dict)
        print(ont_dict)
        return render_template("resultado_get.html", datos_por_puerto=lista_final)
    return render_template("potencia.html")

@app.route("/noc")
@login_required
def noc_monitor():
    if STREAMLIT_PUBLIC_URL:
        streamlit_url = STREAMLIT_PUBLIC_URL.rstrip("/")
    else:
        local_dev = os.getenv("LOCAL_DEV", "false").lower() == "true"
        protocol = "http" if local_dev else "https"
        host = request.host.split(":")[0]
        streamlit_url = f"{protocol}://{host}:{STREAMLIT_PORT}"
    return render_template("noc_monitor.html", streamlit_url=streamlit_url, port=STREAMLIT_PORT)


@app.route("/noc/status")
@login_required
def noc_status():
    """Verifica si Streamlit está listo. Lo usa el frontend via polling."""
    import socket
    try:
        s = socket.create_connection(("127.0.0.1", STREAMLIT_PORT), timeout=1)
        s.close()
        return jsonify({"ready": True})
    except OSError:
        return jsonify({"ready": False})


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/guardar_datos", methods = ["POST"])
@login_required
def guardar_datos():
    conn, estado, resultado = conectar()
    print(estado)
    if estado == "error":
        flash("Error " + str(conn))
        return redirect(url_for("dashboard"))

    conn.write(b"enable\n")
    conn.write(b"config\n")
    datos = descargar_config(conn)  # cierra conn internamente en su bloque finally
    time.sleep(10)
    if datos:
        guardar_sqlite(datos, "current")
        flash("Datos guardados correctamente")
    else:
        flash("No se pudieron guardar los datos")

    # descargar_config cerró la conexión; abrir una nueva para consultar_potencia
    conn2, estado2, _ = conectar()
    if estado2 == "error":
        flash("Error al reconectar para datos ONT")
    else:
        conn2.write(b"enable\n")
        conn2.write(b"config\n")
        datos2 = consultar_potencia(conn2, 0, 1, 0, 0)  # cierra conn2 internamente
        if datos2:
            guardar_sqlite(datos2, "ont")
            flash("Datos ONT guardados correctamente")
        else:
            flash("No se pudieron guardar los datos ONT")

    return redirect(url_for("dashboard"))
@app.route("/service_port", methods = ["GET"])
# @login_required
def service_port():

    conn = sqlite3.connect(DATABASE)
    
    c = conn.cursor()
    c.execute("SELECT datos, id FROM configuration where tipo = 'current' ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    conn.close()

    texto = row[0] if row else ""
    service_ports = extraer_service_ports(texto)
    lines = service_ports
    # print(service_ports[1])


    return render_template("service_port.html", service_ports=service_ports)

@app.route('/borrar_sp/<int:sp_num>', methods = ['GET'])
@login_required
def borrar_sp(sp_num):
    resultado = delete_sp(sp_num)
    return render_template('borrar_sp.html', resultado=resultado)

@app.route('/borrar_ont/<int:frame>/<int:slot>/<int:port>/<int:ontid>/')
@login_required
def borrar_ont(frame, slot, port, ontid):
    # return ejecutar_borrado(frame, slot, port, ontid, sp=None)
    resultado, texto = delete_ont_cont(frame, slot, port, ontid)
    
    return render_template('resultado_alta.html',resultado=texto)

@app.route('/borrar_ont/<int:frame>/<int:slot>/<int:port>/<int:ontid>/borrar_sp/<int:sp>')
@login_required
def borrar_ont_y_sp(frame, slot, port, ontid, sp):
    # return ejecutar_borrado(frame, slot, port, ontid, sp)
    resultado="borrar_ont_y_sp"
    return render_template('resultado_alta.html',resultado=resultado)

@app.route("/update_table", methods = ['POST'])
# @login_required
def update_table():
    guardar_tabla()        
    return redirect(url_for("dashboard"))


@app.route("/verificar_sn/<sn>")
def verificar_sn(sn):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT 1 FROM onus WHERE SN = ?  and deleted = 0", (sn,))
    existe = c.fetchone() is not None
    conn.close()
    return jsonify({"existe": existe})

@app.route("/verificar_ontid/<ontid>")
def verificar_ontid(ontid):

    print(ontid)
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("""
        SELECT ont_id FROM onus WHERE port_id = ? and deleted = 0 GROUP by ont_id  order by ont_id asc
        """, (ontid))
    resultados = c.fetchall()
    conn.close()

    print(resultados)
    ont_ids = [fila[0] for fila in resultados]  # Extrae solo los números

    # print(ont_ids)
    # Buscar el primer número faltante
    for esperado in range(len(ont_ids)):
        # print(esperado)
        if ont_ids[esperado] != esperado:
           return jsonify({"resultado": True , "esperado": esperado})  # Devuelve el primer número faltante

    # Si no falta ninguno, el siguiente
    # return len(ont_ids)
    print(ont_ids)
    # print(len(ont_ids))
    return jsonify({ "resultado": True, "esperado": len(ont_ids)})

@app.route("/verificar_sp/<sp>")
def verificar_sp(sp):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT 1 FROM onus WHERE sp = ? and deleted = 0 ", (sp,))
    existe = c.fetchone() is not None
    conn.close()
    return jsonify({"existe": existe})

@app.route("/verificar_pwd", methods=["POST"])
def verificar_pwd():
    pwd = request.json.get("pwd", "")
    if not PWD_INSERT_OLT:
        return jsonify({"ok": False, "msg": "Password no configurado en el servidor"})
    if pwd == PWD_INSERT_OLT:
        return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "Password incorrecto"})

@app.route("/borrar_ont_sn/<sn>")
# @login_required
def borrar_ont_sn(sn):
    delete_ont_sn(sn)
    return redirect(url_for("alta_ont_web_v4", sn=sn))

@app.route("/borrar_ont_sn_ma/<sn>")
# @login_required
def borrar_ont_sn_ma(sn):
    delete_ont_sn_ma(sn)
    return redirect(url_for("alta_ont_web_v4", sn=sn))

@app.route("/alta-ont-v2", methods=["GET"])
# @login_required
def alta_ont_web_v2():
    if request.method == "POST":
        frame = request.form["frame"]
        slot = request.form["slot"]
        port = request.form["port"]
        ontid = request.form["ontid"]
        sn = request.form["sn"]
        desc = request.form["desc"]
        sp = request.form["sp"]

        resultado = alta_ont_versiontwo(frame, slot, port, ontid, sn, desc, sp)

        return render_template("resultado_alta_v2.html", resultado=resultado)

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT sp FROM onus order by sp desc LIMIT 1")
    sp = c.fetchone()
    conn.close()
    print(sp)
    if sp:
        sp = sp[0]+1
    else:
        sp = 0

    return render_template("alta_ont_v2.html", sp=sp)

@app.route("/alta-ont-v3", methods=["GET", "POST"])
# @login_required
def alta_ont_web_v3():
    if request.method == "POST":
        frame = request.form["frame"]
        slot = request.form["slot"]
        port = request.form["port"]
        ontid = request.form["ontid"]
        sn = request.form["sn"]
        desc = request.form["desc"]
        sp = request.form["sp"]
        pppoe = request.form["pppoe"]
        profile = request.form["profile"]

        # return jsonify({
        #     "frame": frame,
        #     "slot": slot,
        #     "port": port,
        #     "ontid": ontid,
        #     "sn": sn,
        #     "desc": desc,
        #     "sp": sp,
        #     "pppoe": pppoe,
        #     "profile": profile
        # })
        tn, resultado = alta_ont_version_three(frame, slot, port, ontid, sn, desc, sp)

        if tn is None or "Error" in str(resultado) or "Failure" in str(resultado) or "failure" in str(resultado):
            if tn is not None:
                try:
                    tn.close()
                except Exception:
                    pass
            return render_template("resultado_alta_v2.html", resultado=resultado)

        print("Salida Guardando...")
        time.sleep(10)
        cmd = f"save\r\n"
        r, out = send_cmd_telnet_add_onu_two(tn, cmd)
        time.sleep(0.3)
        print("Salida final:\n", out)
        print(repr(out))
        tn.close()
        #alta pppoe
        call_mkt(pppoe,profile,desc)#name ps0001, password 1234, service pppoe, profile 25M, comment nombre cliente
        return render_template("resultado_alta_v2.html", resultado=resultado)

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT sp FROM onus order by sp desc LIMIT 1")
    sp = c.fetchone()
    conn.close()
    #print(sp)
    if sp:
        sp = sp[0]+1
    else:
        sp = 0

    return render_template("alta_ont_v2.html", sp=sp)

@app.route("/alta-ont-v4/<sn>", methods=["GET", "POST"])
# @login_required
def alta_ont_web_v4(sn):
    if request.method == "POST":
        frame = request.form["frame"]
        slot = request.form["slot"]
        port = request.form["port"]
        ontid = request.form["ontid"]
        sn = request.form["sn"]
        desc = request.form["desc"]
        sp = request.form["sp"]

        tn, resultado = alta_ont_version_three(frame, slot, port, ontid, sn, desc, sp)
        if tn is not None:
            try:
                tn.close()
            except Exception:
                pass

        return render_template("resultado_alta_v2.html", resultado=resultado)

    conn = sqlite3.connect(DATABASE)
    # conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("select * from onus  where SN = ? order by ont_id desc limit 1", (sn,))
    rowc = c.fetchone()
    conn.close()

    #print(rowc)
    return render_template("alta_ont_v4.html", rowc=rowc)

import requests

def provision_device_dynamic(
    serial_target,
    pppoe_user,
    pppoe_pass,
    vlan,
    tag="AutoProvisioned",
    provision_name="mynewprovision",
    # host="http://localhost:7557"
    host=SERVER_ACS,
    pppoe_user_temp="user_temp",
    pppoe_pass_temp=None,
    ):
    pppoe_pass_temp = pppoe_pass
    url = f"{host}/provisions/{provision_name}"
    headers = {
        "Content-Type": "text/plain"
    }

    # Aquí se construye el script usando f-strings
    script = f"""
            log('pppoe');
            let serialNumber = declare('DeviceID.SerialNumber', {{ value: 1 }}).value[0]
            log(serialNumber)

            if(serialNumber == '{serial_target}'){{
            let wanConnDevInst = null;
            try {{
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.*", null, {{path: 2}});
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.*", null, {{path: 1}});
                log("✅ Instancia WANConnectionDevice creada: " + JSON.stringify(wanConnDevInst));

                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.Username", null, {{value: "{pppoe_user}"}});
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.Password", null, {{value: "{pppoe_pass}"}});
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.ConnectionType", null, {{value: "IP_Routed"}});
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.ConnectionTrigger", null, {{value: "AlwaysOn"}});
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.TransportType", null, {{value: "PPPoE"}});
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.X_HW_SERVICELIST", null, {{value: "INTERNET"}});
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.X_HW_VLAN", null, {{value: {vlan}}});

                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.Enable", null, {{value: true}});
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.NATEnabled", null, {{value: true}});
                declare("Tags.{tag}", null, {{value: true}});

            }} catch (err) {{
                throw new Error("❌ Error al crear instancia WANConnectionDevice: " + err.message);
            }}
            }} else {{
            
            }}
            """

    try:
        response = requests.put(url, data=script.encode("utf-8"), headers=headers)
        print(f"✅ Código de estado: {response.status_code}")
        print("📦 Respuesta:", response.text)
        return response
    except requests.RequestException as e:
        print("❌ Error durante la solicitud:", e)
        return None


def provision_device_dynamic_ma(
    serial_target,
    pppoe_user,
    pppoe_pass,
    vlan=102,
    tag="AutoProvisioned",
    provision_name="crear_pppoe_vlan102",
    host=SERVER_ACS,
    pppoe_user_temp="user_temp",
    pppoe_pass_temp=None,
    ):
    pppoe_pass_temp = pppoe_pass
    url = f"{host}/provisions/{provision_name}"
    headers = {
        "Content-Type": "text/plain"
    }

    script = f"""
            log('pppoe ma');
            let serialNumber = declare('DeviceID.SerialNumber', {{ value: 1 }}).value[0]
            log(serialNumber)

            if(serialNumber == '{serial_target}'){{
            let wanConnDevInst = null;
            try {{
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.*", null, {{path: 2}});
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.*", null, {{path: 1}});
                log("✅ Instancia WANConnectionDevice creada: " + JSON.stringify(wanConnDevInst));

                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.Username", null, {{value: "{pppoe_user}"}});
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.Password", null, {{value: "{pppoe_pass}"}});
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.ConnectionType", null, {{value: "IP_Routed"}});
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.ConnectionTrigger", null, {{value: "AlwaysOn"}});
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.TransportType", null, {{value: "PPPoE"}});
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.X_HW_SERVICELIST", null, {{value: "INTERNET"}});
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.X_HW_VLAN", null, {{value: {vlan}}});

                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.Enable", null, {{value: true}});
                declare("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.NATEnabled", null, {{value: true}});
                declare("Tags.{tag}", null, {{value: true}});

            }} catch (err) {{
                throw new Error("❌ Error al crear instancia WANConnectionDevice: " + err.message);
            }}
            }} else {{
            
            }}
            """

    try:
        response = requests.put(url, data=script.encode("utf-8"), headers=headers)
        print(f"✅ Código de estado MA: {response.status_code}")
        print("📦 Respuesta:", response.text)
        return response
    except requests.RequestException as e:
        print("❌ Error durante la solicitud MA:", e)
        return None


# import requests
@app.route("/provisions")
def provision_device():
    data = 'log("Provision started at " + now);'
    try:
        response = provision_device_dynamic(
            serial_target="48575443AEBC9FAF",
            pppoe_user="ps0122",
            pppoe_pass="P1n0@Su4r3z",
            vlan=100,
            tag="LidiaSaucedoLara",
            provision_name="crear_pppoe_vlan100",
            # host="http://192.168.1.7:7557"
            host=SERVER_ACS
        )
        return render_template("resultado_alta_v2.html", resultado=response.status_code)
        
    except requests.RequestException as e:
        print("Error during request:", e)
        return None

def to_camel_case(text):
    words = text.strip().split()
    if not words:
        return ''
    return words[0].lower() + ''.join(word.capitalize() for word in words[1:])

#@app.route("/mkt", methods=["GET"])
def call_mkt(name='ps0111',profile='25M',comment='Hector Ontiveros'):
    from routeros_api import RouterOsApiPool

    # # Datos de conexión
    # api_pool = RouterOsApiPool(
    #     host='200.188.72.42',
    #     username='admin',
    #     password='PinoSuar',
    #     plaintext_login=True  # importante para RouterOS v6
    # )

    # api = api_pool.get_api()

    # # Ejemplo: obtener interfaces
    # interfaces = api.get_resource('/interface')
    # for interface in interfaces.get():
    #     print(interface)

    # # Cierra la conexión
    # api_pool.disconnect()

    # return render_template("mkt.html")
    from routeros_api import RouterOsApiPool
    from routeros_api.exceptions import RouterOsApiConnectionError

    # Configuración
    
    PLAINTEXT_LOGIN = True  # importante para RouterOS v6

    # Simulación de entrada (puedes reemplazar con valores reales)
    data = {
        'name': name,#'usuario1',
        'password': PASSWORD_PPPOE,#'pass1234',
        'service': SERVICE_PPPOE,#'pppoe',
        'profile': profile,#'25M',
        'comment': comment,#'Cliente nuevo'
    }

    # Adaptación del script
    try:
        api_pool = RouterOsApiPool(
            host=HOST_MKT,
            username=USERNAME_MKT,
            password=PASSWORD_MKT,
            plaintext_login=PLAINTEXT_LOGIN
        )
        print("Conectando...")
        print(HOST_MKT, USERNAME_MKT, PASSWORD_MKT)
        api = api_pool.get_api()

        # Accedemos al recurso /ppp/secret
        ppp_secret = api.get_resource('/ppp/secret')

        # Construimos los parámetros
        params = {
            "name": data['name'],
            "password": data['password'],
            "service": data['service'],
            "profile": data['profile'],
            "comment": data['comment']
        }

        # Intentamos agregar el usuario
        try:
            result = ppp_secret.add(**params)
            response = {
                'message': result,
                'data': True
            }
            

        except Exception as e:
            # Captura errores del API (por ejemplo, usuario duplicado)
            response = {
                'message': str(e),
                'data': False,
                'datos': data
            }

        api_pool.disconnect()
        print(json.dumps(response, indent=4))
        return jsonify({"response": response})
    except RouterOsApiConnectionError as conn_err:
        response = {
            'message': f"Error de conexión: {conn_err}",
            'data': False
        }

        print(json.dumps(response, indent=4))
        return jsonify({"response": response})

    # Mostrar respuesta
    # import json
    # print(json.dumps(response, indent=4))

@app.route("/sheet", methods=["GET"])
def sheet():
    import gspread
    from google.oauth2.service_account import Credentials
    
    # Cargar credenciales del archivo JSON
    # SCOPE = ["https://www.googleapis.com/auth/spreadsheets"]
    # creds = Credentials.from_service_account_file("react-elearning-e12a6-c869ba1c268d.json", scopes=SCOPE)

    # Autenticarse y abrir hoja
    # gc = gspread.authorize(creds)
    # spreadsheet = gc.open("Ingreso2024")
    # worksheet = spreadsheet.worksheet("cuentas fibra")  # nombre de la pestaña

    # Leer datos
    # filas = worksheet.get_all_records()
    # print("Datos actuales:")
    # print(filas)

    # Escribir nuevo usuario
    # nuevo_usuario = ["nuevo_user", "1234", "pppoe", "25M", "comentario nuevo"]
    # worksheet.append_row(nuevo_usuario)

    # print("¡Fila agregada con éxito!")

    # import psycopg2
    import gspread
    from oauth2client.service_account import ServiceAccountCredentials

    # Google Sheets setup
    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    creds = ServiceAccountCredentials.from_json_keyfile_name('react-elearning-e12a6-c869ba1c268d.json', scope)
    client = gspread.authorize(creds)

    # Open the Google Sheet
    # sheet = client.open("Ingreso2024").sheet1
    sheet = client.open("Ingreso2024").worksheet("cuentas fibra")

    # Get all records from the sheet
    # print(sheet)
    records = sheet.get_all_records()
    recfill = []
    for record in records:
        # print(record)
        if record['sn'] == '':
            continue
        recfill.append(record)

    # print(records)
    return render_template("sheet.html", records=recfill)
    # dump(sheet)
    # return jsonify({"response": records})

@app.route("/sheet_ma", methods=["GET"])
def sheet_ma():
    import gspread
    from oauth2client.service_account import ServiceAccountCredentials

    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    creds = ServiceAccountCredentials.from_json_keyfile_name('react-elearning-e12a6-c869ba1c268d.json', scope)
    client = gspread.authorize(creds)

    sheet = client.open("Ingreso2024").worksheet("cuentas fibra ma")

    records = sheet.get_all_records()
    recfill = []
    for record in records:
        if record['sn'] == '':
            continue
        recfill.append(record)

    return render_template("sheet_ma.html", records=recfill)

@app.route("/buscar-sn/<sn>", methods=["GET"])
def buscar_sn(sn):
    import gspread
    from oauth2client.service_account import ServiceAccountCredentials

    logger.info(f"[buscar-sn] Petición recibida | SN: {sn} | IP: {request.remote_addr}")

    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    creds = ServiceAccountCredentials.from_json_keyfile_name('react-elearning-e12a6-c869ba1c268d.json', scope)
    client = gspread.authorize(creds)

    spreadsheet = client.open("Ingreso2024")
    sn_upper = sn.strip().upper()

    for ws_name in ["cuentas fibra", "cuentas fibra ma"]:
        records = spreadsheet.worksheet(ws_name).get_all_records()
        for record in records:
            if str(record.get("sn", "")).strip().upper() == sn_upper:
                result = {
                    "sn": record.get("sn"),
                    "user": record.get("user"),
                    "password": record.get("password", "P1n0@Su4r3z"),
                    "vlan": record.get("vlan"),
                    "tag": to_genieacs_tag(record.get("name", ""))
                }
                logger.info(f"[buscar-sn] Encontrado en '{ws_name}' | SN: {result['sn']} | user: {result['user']} | vlan: {result['vlan']}")
                return jsonify(result), 200

    logger.warning(f"[buscar-sn] No encontrado | SN: {sn_upper}")
    return jsonify({"error": "ONT no encontrada"}), 404

@app.route("/alta-ont-gs", methods=["POST"])
# @login_required
def alta_ont_web_gs():
    if request.method == "POST":
        frame =  0
        slot =  1
        port = request.form["port"]
        ontid = request.form["ont"]
        sn = request.form["sn"]
        desc = request.form["name"]
        sp = request.form["service_port"]
        pppoe = request.form["user"]
        # profile = "25M"
        port =port.split()[1]

        return render_template("alta_ont_gs.html", frame =frame , slot =slot, port =port, ontid =ontid, sn =sn, desc =desc, sp =sp, pppoe =pppoe)

@app.route("/alta-ont-gs-ma", methods=["POST"])
# @login_required
def alta_ont_web_gs_ma():
    if request.method == "POST":
        frame = 0
        slot = 1
        port = request.form["port"]
        ontid = request.form["ont"]
        sn = request.form["sn"]
        desc = request.form["name"]
        sp = request.form["service_port"]
        pppoe = request.form["user"]
        port = port.split()[1]

        return render_template("alta_ont_gs_ma.html", frame=frame, slot=slot, port=port, ontid=ontid, sn=sn, desc=desc, sp=sp, pppoe=pppoe)

@app.route("/alta-ont-v3-ma", methods=["GET", "POST"])
# @login_required
def alta_ont_web_v3_ma():
    if request.method == "GET":
        return "Esta ruta solo acepta POST. Envía el formulario desde /sheet_ma.", 405

    try:
        frame = request.form["frame"]
        slot = request.form["slot"]
        port = request.form["port"]
        ontid = request.form["ontid"]
        sn = request.form["sn"]
        desc = request.form["desc"]
        sp = request.form["sp"]
        pppoe = request.form["pppoe"]
        profile = request.form["profile"]

        logger.info(f"[alta-ont-v3-ma] Inicio | SN: {sn} | pppoe: {pppoe} | port: {port} | ontid: {ontid}")

        tn, resultado = alta_ont_version_three_ma(frame, slot, port, ontid, sn, desc, sp)

        logger.info(f"[alta-ont-v3-ma] alta_ont_version_three_ma completado | SN: {sn}")

        # Si tn es None o el resultado contiene error, no continuar con save ni MikroTik
        if tn is None or "Failure" in str(resultado) or "failure" in str(resultado) or "Error" in str(resultado):
            logger.error(f"[alta-ont-v3-ma] Error detectado, abortando | SN: {sn} | resultado: {resultado}")
            if tn is not None:
                try:
                    tn.close()
                except Exception:
                    pass
            return render_template("resultado_alta_v2.html", resultado=resultado)

        print("Salida Guardando...")
        time.sleep(10)
        cmd = f"save\r\n"
        r, out = send_cmd_telnet_add_onu_two(tn, cmd)
        time.sleep(0.3)
        print("Salida final:\n", out)
        print(repr(out))
        tn.close()

        logger.info(f"[alta-ont-v3-ma] Llamando call_mkt | pppoe: {pppoe} | profile: {profile}")
        call_mkt(pppoe, profile, desc)

        logger.info(f"[alta-ont-v3-ma] Finalizado OK | SN: {sn}")
        return render_template("resultado_alta_v2.html", resultado=resultado)

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        logger.error(f"[alta-ont-v3-ma] ERROR: {e}\n{tb}")
        return f"<pre>ERROR en /alta-ont-v3-ma:\n\n{tb}</pre>", 500

@app.route("/alta-ont-gs-transp", methods=["POST"])
# @login_required
def alta_ont_web_trans():
    if request.method == "POST":
        frame =  0
        slot =  1
        port = request.form["port"]
        ontid = request.form["ont"]
        sn = request.form["sn"]
        desc = request.form["name"]
        sp = request.form["service_port"]
        pppoe = request.form["user"]
        # profile = "25M"
        port =port.split()[1]

        return render_template("alta_ont_gs_transp.html", frame =frame , slot =slot, port =port, ontid =ontid, sn =sn, desc =desc, sp =sp, pppoe =pppoe)

@app.route("/getpotencia", methods=["GET"])
def getpotencia():
    datos = []
    conn,estado, resultado = conectar()
    print(estado)
    if estado == "error":
        flash("Error " + conn)
        return redirect(url_for("dashboard"))
    else:
        conn.write(b"enable\n")
        conn.write(b"config\n")
        datos = consultar_potencia(conn,0,1,0,0)
        texto_limpio = limpiar_salida_olt(datos)
        datos, errores = parse_ont_info(texto_limpio)
        r_onts = {}
        i=0
        for puerto, onts in datos.items():
            # print('------------------------------------------------------------------------')            
            valores = [line.split('/') for line in puerto.strip().splitlines()]
            valor = [[int(x) for x in linea] for linea in valores]
            # for grupo in valor:
            # print(valor[0][0], valor[0][1], valor[0][2])
            card_id = valor[0][0]
            slot_id = valor[0][1]
            port_id = valor[0][2]
            # print(card_id, slot_id, port_id)
            
            # print(grupo)
            
            for ont in onts.values():
                if(port_id == 3):
                    print('card_id:', card_id, 'slot_id:', slot_id, 'port_id:', port_id , 'ont_id:', ont['ont_id'])
                # print(ont['ont_id'])
                # print(ont['state'])
                ont_id =            ont['ont_id']
                state =             ont['state']
                uptime =            ont['uptime']
                downtime =          ont['downtime']
                down_cause =        ont['down_cause']
                sn =                ont['sn']
                type =              ont['type']
                distance =          ont['distance']
                rx_tx =             ont['rx_tx']
                description =       ont['description']
                service_port_num =  ont['service_port_num']
                cmd = {
                    "editar_url": ont['editar_url'],
                    "borrar_ont": ont['borrar_ont'],
                    "borrar_sp": ont['borrar_sp'],
                }                
                cmd_json = json.dumps(cmd)
                line = ont['line']
                key = (card_id, slot_id, port_id, ont_id)
                # r_onts[i] = [card_id, slot_id, port_id, ont_id, state, uptime, downtime, down_cause, sn, type, distance, rx_tx, description, service_port_num, cmd_json, line]
                r_onts[i] = {
                    "card_id": card_id,
                    "slot_id": slot_id,
                    "port": port_id,
                    "ont": ont_id,
                    "state": state,
                    "uptime": uptime,
                    "downtime": downtime,
                    "down_cause": down_cause,
                    "sn": sn,
                    "type": type,
                    "distance": distance,
                    "rx_tx": rx_tx,
                    "name": description,
                    "service": service_port_num,
                    "cmd_json": cmd_json,
                    "line": line
                }

                i=i+1
                # print(i)

        # print("Error: ",errores)
        # print("Datos: ", datos)
    conn.close()
    # print(datos)
    result = json.dumps(r_onts[0])    
    # return result
    return render_template("get_potencia.html", records = r_onts)

# ─── Network Scanner ──────────────────────────────────────────────────────────

@app.route('/network-scan')
@login_required
def network_scan():
    return render_template('network_scan.html')


@app.route('/api/network-scan', methods=['POST'])
@login_required
def api_network_scan():
    from scanner.orchestrator import run_scan
    data = request.get_json(silent=True) or {}
    mkt_host = data.get('host') or None
    mkt_port = int(data.get('port') or 0) or None
    mkt_user = data.get('user') or None
    mkt_pass = data.get('password') or None
    listen_sec = int(data.get('listen_sec', 5))
    neighbors_only = bool(data.get('neighbors_only', True))

    # Guardar credenciales del hub en sesión — las usa el proxy y WinBox
    # para crear el túnel SSH sin necesidad de pasar credenciales en la URL.
    if mkt_host:
        session['hub_host'] = mkt_host
        session['hub_port'] = mkt_port or int(os.getenv('M1_PORT', 12222))
        session['hub_user'] = mkt_user or os.getenv('M1_USER', 'admin')
        session['hub_pass'] = mkt_pass or os.getenv('M1_PASS', '')

    try:
        result = run_scan(
            mkt_host=mkt_host,
            mkt_port=mkt_port,
            mkt_user=mkt_user,
            mkt_pass=mkt_pass,
            listen_sec=listen_sec,
            neighbors_only=neighbors_only,
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error en /api/network-scan: {e}")
        return jsonify({'error': str(e), 'devices': [], 'stats': {}, 'errors': [str(e)]}), 500


@app.route('/api/ping', methods=['POST'])
@login_required
def api_ping():
    from scanner.mikrotik_ssh import connect, run_command
    data = request.get_json(silent=True) or {}
    target_ip = data.get('ip', '').strip()
    if not target_ip:
        return jsonify({'error': 'IP requerida'}), 400

    mkt_host = data.get('host') or os.getenv('M1_HOST', '')
    mkt_port = int(data.get('port') or os.getenv('M1_PORT', 12222))
    mkt_user = data.get('user') or os.getenv('M1_USER', '')
    mkt_pass = data.get('password') or os.getenv('M1_PASS', '')

    try:
        client = connect(mkt_host, mkt_port, mkt_user, mkt_pass)
        raw = run_command(client, f'/ping {target_ip} count=4 interval=200ms', timeout=15)
        client.close()
        # Extraer estadísticas de la última línea
        import re
        stats_m = re.search(
            r'sent=(\d+)\s+received=(\d+)\s+packet-loss=(\d+)%'
            r'(?:\s+min-rtt=(\S+)\s+avg-rtt=(\S+)\s+max-rtt=(\S+))?',
            raw
        )
        stats = {}
        if stats_m:
            stats = {
                'sent':     int(stats_m.group(1)),
                'received': int(stats_m.group(2)),
                'loss':     int(stats_m.group(3)),
                'min':      stats_m.group(4) or '',
                'avg':      stats_m.group(5) or '',
                'max':      stats_m.group(6) or '',
            }
        return jsonify({'output': raw, 'ip': target_ip, 'stats': stats})
    except Exception as e:
        logger.error(f"Error en /api/ping {target_ip}: {e}")
        return jsonify({'error': str(e), 'ip': target_ip}), 500


# ── Proxy de dispositivos vía túnel SSH ───────────────────────────────────

_HOP_BY_HOP = {
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailers', 'transfer-encoding', 'upgrade',
    'content-encoding', 'content-length',
}
# Strip these from forwarded requests so the upstream always returns full bodies
# (304 responses have no body — the interceptor script can't be injected).
_STRIP_REQ = {'if-none-match', 'if-modified-since', 'if-match', 'if-unmodified-since', 'if-range'}


def _proxy_prefix(ip, port):
    return f'/proxy/{ip}/{port}'


def _make_js_intercept(ip: str, port: int) -> str:
    """
    Script inyectado al inicio del <head>.
    Intercepta TODAS las formas en que el browser carga recursos remotos:
      fetch(), XHR, WebSocket — y la inyección dinámica de <script>/<link>
      que usa Webpack para code-splitting (chunks cargados tras login).
    """
    prefix = _proxy_prefix(ip, port)
    ip_re  = ip.replace('.', '\\\\.')   # 192\.168\.2\.180 para JS RegExp
    ajax_timeout = PROXY_AJAX_TIMEOUT_MS
    return (
        '<script>'
        '(function(){'

        # ── función de reescritura central ────────────────────────────────
        f'var P="{prefix}";'
        f'var R=new RegExp("https?://{ip_re}(?::{port})?","g");'
        'if(typeof window.__!=="function"){'
          'window.__=function(s){return s==null?"":String(s);};'
        '}'
        'function rw(u){'
          'if(typeof u!=="string"||!u)return u;'
          'u=u.replace(R,P);'
          'if(u.charAt(0)==="/"&&u.slice(0,7)!=="/proxy/")u=P+u;'
          'return u;'
        '}'

        # ── fetch() ───────────────────────────────────────────────────────
        'var _f=window.fetch;'
        'window.fetch=function(u,o){return _f.call(this,rw(u),o);};'

        # ── XMLHttpRequest ────────────────────────────────────────────────
        'var _o=XMLHttpRequest.prototype.open;'
        'XMLHttpRequest.prototype.open=function(){'
          'var a=Array.from(arguments);a[1]=rw(a[1]);return _o.apply(this,a);'
        '};'

        # Extend jQuery Ajax timeouts for proxied CGI calls. Device UIs often
        # assume LAN latency and abort status reloads too quickly over tunnels.
        'function tuneJq(){'
          'var $=window.jQuery||window.$;'
          'if(!$||!$.ajax||$.__proxyTimeoutPatched)return false;'
          '$.__proxyTimeoutPatched=true;'
          'function isCgi(u){u=rw(u||"");return typeof u==="string"&&/\\.cgi(?:\\?|$)/.test(u);}'
        'if($.ajaxPrefilter){'
            '$.ajaxPrefilter(function(o){'
              f'if(o&&isCgi(o.url))o.timeout=Math.max(Number(o.timeout)||0,{ajax_timeout});'
            '});'
          '}'
          'var _ajax=$.ajax;'
          '$.ajax=function(u,o){'
            'var opt=typeof u==="string"?(o=o||{},o.url=u,o):(u||{});'
            f'if(opt&&isCgi(opt.url))opt.timeout=Math.max(Number(opt.timeout)||0,{ajax_timeout});'
            'return _ajax.apply(this,arguments);'
          '};'
          'return true;'
        '}'
        'if(!tuneJq()){'
          'var _jqTimer=setInterval(function(){if(tuneJq())clearInterval(_jqTimer);},50);'
          'setTimeout(function(){clearInterval(_jqTimer);},10000);'
        '}'

        # ── WebSocket ─────────────────────────────────────────────────────
        'if(window.WebSocket){'
          'var _W=window.WebSocket;'
          'window.WebSocket=function(u,p){'
            'u=rw(u).replace(/^wss:/,"ws:").replace(/^https:/,"ws:");'
            'try{return new _W(u,p);}catch(e){console.warn("[proxy] WS:",e);}'
          '};'
          'Object.assign(window.WebSocket,_W);'
        '}'

        # ── Webpack code-splitting: <script src> y <link href> dinámicos ──
        # Capa 1: wrappea setters de prototipo — intercepta asignaciones directas
        # (link.href = x) antes de que el browser inicie la carga.
        'function wrapSetter(proto,prop){'
          'var d=Object.getOwnPropertyDescriptor(proto,prop);'
          'if(!d||!d.configurable||!d.set)return;'
          'Object.defineProperty(proto,prop,{'
            'get:d.get,'
            'set:function(v){d.set.call(this,rw(v));},'
            'configurable:true,enumerable:d.enumerable'
          '});'
        '}'
        'try{wrapSetter(HTMLScriptElement.prototype,"src");}catch(e){}'
        'try{wrapSetter(HTMLLinkElement.prototype,"href");}catch(e){}'
        'try{wrapSetter(HTMLImageElement.prototype,"src");}catch(e){}'

        # ── setAttribute: fallback para loaders que usan setAttribute ─────────
        'var _sa=Element.prototype.setAttribute;'
        'Element.prototype.setAttribute=function(n,v){'
          'if((n==="src"||n==="href")&&typeof v==="string")v=rw(v);'
          'return _sa.call(this,n,v);'
        '};'

        # ── Capa 2: MutationObserver — red de seguridad para chunks Webpack ───
        # Algunos builds usan Object.assign o acceso indirecto que escapa la
        # capa 1. El observer reescribe href/src justo después de la inserción
        # al DOM, antes de que el browser inicie el request de red.
        'try{'
          'new MutationObserver(function(ms){'
            'ms.forEach(function(m){'
              'm.addedNodes.forEach(function(n){'
                'if(!n.tagName)return;'
                'var t=n.tagName.toUpperCase();'
                'if(t==="LINK"){var h=n.getAttribute("href");if(h&&h.indexOf("/proxy/")<0){var rh=rw(h);if(rh!==h)_sa.call(n,"href",rh);}}'
                'else if(t==="SCRIPT"){var s=n.getAttribute("src");if(s&&s.indexOf("/proxy/")<0){var rs=rw(s);if(rs!==s)_sa.call(n,"src",rs);}}'
              '});'
              # también captura cambios de atributo en elementos ya en el DOM
              'if(m.type==="attributes"&&m.target){'
                'var el=m.target,at=m.attributeName;'
                'if(at==="href"||at==="src"){'
                  'var v=el.getAttribute(at);'
                  'if(v&&v.indexOf("/proxy/")<0){var rv=rw(v);if(rv!==v)_sa.call(el,at,rv);}'
                '}'
              '}'
            '});'
          '}).observe(document.documentElement,{'
            'childList:true,subtree:true,'
            'attributes:true,attributeFilter:["href","src"]'
          '});'
        '}catch(e){}'

        '})();'
        '</script>'
    )


def _should_proxy_url(url: str) -> bool:
    if not url:
        return False
    u = url.strip()
    if not u or u.startswith(('#', '//', '/proxy/')):
        return False
    return not re.match(r'^[a-z][a-z0-9+.-]*:', u, flags=re.I)


def _rewrite_url_value(url: str, ip: str, port: int, subpath: str = '') -> str:
    if not _should_proxy_url(url):
        return url

    prefix = _proxy_prefix(ip, port)
    if url.startswith('/'):
        return prefix + url

    base = '/' + (subpath or '')
    if not base.endswith('/'):
        base = base.rsplit('/', 1)[0] + '/'
    return prefix + urljoin(base, url)


def _rewrite_asset_urls(text: str, ip: str, port: int, subpath: str = '') -> str:
    """
    Reescribe URLs en HTML/CSS para que pasen por el proxy.
    """
    prefix = _proxy_prefix(ip, port)

    # href/src/action relativos o absolutos del dispositivo.
    text = re.sub(
        r'((?:href|src|action)=")([^"]*)',
        lambda m: m.group(1) + _rewrite_url_value(m.group(2), ip, port, subpath),
        text,
    )
    text = re.sub(
        r"((?:href|src|action)=')([^']*)",
        lambda m: m.group(1) + _rewrite_url_value(m.group(2), ip, port, subpath),
        text,
    )
    # content="/..." en meta refresh u otros casos donde content sea URL.
    text = re.sub(
        r'((?:content)=")(/[^"]*)',
        lambda m: m.group(1) + _rewrite_url_value(m.group(2), ip, port, subpath),
        text,
    )
    text = re.sub(
        r"((?:content)=')(/[^']*)",
        lambda m: m.group(1) + _rewrite_url_value(m.group(2), ip, port, subpath),
        text,
    )
    # url(...) en CSS, incluyendo rutas relativas como url(login-unms.svg).
    text = re.sub(
        r'url\(\s*([\'"]?)([^)\'"]+)\1\s*\)',
        lambda m: f'url({m.group(1)}{_rewrite_url_value(m.group(2).strip(), ip, port, subpath)}{m.group(1)})',
        text,
    )
    # URLs absolutas del propio dispositivo
    for scheme in ('https', 'http'):
        text = text.replace(f'{scheme}://{ip}:{port}', prefix)
        text = text.replace(f'{scheme}://{ip}',        prefix)

    return text


def _rewrite(text: str, ip: str, port: int, subpath: str = '') -> str:
    """
    Reescribe URLs en HTML e inyecta el interceptor JS en el <head>.
    """
    # Inyectar interceptor JS solo en HTML real. Los bundles JS pueden contener
    # el texto "<head>" dentro de strings y se rompen si se inyecta ahi.
    if '<head>' in text:
        text = text.replace('<head>', '<head>' + _make_js_intercept(ip, port), 1)
    elif '<HEAD>' in text:
        text = text.replace('<HEAD>', '<HEAD>' + _make_js_intercept(ip, port), 1)

    return _rewrite_asset_urls(text, ip, port, subpath)


def _rewrite_location(location: str, ip: str, port: int) -> str:
    prefix = _proxy_prefix(ip, port)
    for scheme in ('https', 'http'):
        for suffix in (f':{port}', ''):
            base = f'{scheme}://{ip}{suffix}'
            if location.startswith(base):
                return prefix + location[len(base):]
    if location.startswith('/'):
        return prefix + location
    return location


def _rewrite_cookies(raw_cookies: list[str]) -> list[str]:
    """Quita Secure y Domain de Set-Cookie para que el browser los acepte."""
    out = []
    for c in raw_cookies:
        c = re.sub(r';\s*Secure', '', c, flags=re.I)
        c = re.sub(r';\s*Domain=[^;]+', '', c, flags=re.I)
        c = re.sub(r';\s*SameSite=[^;]+', '', c, flags=re.I)
        out.append(c)
    return out


def _proxy_target_from_referer(asset_path: str):
    ref = request.headers.get('Referer', '')
    ref_path = urlparse(ref).path if ref else ''
    m = re.match(r'^/proxy/([^/]+)/(\d+)(?:/.*)?$', ref_path)
    if not m:
        return None

    target = f'/proxy/{m.group(1)}/{m.group(2)}/{asset_path}'
    if request.query_string:
        target += '?' + request.query_string.decode('utf-8', errors='replace')
    return target


@app.route('/images/<path:asset>', methods=['GET', 'HEAD'])
@login_required
def proxy_referred_image(asset):
    target = _proxy_target_from_referer(f'images/{asset}')
    if target:
        return redirect(target, code=302)
    return ('Not found', 404)


_PROXY_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
_PROXY_RETRY_METHODS = {'GET', 'HEAD', 'OPTIONS'}
_PROXY_STATIC_EXTS = (
    '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.map',
)


def _looks_like_premature_read(error: Exception) -> bool:
    msg = str(error)
    return 'IncompleteRead' in msg or 'Response ended prematurely' in msg


def _looks_like_ssl_eof(error: Exception) -> bool:
    msg = str(error)
    return 'SSLEOFError' in msg or 'UNEXPECTED_EOF_WHILE_READING' in msg


def _is_writecfg(subpath: str) -> bool:
    return subpath.lower().endswith('writecfg.cgi')


def _writecfg_assumed_success(ip: str, port: int, subpath: str, reason: str):
    logger.warning(
        "[proxy] writecfg.cgi corto la respuesta; asumiendo aplicado %s:%s/%s: %s",
        ip, port, subpath, reason,
    )
    return jsonify({
        'success': True,
        'status': 'ok',
        'applied': True,
        'proxy_warning': 'upstream_response_ended_prematurely_after_writecfg',
    })


def _apply_upstream_accept_headers(headers: dict, subpath: str) -> None:
    path = subpath.lower()
    headers.pop('Accept-Language', None)
    if path.endswith('.cgi'):
        headers['Accept'] = '*/*'
        headers['Accept-Encoding'] = 'identity'
        headers['Connection'] = 'close'
    elif path.endswith(_PROXY_STATIC_EXTS):
        headers['Accept'] = '*/*'
        headers['Accept-Encoding'] = 'gzip, deflate, identity'
    else:
        headers['Accept-Encoding'] = 'gzip, deflate, identity'


def _read_proxy_body(resp, ip, port, subpath, tolerate_empty=False):
    chunks = []
    if hasattr(resp.raw, 'enforce_content_length'):
        resp.raw.enforce_content_length = False
    try:
        for chunk in resp.iter_content(chunk_size=65536):
            if chunk:
                chunks.append(chunk)
        return b''.join(chunks)
    except Exception as e:
        raw = b''.join(chunks)
        if raw or (tolerate_empty and _looks_like_premature_read(e)):
            logger.warning(
                "[proxy] Respuesta incompleta tolerada %s:%s/%s: %s",
                ip, port, subpath, e,
            )
            return raw
        raise


def _proxy_request_with_retry(
    ip, port, method, target_factory, headers, body, subpath,
    reset_upstream=None,
):
    attempts = 2 if method in _PROXY_RETRY_METHODS else 1
    last_error = None

    for attempt in range(attempts):
        req_headers = dict(headers)
        if attempt > 0:
            req_headers['Connection'] = 'close'

        sess = _new_proxy_session(pool_maxsize=1)
        try:
            resp = sess.request(
                method=method,
                url=target_factory(),
                headers=req_headers,
                data=body,
                allow_redirects=False,
                stream=True,
                timeout=(15, PROXY_UPSTREAM_TIMEOUT),
            )
            raw = _read_proxy_body(
                resp, ip, port, subpath,
                tolerate_empty=(
                    method in _PROXY_RETRY_METHODS and attempt + 1 == attempts
                ),
            )
            return resp, raw
        except Exception as e:
            last_error = e
            if attempt + 1 < attempts:
                if reset_upstream and _looks_like_ssl_eof(e):
                    reset_upstream()
                logger.warning(
                    "[proxy] Reintentando %s:%s por conexion upstream rota: %s",
                    ip, port, e,
                )
        finally:
            try:
                sess.close()
            except Exception:
                pass

    raise last_error

@app.route('/proxy/<ip>/<int:port>/', defaults={'subpath': ''}, methods=_PROXY_METHODS)
@app.route('/proxy/<ip>/<int:port>/<path:subpath>', methods=_PROXY_METHODS)
@login_required
def device_proxy(ip, port, subpath):
    # 1. Credenciales del hub desde la sesión (guardadas al hacer scan)
    hub = _session_hub_creds()

    # 2. Obtener (o crear) el túnel SSH → MikroTik hub → target
    try:
        local_port = tunnel_manager.get_local_port(
            ip, port,
            hub_host=hub['host'],
            hub_port=hub['port'],
            hub_user=hub['user'],
            hub_pass=hub['pass'],
        )
    except Exception as e:
        logger.error(f"[proxy] Tunel fallido {ip}:{port} via {hub['host']} — {e}")
        return (
            f'<pre style="font-family:monospace;padding:2rem">'
            f'No se pudo crear el tunel hacia {ip}:{port}\n\n{e}</pre>',
            502,
        )

    # 3. Construir URL destino (a través del túnel local)
    scheme = 'https' if port in (443, 8443) else 'http'
    query = request.query_string.decode('utf-8', errors='replace')

    def target_url():
        url = f'{scheme}://127.0.0.1:{local_port}/{subpath}'
        if query:
            url += '?' + query
        return url

    def reset_upstream():
        nonlocal local_port
        logger.warning(
            "[proxy] Reiniciando tunel por EOF SSL %s:%s via %s",
            ip, port, hub['host'],
        )
        tunnel_manager.close(ip, port, hub_host=hub['host'])
        _drop_proxy_session(ip, port)
        local_port = tunnel_manager.get_local_port(
            ip, port,
            hub_host=hub['host'],
            hub_port=hub['port'],
            hub_user=hub['user'],
            hub_pass=hub['pass'],
        )

    # 3. Reenviar la petición
    fwd_headers = {
        k: v for k, v in request.headers
        if k.lower() not in _HOP_BY_HOP
        and k.lower() not in _STRIP_REQ
        and k.lower() != 'host'
    }
    fwd_headers['Host'] = f'{ip}:{port}' if port not in (80, 443) else ip
    _apply_upstream_accept_headers(fwd_headers, subpath)

    # El browser es el dueño del jar de cookies; el Session solo gestiona
    # la conexión TCP persistente.  Pasamos las cookies del browser como
    # header crudo y limpiamos el jar interno para evitar conflictos.
    browser_cookie = request.headers.get('Cookie', '')
    if browser_cookie:
        fwd_headers['Cookie'] = browser_cookie
    else:
        fwd_headers.pop('Cookie', None)

    try:
        resp, raw = _proxy_request_with_retry(
            ip, port, request.method, target_url, fwd_headers,
            request.get_data(), subpath, reset_upstream=reset_upstream,
        )
    except Exception as e:
        if (
            request.method == 'POST'
            and _is_writecfg(subpath)
            and _looks_like_premature_read(e)
        ):
            return _writecfg_assumed_success(ip, port, subpath, str(e))

        logger.error(f"[proxy] Error de petición {ip}:{port}/{subpath} — {e}")
        return (
            f'<pre style="font-family:monospace;padding:2rem">'
            f'Error al conectar con {ip}:{port}\n\n{e}</pre>',
            502,
        )

    # 4. Extraer Set-Cookie del dispositivo (antes de leer el body)
    raw_sc = (
        resp.raw.headers.getlist('Set-Cookie')
        if hasattr(resp.raw.headers, 'getlist')
        else []
    )
    if not raw_sc and 'Set-Cookie' in resp.headers:
        raw_sc = [resp.headers['Set-Cookie']]

    # 5. Reescribir URLs en HTML / CSS. No tocar JS: los bundles minificados
    # pueden contener "<head>" o URLs dentro de strings y romperse al editarlos.
    content_type = resp.headers.get('Content-Type', '')
    content_type_l = content_type.lower()
    accept_l = request.headers.get('Accept', '').lower()
    if (
        not raw
        and resp.status_code == 200
        and ('json' in content_type_l or 'json' in accept_l)
    ):
        if request.method == 'POST' and _is_writecfg(subpath):
            return _writecfg_assumed_success(ip, port, subpath, 'empty JSON response')

        logger.error(
            "[proxy] Respuesta JSON vacia de upstream %s:%s/%s",
            ip, port, subpath,
        )
        return jsonify({
            'error': 'empty_upstream_json_response',
            'target': f'{ip}:{port}/{subpath}',
        }), 502

    if 'html' in content_type_l:
        raw = _rewrite(raw.decode('utf-8', errors='replace'), ip, port, subpath).encode('utf-8')
    elif 'css' in content_type_l:
        raw = _rewrite_asset_urls(raw.decode('utf-8', errors='replace'), ip, port, subpath).encode('utf-8')

    # 6. Manejar redirects del dispositivo
    #    IMPORTANTE: incluir Set-Cookie incluso en redirects.
    #    /cookiechecker devuelve 302 + Set-Cookie; si no se reenvía la cookie
    #    el browser nunca la almacena y se queda en loop infinito.
    if resp.status_code in (301, 302, 303, 307, 308):
        location = _rewrite_location(resp.headers.get('Location', '/'), ip, port)
        redir = redirect(location, code=resp.status_code)
        for cookie in _rewrite_cookies(raw_sc):
            redir.headers.add('Set-Cookie', cookie)
        return redir

    # 7. Construir respuesta para el browser
    out_headers = {
        k: v for k, v in resp.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }
    out_headers.pop('Set-Cookie', None)

    flask_resp = Response(raw, status=resp.status_code,
                          content_type=content_type)
    for cookie in _rewrite_cookies(raw_sc):
        flask_resp.headers.add('Set-Cookie', cookie)
    for k, v in out_headers.items():
        if k.lower() != 'set-cookie':
            flask_resp.headers[k] = v

    return flask_resp


@app.route('/api/proxy/list')
@login_required
def api_proxy_list():
    return jsonify(tunnel_manager.list_active())


@app.route('/api/proxy/tunnel', methods=['POST'])
@login_required
def api_proxy_tunnel():
    """Crea (o reutiliza) un túnel TCP puro y devuelve el puerto local.
    Uso: WinBox, SSH, Telnet, etc. — cualquier protocolo no-HTTP.
    Parámetros JSON:
      ip      — IP del dispositivo destino (requerido)
      port    — Puerto destino (default 8291 WinBox)
      hub_ip  — IP del hub MikroTik que tiene acceso LAN al destino (default M1_HOST)
    """
    data = request.get_json(silent=True) or {}
    ip   = data.get('ip', '').strip()
    port = int(data.get('port', 8291))
    if not ip:
        return jsonify({'error': 'ip requerido'}), 400

    hub = _session_hub_creds()
    try:
        tunnel = tunnel_manager.get_local_port_info(
            ip, port,
            hub_host=hub['host'],
            hub_port=hub['port'],
            hub_user=hub['user'],
            hub_pass=hub['pass'],
        )
        local_port = tunnel['local_port']
        return jsonify({
            'local_port': local_port,
            'connect_to': tunnel.get('connect_to') or f'localhost:{local_port}',
            'public_host': tunnel.get('public_host'),
            'public_url': tunnel.get('public_url'),
            'expires_in_sec': tunnel.get('expires_in_sec'),
            'reused': tunnel['reused'],
        })
    except Exception as e:
        logger.error(f"[tunnel] Error creando tunel {ip}:{port} via {hub['host']} — {e}")
        return jsonify({'error': str(e)}), 502


@app.route('/api/proxy/close', methods=['POST'])
@login_required
def api_proxy_close():
    data = request.get_json(silent=True) or {}
    ip   = data.get('ip', '')
    port = int(data.get('port', 0))
    hub = _session_hub_creds()
    tunnel_manager.close(ip, port, hub_host=hub['host'])
    with _proxy_sessions_lock:
        _proxy_sessions.pop((ip, port), None)
    return jsonify({'ok': True})


# ── Gestión de usuarios ───────────────────────────────────────────────────────

@app.route('/usuarios')
@login_required
def usuarios():
    from flask_login import current_user
    if current_user.role != 'admin':
        flash('Acceso solo para administradores')
        return redirect('/dashboard')
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, username, full_name, role FROM users ORDER BY id")
    users_list = [dict(r) for r in c.fetchall()]
    conn.close()
    return render_template('usuarios.html', users=users_list)


@app.route('/usuarios/crear', methods=['POST'])
@login_required
def usuarios_crear():
    from flask_login import current_user
    if current_user.role != 'admin':
        flash('Acceso solo para administradores')
        return redirect('/dashboard')
    username  = request.form.get('username', '').strip()
    password  = request.form.get('password', '').strip()
    full_name = request.form.get('full_name', '').strip()
    role      = request.form.get('role', 'user').strip()
    if not username or not password:
        flash('Usuario y contraseña son requeridos')
        return redirect('/usuarios')
    if role not in ('admin', 'user'):
        role = 'user'
    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute(
            "INSERT INTO users (username, password, full_name, role) VALUES (?,?,?,?)",
            (username, generate_password_hash(password), full_name, role),
        )
        conn.commit()
        conn.close()
        flash(f'Usuario "{username}" creado correctamente')
    except sqlite3.IntegrityError:
        flash(f'El usuario "{username}" ya existe')
    return redirect('/usuarios')


@app.route('/usuarios/eliminar/<int:user_id>', methods=['POST'])
@login_required
def usuarios_eliminar(user_id):
    from flask_login import current_user
    if current_user.role != 'admin':
        flash('Acceso solo para administradores')
        return redirect('/dashboard')
    if user_id == current_user.id:
        flash('No puedes eliminar tu propia cuenta')
        return redirect('/usuarios')
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    flash('Usuario eliminado')
    return redirect('/usuarios')


# ── Auth para app mobile (token Bearer 24 h) ──────────────────────────────────

@app.route('/api/auth/login', methods=['POST'])
def api_auth_login():
    data     = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'usuario y contraseña requeridos'}), 400
    user = User.get(username)
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Credenciales incorrectas'}), 401
    token_val  = uuid.uuid4().hex + uuid.uuid4().hex   # 64 chars aleatorios
    now        = datetime.utcnow()
    expires_at = (now + timedelta(hours=24)).isoformat()
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO api_tokens (user_id, token, name, created_at, expires_at) VALUES (?,?,?,?,?)",
        (user.id, token_val, 'Mobile login', now.isoformat(), expires_at),
    )
    conn.commit()
    conn.close()
    logger.info(f"[api_auth] Token creado para usuario {username}")
    return jsonify({
        'token':      token_val,
        'expires_at': expires_at,
        'user': {
            'id':        user.id,
            'username':  user.username,
            'full_name': user.full_name,
            'role':      user.role,
        },
    })


@app.route('/api/auth/logout', methods=['POST'])
def api_auth_logout():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        token_val = auth[7:].strip()
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("UPDATE api_tokens SET revoked=1 WHERE token=?", (token_val,))
        conn.commit()
        conn.close()
        logger.info("[api_auth] Token revocado via logout")
    return jsonify({'ok': True})


@app.route('/api/auth/me')
def api_auth_me():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'No autorizado'}), 401
    row = _get_valid_token(auth[7:].strip())
    if not row:
        return jsonify({'error': 'Token inválido o expirado'}), 401
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, username, full_name, role FROM users WHERE id=?", (row['user_id'],))
    user = dict(c.fetchone() or {})
    conn.close()
    return jsonify(user)


_BACKBONE_HOST = os.getenv('BACKBONE_HOST', '')


@app.route('/api/health')
@api_required
def api_health():
    """Pinga el backbone y devuelve online/offline. Requiere Bearer token."""
    host = _BACKBONE_HOST
    if not host:
        return jsonify({'status': 'unknown', 'error': 'BACKBONE_HOST no configurado'}), 503
    import platform
    is_windows = platform.system().lower() == 'windows'
    cmd = ['ping', '-n', '5', '-w', '2000', host] if is_windows else ['ping', '-c', '5', '-W', '2', host]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=20)
        status = 'online' if result.returncode == 0 else 'offline'
    except Exception:
        status = 'offline'
    return jsonify({'status': status, 'host': host})


@app.route('/api/health/backbone')
@login_required
def api_backbone_health():
    host = _BACKBONE_HOST
    if not host:
        return jsonify({'status': 'unknown', 'error': 'BACKBONE_HOST no configurado'}), 503
    import platform
    is_windows = platform.system().lower() == 'windows'
    if is_windows:
        cmd = ['ping', '-n', '5', '-w', '2000', host]
    else:
        cmd = ['ping', '-c', '5', '-W', '2', host]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=20)
        status = 'online' if result.returncode == 0 else 'offline'
    except Exception:
        status = 'offline'
    return jsonify({'status': status, 'host': host})


if __name__ == "__main__":
    start_streamlit()
    local_dev = os.getenv("LOCAL_DEV", "false").lower() == "true"
    if local_dev:
        app.run(host="0.0.0.0", port=8080, debug=True, threaded=True)
    else:
        app.run(host="0.0.0.0", port=8080, ssl_context=("fullchain.pem","privkey.pem"), debug=False, threaded=True)
