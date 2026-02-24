from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from werkzeug.security import check_password_hash
import sqlite3,time
import os
import json
from dotenv import load_dotenv
from olt_telnet import alta_ont, consultar_potencia, descargar_config, guardar_sqlite, conectar, obtener_ultimo_config, parse_ont_info, limpiar_salida_olt, extraer_service_ports, delete_sp, delete_ont_cont, guardar_tabla, get_potencia, alta_ont_versiontwo, delete_ont_sn, alta_ont_version_three, send_cmd_telnet_add_onu_two
from datetime import datetime
import re
load_dotenv()

LINE_PROFILE = os.getenv("LINE_PROFILE_ID", "500")
SRV_PROFILE = os.getenv("SRV_PROFILE_ID", "500")
VLAN = os.getenv("VLAN", "100")
PASSWORD_PPPOE = os.getenv("PASSWORD_PPPOE", "1234")
SERVICE_PPPOE = os.getenv("SERVICE_PPP", "pppoe")

HOST_MKT = os.getenv("HOST_MKT", "LOCALHOST")
USERNAME_MKT = os.getenv("USERNAME_MKT", "admin")
PASSWORD_MKT =  os.getenv("PASSWORD_MKT", "admin")
SERVER_ACS = os.getenv("SERVER_ACS", "192.168.1.7:7557")


# Cargar variables del archivo .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configurar login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

DATABASE = "users.db"
# conn = conectar()

class User(UserMixin):
    def __init__(self, id_, username, password_hash):
        self.id = id_
        self.username = username
        self.password_hash = password_hash

    @staticmethod
    def get(username):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return User(*row)
        return None

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password FROM users WHERE id = ?", (user_id,))
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

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/guardar_datos", methods = ["POST"])
@login_required
def guardar_datos():
    conn,estado, resultado = conectar()
    print(estado)
    if estado == "error":
        flash("Error " + conn)
        return redirect(url_for("dashboard"))
    else:
        conn.write(b"enable\n")
        conn.write(b"config\n")
        datos = descargar_config(conn)
        time.sleep(10)
        if datos:
            guardar_sqlite(datos,"current")
            flash("Datos guardados correctamente")
        else:
            flash("No se pudieron guardar los datos")

        datos = consultar_potencia(conn, 0,1,0,0)    
        if datos:
            guardar_sqlite(datos,"ont")
            flash("Datos guardados correctamente")
        else:
            flash("No se pudieron guardar los datos")
        
        conn.close()

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

@app.route("/borrar_ont_sn/<sn>")
# @login_required
def borrar_ont_sn(sn):
    delete_ont_sn(sn)
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
        # valores = alta_ont_version_three(frame, slot, port, ontid, sn, desc, sp)
        # print(valores)
        # return
        # resultado = 'Success';
        user = to_camel_case(desc)
        response = provision_device_dynamic(
            serial_target=sn,
            pppoe_user=pppoe,
            pppoe_pass=PASSWORD_PPPOE,
            vlan=VLAN,
            tag=user,
            provision_name="crear_pppoe_vlan100",
            host=SERVER_ACS
        )
        print("Salida Guardando...")                    

        time.sleep(10)
        # tn.write(b"save\r\n")
        cmd = f"save\r\n"    
        # cmd = "save\r\n";
        r, out = send_cmd_telnet_add_onu_two(tn, cmd)
        time.sleep(0.3)
        # out = tn.read_very_eager().decode("utf-8",errors="ignore")
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

        resultado = alta_ont_version_three(frame, slot, port, ontid, sn, desc, sp)

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
    host=SERVER_ACS
    ):
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
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, ssl_context=("fullchain.pem","privkey.pem"),debug=True)
