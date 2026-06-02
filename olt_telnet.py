import telnetlib
import os
from dotenv import load_dotenv
import time
import socket
import re
import sqlite3
from datetime import datetime
import re
from collections import defaultdict
import json
import time
import traceback

load_dotenv()

OLT_IP = os.getenv("OLT_HOST")
OLT_PORT = os.getenv("OLT_PORT")
VLAN = os.getenv("VLAN", "100")

OLT_USER = os.getenv("OLT_USER")
OLT_PASS = os.getenv("OLT_PASS")
LINE_PROFILE = os.getenv("LINE_PROFILE", "500")
SRV_PROFILE = os.getenv("SRV_PROFILE", "500")
DATABASE = "users.db"
LINE_PROFILE_V2 = os.getenv("LINE_PROFILE_ID", "98")
SRV_PROFILE_V2 = os.getenv("SRV_PROFILE_ID", "98")
GEMPORT_TR = os.getenv("GEMPORT_TR", "1")
GEMPORT_INT = os.getenv("GEMPORT_INT", "2")
VLAN_TR = os.getenv("VLAN_TR", "99")
VLAN_INT = os.getenv("VLAN_INT", "100")
VLAN_TR_MA = os.getenv("VLAN_TR_MA", "101")
VLAN_INT_MA = os.getenv("VLAN_INT_MA", "102")

LINE_PROFILE_TRANSPARENT = os.getenv("LINE_PROFILE_TRANSPARENT", "500")
SRV_PROFILE_TRANSPARENT = os.getenv("SRV_PROFILE_TRANSPARENT", "500")

OLT_IP_MA   = os.getenv("OLT_IP_MA")
OLT_PORT_MA = os.getenv("OLT_PORT_MA", "23")
OLT_USER_MA = os.getenv("OLT_USER_MA")
OLT_PASS_MA = os.getenv("OLT_PASS_MA")

def conectar():
    try:
        print("Conectando al servidor...")
        print(OLT_IP)
        print(OLT_PORT)
    # Leer prompt de usuario
        tn = telnetlib.Telnet(OLT_IP, OLT_PORT, timeout=10)
        output = tn.read_until(b">>User name:", timeout=5).decode("ascii", errors="ignore")
        print("Servidor pide usuario.")
        if "reenter" in output.lower():
            return tn,"error", output

        tn.write(OLT_USER.encode("ascii") + b"\r\n")
        time.sleep(1)

        # Leer prompt de contraseña
        output = tn.read_until(b">>User password:", timeout=5).decode("ascii", errors="ignore")
        print("Servidor pide contraseña.")
        if "reenter" in output.lower():
            return tn, "error", output

        tn.write(OLT_PASS.encode("ascii") + b"\r\n")
        time.sleep(2)

        # Leer lo que responde después del login
        post_login = tn.read_very_eager()
        decoded = post_login.decode("ascii", errors="ignore")
        print("Respuesta post-login:")
        print(decoded)

        if "incorrect" in decoded.lower():
            return tn,"error", "Contraseña incorrecta."
        elif "reenter" in decoded.lower():
            return tn, "error", f"Demasiados intentos fallidos. { decoded }"
        elif ">" in decoded:
            # return "ok", decoded
            return tn, "exito", "login correcto." 
        else:
            return tn, "error", "No se detectó el prompt esperado."

    except Exception as e:
        return tn, "error", f"Excepción durante login: {e}"

def conectar_ma():
    try:
        print("Conectando al servidor MA...")
        print(OLT_IP_MA)
        print(OLT_PORT_MA)
        tn = telnetlib.Telnet(OLT_IP_MA, OLT_PORT_MA, timeout=10)
        output = tn.read_until(b">>User name:", timeout=5).decode("ascii", errors="ignore")
        print("Servidor pide usuario.")
        if "reenter" in output.lower():
            return tn, "error", output

        tn.write(OLT_USER_MA.encode("ascii") + b"\r\n")
        time.sleep(1)

        output = tn.read_until(b">>User password:", timeout=5).decode("ascii", errors="ignore")
        print("Servidor pide contraseña.")
        if "reenter" in output.lower():
            return tn, "error", output

        tn.write(OLT_PASS_MA.encode("ascii") + b"\r\n")
        time.sleep(2)

        post_login = tn.read_very_eager()
        decoded = post_login.decode("ascii", errors="ignore")
        print("Respuesta post-login:")
        print(decoded)

        if "incorrect" in decoded.lower():
            return tn, "error", "Contraseña incorrecta."
        elif "reenter" in decoded.lower():
            return tn, "error", f"Demasiados intentos fallidos. {decoded}"
        elif ">" in decoded:
            return tn, "exito", "login correcto."
        else:
            return tn, "error", "No se detectó el prompt esperado."

    except Exception as e:
        return tn, "error", f"Excepción durante login: {e}"

# para routers sin wifi modo transparente
def alta_ont(frame, slot, port, ontid, sn, desc, service_port):
    try:
        tipo = 'alta_onu'
        PATRON_CR = re.compile(r"{\s*<cr>.*?}", re.IGNORECASE)
        # PATRON_SP = re.compile(r"{\s*service-port.*?}", re.IGNORECASE)
        PATRON_SP = re.compile(
            r"service-port\s+(\d+)\s+vlan\s+(\d+)\s+gpon\s+(\d+/\d+/\d+)",
            re.IGNORECASE
        )

        tn,estado, resultado = conectar()
        print(estado)
        if estado == "error":
            print("Error " + tn)
            return redirect(url_for("dashboard"))
        else:
            tn.write(b"enable\n")
            tn.write(b"config\n")
            if isinstance(tn, str):
                return tn  # error de conexión


            interface_cmd = f"interface gpon {frame}/{slot}\n"
            
            add_ont_cmd = (
                f'ont add {port} {ontid} sn-auth "{sn}" omci '
                f'ont-lineprofile-id {LINE_PROFILE_TRANSPARENT} ont-srvprofile-id {SRV_PROFILE_TRANSPARENT} '
                f'desc "{desc}"'
            )

            service_cmd = (
                f'service-port {service_port} vlan {VLAN} gpon {frame}/{slot}/{port} ont {ontid} '
                f'gemport 37 multi-service user-vlan {VLAN} tag-transform transparent'
            )

            tn.write(interface_cmd.encode("ascii"))
            time.sleep(0.3)

            print("ADD ONT command:", add_ont_cmd)
            tn.write(add_ont_cmd.encode("ascii") + b"\r\n")
            time.sleep(0.5)

            out = tn.read_very_eager().decode("utf-8",errors="ignore")
            print(repr(out))

            if PATRON_CR.search(out):
                print("OLT espera ENTER, enviando...")
                tn.write(b"\r\n")
                time.sleep(0.3)

            out = tn.read_very_eager().decode("utf-8",errors="ignore")
            print(repr(out))

            PATRON_CONFLICTO = re.compile(
                r"(Failure.*?|Conflicted service virtual port index:\s*(\d+))",
                re.IGNORECASE | re.DOTALL
            )
            if "Failure: The ONT ID has already existed" in out:
                # return "existe"
                tn.close()
                return out
            elif re.search(r"PortID\s*:\s*\d+,\s*ONTID\s*:\s*\d+", out):
                tn.write(b"quit\r\n")
                time.sleep(0.5)
                tn.write(service_cmd.encode("ascii")+ b"\r\n")
                time.sleep(0.5)
                out = tn.read_very_eager().decode("utf-8",errors="ignore")
                print(repr(out))

                match = PATRON_CONFLICTO.search(out)
                if match:
                    if match.group(2):
                        # //insert en tabla
                        guardar_sqlite(out, tipo)
                        tn.close()
                        return f"⚠️ El service-port {match.group(2)} ya existe. No se pudo crear. {out}"
                    return "⚠️ Error: se detectó un conflicto al crear el service-port. {out}"

                if PATRON_SP.search(out):
                    print(f"service-port... {out}")
                    tn.write(b"\r\n")
                    time.sleep(0.3)

                    # datos = descargar_config(tn)
                    # time.sleep(0.5)
                    # if datos:
                    #     guardar_sqlite(datos,"current")
                    #     print("Datos guardados correctamente")
                    # else:
                    #     print("No se pudieron guardar los datos")

                    time.sleep(0.5)
                    # datos = consultar_potencia(tn, 0,1,0,0)    
                    # if datos:
                    #     guardar_sqlite(datos,"ont")

                    time.sleep(10)
                    tn.write(b"save\r\n")
                    time.sleep(0.3)
                    # out = tn.read_very_eager().decode("utf-8",errors="ignore")
                    # print("Salida final:\n", out)                    
                    # print(repr(out))
                    # guardar_sqlite(out, tipo)

                    tn.close()
                    return out

            output = tn.read_very_eager().decode("utf-8", errors="ignore")
            print("Salida final:\n", output)
            return output
    except Exception as e:
        return f"Error al dar de alta ONT: {e} {estado} {resultado}"

def consultar_potencia(conn, frame, slot, port, ontid):
    try:
        MORE_PROMPT = b"---- More ( Press 'Q' to break ) ----" # El patrón que buscamos (en bytes)
        MORE_PROMPT = re.compile(br"---- More \( Press 'Q' to break \) ----")
        time.sleep(3)
        
        tn = conn
        if isinstance(tn, str):
            return tn  # error de conexión
        tn.sock.settimeout(10)
        limpiar_buffer(tn)  # 🚿 limpiar cualquier residuo
        # cmd = f"display ont info summary {frame}/{slot} {port} {ontid}\n"
        cmd = f"display ont info summary {frame}/{slot}\n"
        print(cmd)

        tn.write(cmd.encode("ascii"))
        tn.write(b"\n")
        time.sleep(2)


        full_output = b"" # Para almacenar toda la salida recibida

        while True:
            # Intentamos leer hasta encontrar el patrón 'More' o cualquier otro dato
            # o hasta que se cumpla el timeout para esta operación de lectura.
            # Es crucial que el timeout aquí sea razonable para la respuesta del servidor.
            index, match, data = tn.expect([MORE_PROMPT, b"\n"], timeout=10)

            # Agrega los datos leídos al output completo
            if data:
                full_output += data
                # Opcional: imprimir una parte de la salida para depuración
                # print(f"Datos recibidos ({len(data)} bytes): {data.decode('ascii', errors='ignore')[:100]}...")

            # Si encontramos el patrón 'More'
            if index == 0:
                print(">>> Detectado '---- More ----'. Enviando 'Q'...")
                # tn.write(b"Q\n") # Envía 'Q' seguido de un salto de línea si es necesario
                tn.write(b" ")
                time.sleep(0.5) # Pequeña pausa para que el servidor procese la 'Q'
            # Si no encontramos el patrón 'More' y el índice es -1, significa timeout o EOF.
            # Si index es 1, significa que leímos un salto de línea (b"\n")
            elif index == -1:
                print(">>> No se detectó '---- More ----' en el tiempo de espera o el servidor dejó de enviar datos. Terminando.")
                break # Salimos del bucle si no hay más datos o timeout

            # Si el patrón no es "More" y el servidor sigue enviando cosas,
            # podríamos querer alguna otra condición de salida o simplemente
            # seguir leyendo hasta que ya no haya más datos o un timeout.
            # Para este ejemplo, si no es 'More' y no es timeout, asumimos que estamos fuera de paginación
            # y que el flujo de datos terminará o tendremos que buscar otro patrón.
            # Para simplificar, si no es 'More' y hay datos, y no hay más 'More' en el siguiente ciclo, se detendrá.

            # Considera también una condición de salida si full_output alcanza un tamaño excesivo
            # para evitar bucles infinitos en caso de comportamiento inesperado del servidor.
            if len(full_output) > 1024 * 1024 * 5: # Por ejemplo, si excede 5MB
                print(">>> Advertencia: Se ha alcanzado un límite de tamaño de salida. Terminando el bucle.")
                break

        # print("\n--- Salida completa del servidor ---")
        print(full_output.decode('ascii', errors='ignore')) # Decodifica y muestra toda la salida
        # print(repr(full_output))

        return full_output.decode('ascii', errors='ignore')
    except socket.timeout:
        print("Timeout occurred while reading from the server.")
    except EOFError:
        print("EOF reached before timeout.")
    except Exception as e:
        print(f"An error occurred: {e}")
    # finally:
    #     tn.close()
    # except Exception as e:
    #     return f"Error al consultar potencia: {e}"

def descargar_config(conn):
    try:
        MORE_PROMPT = b"---- More ( Press 'Q' to break ) ----" # El patrón que buscamos (en bytes)
        MORE_PROMPT = re.compile(br"---- More \( Press 'Q' to break \) ----")
        time.sleep(2)
        
        tn = conn 
        if isinstance(tn, str):
            return tn  # error de conexión
        tn.sock.settimeout(10)
        limpiar_buffer(tn)  # 🚿 limpiar cualquier residuo
        # cmd = f"display ont info summary {frame}/{slot} {port} {ontid}\n"
        cmd = f"display current-configuration\n"
        print(cmd)

        tn.write(cmd.encode("ascii"))
        tn.write(b"\n")
        time.sleep(2)


        full_output = b"" # Para almacenar toda la salida recibida

        while True:
            # Intentamos leer hasta encontrar el patrón 'More' o cualquier otro dato
            # o hasta que se cumpla el timeout para esta operación de lectura.
            # Es crucial que el timeout aquí sea razonable para la respuesta del servidor.
            index, match, data = tn.expect([MORE_PROMPT, b"\n"], timeout=10)

            # Agrega los datos leídos al output completo
            if data:
                full_output += data
                # Opcional: imprimir una parte de la salida para depuración
                # print(f"Datos recibidos ({len(data)} bytes): {data.decode('ascii', errors='ignore')[:100]}...")
                
            # Si encontramos el patrón 'More'
            if index == 0:
                print(">>> Detectado '---- More ----'. Enviando 'Q'...")
                # tn.write(b"Q\n") # Envía 'Q' seguido de un salto de línea si es necesario
                tn.write(b" ")
                time.sleep(0.5) # Pequeña pausa para que el servidor procese la 'Q'
            # Si no encontramos el patrón 'More' y el índice es -1, significa timeout o EOF.
            # Si index es 1, significa que leímos un salto de línea (b"\n")
            elif index == -1:
                print(">>> No se detectó '---- More ----' en el tiempo de espera o el servidor dejó de enviar datos. Terminando.")
                break # Salimos del bucle si no hay más datos o timeout

            # Si el patrón no es "More" y el servidor sigue enviando cosas,
            # podríamos querer alguna otra condición de salida o simplemente
            # seguir leyendo hasta que ya no haya más datos o un timeout.
            # Para este ejemplo, si no es 'More' y no es timeout, asumimos que estamos fuera de paginación
            # y que el flujo de datos terminará o tendremos que buscar otro patrón.
            # Para simplificar, si no es 'More' y hay datos, y no hay más 'More' en el siguiente ciclo, se detendrá.

            # Considera también una condición de salida si full_output alcanza un tamaño excesivo
            # para evitar bucles infinitos en caso de comportamiento inesperado del servidor.
            if len(full_output) > 1024 * 1024 * 5: # Por ejemplo, si excede 5MB
                print(">>> Advertencia: Se ha alcanzado un límite de tamaño de salida. Terminando el bucle.")
                break

        # print("\n--- Salida completa del servidor ---")
        # print(full_output.decode('ascii', errors='ignore')) # Decodifica y muestra toda la salida
        # print(repr(full_output))

        return full_output.decode("utf-8", errors='ignore')
    except socket.timeout:
        print("Timeout occurred while reading from the server.")
    except EOFError:
        print("EOF reached before timeout.")
    except Exception as e:
        print(f"An error occurred: {e}")
    # finally:
    #     tn.close()

def guardar_sqlite(output, tipo):
    
    if output:
        texto = output
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("""
            INSERT INTO configuration (fecha, datos, tipo)
            VALUES(?,?,?)
        """, (timestamp, texto, tipo))

        conn.commit()
        conn.close()
        return True
    return false
def limpiar_buffer(tn):
    """Limpia el buffer del Telnet leyendo todo lo que haya pendiente."""
    while True:
        data = tn.read_very_eager()
        if not data:
            break

def parse_ont_info(texto):
    puertos = defaultdict(dict)
    current_port = None
    parsing_ont_info = False
    parsing_ont_detail = False
    errores = []

    PATRON_SERVICE_PORT = re.compile(
        r"service-port\s+(\d+)\s+vlan\s+\d+\s+gpon\s+(\d+/\d+/\d+)\s+ont\s+(\d+)",
        re.IGNORECASE
    )

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT datos, id FROM configuration where tipo = 'current' ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    conn.close()

    current = row[0] if row else ""
    # Extraer service-ports
    
    ont_service_map = {}  # clave: (puerto, ont_id), valor: sp_num
    for match in PATRON_SERVICE_PORT.finditer(current):
        sp_num = int(match.group(1))
        port = match.group(2)
        ont_id = int(match.group(3))
        ont_service_map[(port, ont_id)] = sp_num

    lines = texto.splitlines()
    for line in lines:
        original_line = line
        line = line.strip()

        match_port = re.match(r"In port (\d+/\d+/\d+),", line)
        if match_port:
            current_port = match_port.group(1)
            continue

        if re.match(r"ONT\s+Run\s+Last", line):
            parsing_ont_info = True
            parsing_ont_detail = False
            continue

        if re.match(r"ONT\s+SN\s+Type\s+Distance", line):
            parsing_ont_info = False
            parsing_ont_detail = True
            continue

        if re.match(r"^-+$", line) or not current_port:
            continue

        if parsing_ont_info and re.match(r"\d+\s+\w+", line):
            partes = line.split()
            if partes[0].isdigit():

                ont_id = int(partes[0])
                sp_num = ont_service_map.get((current_port, ont_id))
                # Si existe la clave y el subcampo, se concatena; si no, solo se usa la nueva línea
                if current_port in puertos and ont_id in puertos[current_port] and "line" in puertos[current_port][ont_id]:
                    linea_concatenada = puertos[current_port][ont_id]["line"] + " " + line
                else:
                    linea_concatenada = line

                puertos[current_port][ont_id] = {
                    "ont_id": ont_id,
                    "state": partes[1],
                    "uptime": partes[2] + " " + partes[3] if partes[2] != "-" else "-",
                    "downtime": partes[4] + " " + partes[5] if partes[4] != "-" else "-",
                    "down_cause": " ".join(partes[6:]) if len(partes) > 6 else "-",
                    "has_service_port": sp_num is not None,
                    "service_port_num": sp_num,
                    "editar_url": f"/editar/{current_port}/{ont_id}",
                    "borrar_ont": f"/borrar_ont/{current_port}/{ont_id}",
                    "borrar_sp": f"/borrar_sp/{sp_num}",
                    "line": linea_concatenada
                }
            else:
                errores.append(f"[ONT INFO] Línea ignorada: {original_line}")

        elif parsing_ont_detail and re.match(r"\d+\s+[A-F0-9]+", line):
            # print(f"line: {line}")
            # print(f"current: {partes}")

            partes = line.split()
            if partes[0].isdigit():
                ont_id = int(partes[0])
                if ont_id in puertos[current_port]:
                    # linea_concatenada = puertos[current_port][ont_id]["line"] + " " + line
                    # Si existe la clave y el subcampo, se concatena; si no, solo se usa la nueva línea
                    if current_port in puertos and ont_id in puertos[current_port] and "line" in puertos[current_port][ont_id]:
                        linea_concatenada = puertos[current_port][ont_id]["line"] + " " + line
                    else:
                        linea_concatenada = line

                    puertos[current_port][ont_id].update({
                        "sn": partes[1],
                        "type": partes[2],
                        "distance": partes[3],
                        "rx_tx": partes[4],
                        "description": " ".join(partes[5:]) if len(partes) > 5 else "",
                        "line": linea_concatenada
                    })
                else:
                    errores.append(f"[DETALLE] ID {ont_id} no está en sección anterior → {original_line}")
            else:
                errores.append(f"[DETALLE] Línea ignorada: {original_line}")

    return puertos, errores


def obtener_ultimo_config(db_path="users.db"):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT datos FROM configuration where tipo = 'ont' ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def limpiar_salida_olt(texto):
    texto = re.sub(r"---- More \( Press 'Q' to break \) ----", "", texto)
    texto = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", texto)  # códigos ANSI
    texto = re.sub(r" {2,}", " ", texto)
    return texto

def extraer_service_ports(texto):
    """
    Extrae todos los comandos 'service-port' de la configuración.
    """
    # Limpiar secuencias de escape y paginación
    texto = re.sub(r"---- More \( Press 'Q' to break \) ----", "", texto)
    texto = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", texto)

    # Buscar todos los bloques service-port completos (pueden ser multilinea)
    bloques = re.findall(
        r"(service-port \d+ vlan \d+ gpon \d+/\d+/\d+ ont \d+ gemport \d+ multi-service user-vlan\s*\d+ tag-transform \w+)",
        texto.replace('\n', ' '),
        re.IGNORECASE
    )

    return bloques

def delete_sp(sp):
    tn,estado, resultado = conectar()
    print(estado)
    if estado == "error":
        print("Error " + tn)
        return "Conexion cerrada"
    else:
        tn.write(b"enable\n")
        tn.write(b"config\n")
        if isinstance(tn, str):
            return tn  # error de conexión

        # interface_cmd = f"undo service-port {sp}\r\n"
        # time.sleep(0.3)
        # tn.write(interface_cmd.encode("ascii"))
        # time.sleep(1)
        # print(interface_cmd)
        # out = tn.read_very_eager().decode("utf-8",errors="ignore")
        
        # print(repr(out))

        # texto = "Service virtual port does not exist"
        # PATRON_ERROR_SP = re.compile(
        #     r"(Failure.*?|Service virtual port does not exist(?:\s+(\d+))?)",
        #     re.IGNORECASE | re.DOTALL
        # )
        # match = PATRON_ERROR_SP.search(out)
        # if match:
        #     print("✅ Detectado:", match.group(0))
        #     tn.close()
        #     return texto

        res,txt = undo_service_port(tn, sp)

        if res == True:
           tn.close()
           conn = sqlite3.connect(DATABASE)    
           c = conn.cursor()
           c.execute("UPDATE service_ports set deleted = 1 WHERE service_port = ?", (sp,))
           conn.commit()
           conn.close()

           return txt
        

        
        # datos = descargar_config(tn)
        # time.sleep(0.5)
        # if datos:
        #     guardar_sqlite(datos,"current")
        #     print("Datos guardados correctamente")
        # else:
        #     print("No se pudieron guardar los datos")

        # time.sleep(0.5)
        # datos = consultar_potencia(tn, 0,1,0,0)    
        # if datos:
        #     guardar_sqlite(datos,"ont")

        # time.sleep(10)
        # tn.write(b"save\r\n")
        # time.sleep(0.3)
        # out = tn.read_very_eager().decode("utf-8",errors="ignore")
        # print("Salida final:\n", out)                    
        # print(repr(out))
        # guardar_sqlite(out, 'delete_sp')

        tn.close()
        return txt
        
def undo_service_port(tn, sp):
    interface_cmd = f"undo service-port {sp}\r\n"
    time.sleep(0.3)
    tn.write(interface_cmd.encode("ascii"))
    time.sleep(1)
    print(interface_cmd)
    out = tn.read_very_eager().decode("utf-8",errors="ignore")
    
    print(repr(out))

    texto = "Service virtual port does not exist"
    PATRON_ERROR_SP = re.compile(
        r"(Failure.*?|Service virtual port does not exist(?:\s+(\d+))?)",
        re.IGNORECASE | re.DOTALL
    )
    match = PATRON_ERROR_SP.search(out)
    if match:
        print("✅ Detectado:", match.group(0))
        tn.close()
        return False,texto
    
    return True,out
        
def delete_only_str(tn,frame, slot, port, ontid):
    interface_cmd = f"interface gpon {frame}/{slot}\r\n"
    # time.sleep(0.3)
    tn.write(interface_cmd.encode("ascii"))
    time.sleep(1)
    print(interface_cmd)
    # out = tn.read_very_eager().decode("utf-8",errors="ignore")
    
    # print(repr(out))

    interface_cmd = f"ont delete {port} {ontid}\r\n"
    # time.sleep(0.3)
    tn.write(interface_cmd.encode("ascii"))
    time.sleep(1)
    print(interface_cmd)
    out = tn.read_very_eager().decode("utf-8",errors="ignore")
    
    print(repr(out))

    texto = "Service virtual port does not exist"
    PATRON_ERROR_SP = re.compile(
        r"""(
            Failure:\s+The\s+ONT\s+does\s+not\s+exist|
            Parameter\s+error.*?locates\s+at|
            Failure:.*?service\s+virtual\s+ports
        )""",
        re.IGNORECASE | re.DOTALL | re.VERBOSE
    )

    match = PATRON_ERROR_SP.search(out)
    if match:
        print("✅ Detectado error crítico:", match.group(0))
        tn.close()
        return False,match.group(0)

    
    return True,out

def delete_ont_sp():
    tn,estado, resultado = conectar()
    print(estado)
    if estado == "error":
        print("Error " + tn)
        return "Conexion cerrada"
    else:
        tn.write(b"enable\n")
        tn.write(b"config\n")
        if isinstance(tn, str):
            return tn  # error de conexión
        res,text = undo_service_port(tn)

        if res == True:
            #to do insertar en base de datos que se borro el service port
           tn.close()
           return txt
        else:
            print('delete ont')

def delete_ont_cont(frame, slot, port, ontid):
    tn,estado, resultado = conectar()
    print(estado)
    if estado == "error":
        print("Error " + tn)
        return "Conexion cerrada"
    else:
        tn.write(b"enable\n")
        tn.write(b"config\n")
        if isinstance(tn, str):
            return tn  # error de conexión
        
        result,txt = delete_only_str(tn,frame, slot, port, ontid)
        if(result == True):
            tn.close()
            conn = sqlite3.connect(DATABASE)    
            c = conn.cursor()
            c.execute("UPDATE onus set deleted = 1 WHERE card_id = ? AND slot_id = ? AND port_id = ? AND ont_id = ?", (frame, slot, port, ontid))
            conn.commit()
            conn.close()

    return result,txt     

def guardar_tabla():
    raw_text = obtener_ultimo_config()
    texto_limpio = limpiar_salida_olt(raw_text)
    datos_por_puerto, errores = parse_ont_info(texto_limpio)
    conn = None
    if conn is None:
        # conn = sqlite3.connect("mi_base.db", timeout=10)
        conn = sqlite3.connect(DATABASE)
    
    
    i=1
    c = conn.cursor()
    c.execute("UPDATE onus SET deleted = 1 ")
    for puerto, onts in datos_por_puerto.items():
        # print('------------------------------------------------------------------------')
        
        valores = [line.split('/') for line in puerto.strip().splitlines()]
        valor = [[int(x) for x in linea] for linea in valores]
        # for grupo in valor:
        # print(valor[0][0], valor[0][1], valor[0][2])
        card_id = valor[0][0]
        slot_id = valor[0][1]
        port_id = valor[0][2]
        # print(card_id, slot_id, port_id)
        # print('card_id:', card_id, 'slot_id:', slot_id, 'port_id:', port_id)
        # print(grupo)
        for ont in onts.values():
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
            # print(ont_id, state, uptime, downtime, down_cause, sn, type, distance, rx_tx, description, service_port_num)
            # "has_service_port": sp_num is not None,

            # Verificar si ya existe
            c.execute("""
                SELECT * FROM onus WHERE card_id=? AND slot_id=? AND port_id=? AND ont_id=?
            """, (card_id, slot_id, port_id, ont_id))

            row = c.fetchone()

            if row:
                # Ya existe, actualiza
                print('Ya existe, actualiza')
                print(ont_id, state, uptime, downtime, down_cause, sn, type, distance, rx_tx, description, service_port_num, cmd_json)
                c.execute("""
                    UPDATE onus
                    SET deleted=0, state=?, uptime=?, downtime=?, cause=?, SN=?, type=?, distance=?, rx_tx=?, description=?, sp=?, cmd=?, cadena=?
                    WHERE card_id=? AND slot_id=? AND port_id=? AND ont_id=?
                """, (state, uptime, downtime, down_cause, sn, type, distance, rx_tx, description, service_port_num, cmd_json, line,
                    card_id, slot_id, port_id, ont_id))
            else:
                # No existe, inserta
                print('No existe, inserta')
                c.execute("""
                    INSERT INTO onus (card_id, slot_id, port_id, ont_id, state, uptime, downtime, cause, SN, type, distance, rx_tx, description, sp, cmd, deleted, cadena, olt)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 'EA')
                """, (card_id, slot_id, port_id, ont_id, state, uptime, downtime, down_cause, sn, type, distance, rx_tx, description, service_port_num, cmd_json, line))

    
        print('-------------------------------------F I N-----------------------------------')
    conn.commit()
    conn.close()

        # Regex para extraer los campos clave
    pattern = re.compile(r"service-port (\d+)\s+vlan (\d+)\s+gpon (\d+)/(\d+)/(\d+)\s+ont (\d+)")

    # Conexión a SQLite (archivo local)
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Crear tabla si no existe
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS service_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_port INTEGER,
            vlan INTEGER,
            card_id INTEGER,
            slot_id INTEGER,
            port_id INTEGER,
            ont INTEGER,
            ont_id INTEGER,
            cadena TEXT,
            deleted INTEGER DEFAULT 0
        )
    """)
    cursor.execute("UPDATE service_ports SET deleted = 1 ")
    c = conn.cursor()
    c.execute("SELECT datos, id FROM configuration where tipo = 'current' ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    # conn.close()

    texto = row[0] if row else ""
    service_ports = extraer_service_ports(texto)
    lines = service_ports
    # Insertar datos
    for line in lines:
        match = pattern.search(line)
        if match:
            service_port, vlan, card_id, slot_id, port_id, ont_id = match.groups()
            
            # Buscar si ya existe el registro
            cursor.execute("""
                SELECT id FROM service_ports 
                WHERE card_id=? AND slot_id=? AND port_id=? AND ont_id=? AND service_port=?
            """, (card_id, slot_id, port_id, ont_id, service_port))
            
            row = cursor.fetchone()
            if row:
                print(row[0])
                print(f"DEBUG types: service_port={(service_port)}") 
                print(f"DEBUG types: vlan={(vlan)}") 
                print(f"DEBUG types:ont={(ont_id)}") 
                print(f"DEBUG types:line={(line)}") 

                # print(f"DEBUG types: service_port={type(service_port)}, vlan={type(vlan)}, ont={type(ont)}, line={type(line)}, record_id={type(record_id)}")

                # Si ya existe: actualiza
                record_id = int(row[0])
                print(f"DEBUG types:record_id={(record_id)}")
                cursor.execute("""
                    UPDATE service_ports
                    SET service_port=?, vlan=?, ont_id=?, cadena=?, deleted=0
                    WHERE id=?
                """, (
                    int(service_port),
                    int(vlan),
                    int(ont_id),
                    line,
                    int(record_id)
                ))
                print(f"Actualizado registro ID {record_id}")
            else:
                # Si no existe: inserta
                cursor.execute("""
                    INSERT INTO service_ports (
                        service_port, vlan, card_id, slot_id, port_id,
                        ont_id, cadena, deleted, olt
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'EA')
                """, (
                    int(service_port),
                    int(vlan),
                    int(card_id),
                    int(slot_id),
                    int(port_id),
                    int(ont_id),
                    line
                ))
                print("Insertado nuevo registro")

    # Guardar e imprimir confirmación
    conn.commit()
    print("Datos insertados correctamente.")
    
    # Opcional: ver registros
    # for row in cursor.execute("SELECT * FROM service_ports"):
    #     print(row)
    # --------------------------------------------- o n u   c o n f i g ---------------------------------------------
    c = conn.cursor()
    c.execute("SELECT datos, id FROM configuration where tipo = 'current' ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    # conn.close()

    raw_text = row[0] if row else ""
    texto_limpio = limpiar_salida_olt(raw_text)
    resultado = extraer_onus(texto_limpio)
    for onu in resultado:
        # print(f"ONT ID: {onu['ont_id']}, SN: {onu['sn']}")
        # print(f"TEXTO:\n{onu['texto']}\n")
        # Verificar si ya existe
        c.execute("""
            SELECT * FROM onus WHERE SN=? 
        """, (
            onu['sn'],
        ))

        row = c.fetchone()

        if row:
            # Ya existe, actualiza
            #print('Ya existe, actualiza')
            #print(ont_id, state, uptime, downtime, down_cause, sn, type, distance, rx_tx, description, service_port_num, cmd_json)
            c.execute("""
                UPDATE onus
                SET config=?
                WHERE SN=?
            """, ( onu['texto'], onu['sn'],
            ))
    conn.commit()
    conn.close()

    return True

def get_potencia():

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("select *, (select GROUP_CONCAT(service_port) from service_ports sp  where sp.card_id = onus.card_id  and sp.slot_id = onus.slot_id  and sp.port_id = onus.port_id  and sp.ont_id = onus.ont_id and sp.deleted = 0) service_ports  from onus  where onus.deleted = 0 limit 512")
    rowc = c.fetchall()
    conn.close()

    return rowc


def alta_ont_versiontwo(frame, slot, port, ontid, sn, desc, service_port):
    try:
        tipo = 'alta_onu_version_two'
        PATRON_CR = re.compile(r"{\s*<cr>.*?}", re.IGNORECASE)
        

        tn,estado, resultado = conectar()
        # print(estado)
        if estado == "error":
            print("Error " + tn)
            return redirect(url_for("dashboard"))
        else:
            tn.write(b"enable\n")
            tn.write(b"config\n")
            if isinstance(tn, str):
                return tn  # error de conexión


            interface_cmd = f"interface gpon {frame}/{slot}\n"
            
            add_ont_cmd = (
                f'ont add {port} {ontid} sn-auth "{sn}" omci '
                f'ont-lineprofile-id {LINE_PROFILE_V2} ont-srvprofile-id {SRV_PROFILE_V2} '
                f'desc "{desc}"'
            )

            add_ont_cmd_two = (
                f'ont ipconfig {port} {ontid} dhcp'
                f' vlan {VLAN_TR} priority 5'                
            )

            add_ont_cmd_three = (
                f'ont tr069-server-config {port} {ontid} profile-id 1'
            )
            # ont add 2 63 sn-auth "48575443AEC042AF" omci ont-lineprofile-id 98 ont-srvprofile-id 98 desc "Test Mixto" 
            # ont ipconfig 2 63 dhcp vlan 99 priority 5
            # ont tr069-server-config 2 63 profile-id 1

            # PATRON_SP = re.compile(r"{\s*service-port.*?}", re.IGNORECASE)
            PATRON_SP = re.compile(
                r"service-port\s+(\d+)\s+vlan\s+(\d+)\s+gpon\s+(\d+/\d+/\d+)",
                re.IGNORECASE
            )

            service_cmd = (
                f'service-port {service_port} vlan {VLAN_INT}  '
                f'gpon {frame}/{slot}/{port} ont {ontid} '
                f'gemport {GEMPORT_INT} multi-service user-vlan {VLAN_INT} tag-transform translate'
            )
            # convertir a numero
            service_port = int(service_port) + 1
            service_cmd_two = (
                f'service-port {service_port} vlan {VLAN_TR} gpon {frame}/{slot}/{port} ont {ontid} '
                f'gemport {GEMPORT_TR} multi-service user-vlan {VLAN_TR} tag-transform translate'
            )


            # service-port 1000 vlan 99 gpon 0/0/0 ont 1 gemport 1 multi-service user-vlan 99
            # service-port 1001 vlan 100 gpon 0/0/0 ont 1 gemport 2 multi-service user-vlan 100

            # interface gpon 1/1 ----------------------------------------------------
            tn.write(interface_cmd.encode("ascii"))
            time.sleep(0.3)
            # add ont -------------------------------------------------------------------
            # print("ADD ONT command----------------------------------------------------:", add_ont_cmd)
            tn.write(add_ont_cmd.encode("ascii") + b"\r\n")
            time.sleep(0.5)

            out = tn.read_very_eager().decode("utf-8",errors="ignore")
            # print(repr(out))

            if PATRON_CR.search(out):
                # print("OLT espera ENTER, enviando...")
                tn.write(b"\r\n")
                time.sleep(0.3)

                out = tn.read_very_eager().decode("utf-8",errors="ignore")
                # print(repr(out))

                PATRON_CONFLICTO = re.compile(
                    r"(Failure.*?|Conflicted service virtual port index:\s*(\d+))",
                    re.IGNORECASE | re.DOTALL
                )
                if "Failure: The ONT ID has already existed" in out:
                    # return "existe"
                    tn.close()
                    # print("-----------------------------------------------existe " + out)
                    return out
                elif "Failure: SN already exists" in out:
                    # return "existe"
                    tn.close()
                    # print("-----------------------------------------------existe " + out)
                    return out
                elif re.search(r"PortID\s*:\s*\d+,\s*ONTID\s*:\s*\d+", out):
                    # ----------------------comando dos ----------------------------
                    PATRON_fail = re.compile(
                        r"(failure|error|Conflicted service virtual port index:\s*(\d+))",
                        re.IGNORECASE
                    )
                    # print("ADD ONT command--------------------------------:", add_ont_cmd_two)
                    tn.write(add_ont_cmd_two.encode("ascii") + b"\r\n")
                    time.sleep(0.1)
                    out = tn.read_very_eager().decode("utf-8",errors="ignore")
                    # print(repr(out))

                    if PATRON_fail.search(out):
                        print(f"error: {out}")
                        tn.close()
                        # return f"⚠️ El service-port {match.group(2)} ya existe. No se pudo crear. {out}"
                        return "⚠️ Error: se detectó un conflicto . {out}"
                    else:
                        # ---------------------------comando tres ----------------------------
                        # print("ADD ONT command tres--------------------------------:", add_ont_cmd_three)
                        tn.write(add_ont_cmd_three.encode("ascii") + b"\r\n")
                        time.sleep(0.1)
                        out = tn.read_very_eager().decode("utf-8",errors="ignore")
                        time.sleep(3)
                        


                        match = PATRON_fail.search(out)
                        if PATRON_fail.search(out):
                            print(f"error: {out}")
                            tn.close()
                            # return f"⚠️ El service-port {match.group(2)} ya existe. No se pudo crear. {out}"
                            return "⚠️ Error: se detectó un conflicto . {out}"
                        else:
                            # ---------------------------comando cuarto ----------------------------
                            # print("out --------------------------------:", out)
                            #service port ------------------------------------------------------
                            tn.write(b"quit\r\n")
                            time.sleep(0.1)
                            out = tn.read_very_eager().decode("utf-8",errors="ignore")                            
                            # print((out))
                            if "quit" in out:
                                print(f"quit found : {out}")
                                
                                # print("-----------------------------------------------existe " + out)                            
                                print("service-port command-----------------------------------------:", service_cmd)
                                time.sleep(0.1)
                                tn.write(service_cmd.encode("ascii")+ b"\r\n") #
                                # tn.write(b"\r\n")
                                time.sleep(1.5)
                                out = tn.read_very_eager().decode("utf-8")                            
                                print(repr(out))
                                if PATRON_CR.search(out):
                                    print("OLT espera ENTER, enviando...")
                                    tn.write(b"\r\n")
                                    time.sleep(0.3)

                                    out = tn.read_very_eager().decode("utf-8",errors="ignore")
                                    print(repr(out))                                                               
                                    if(PATRON_fail.search(out)):
                                        print(f"error: {out}")
                                        tn.close()
                                        return f"⚠️ El service-port. No se pudo crear. {out}"                        
                                    else:
                                        print(f"else ................................................... {out}")
                                        tn.write(service_cmd_two.encode("ascii")+ b"\r\n") #
                                        # tn.write(b"\r\n")
                                        time.sleep(1.5)
                                        out = tn.read_very_eager().decode("utf-8")                            
                                        print(repr(out))

                                        if PATRON_CR.search(out):
                                            print("OLT espera ENTER, enviando...")
                                            tn.write(b"\r\n")
                                            time.sleep(0.3)

                                            out = tn.read_very_eager().decode("utf-8",errors="ignore")
                                            print(repr(out))                                                               
                                            if(PATRON_fail.search(out)):
                                                print(f"error: {out}")
                                                tn.close()
                                                return f"⚠️ El service-port. No se pudo crear. {out}"                        
                                            else:
                                                print(f"else ................................................... {out}")
                                                tn.close()
                                                return out
                            

                                # datos = descargar_config(tn)
                                # time.sleep(0.5)
                                # if datos:
                                    # guardar_sqlite(datos,"current")
                                    # print("Datos guardados correctamente")
                                # else:
                                #     print("No se pudieron guardar los datos")

                                #     time.sleep(0.5)
                            # datos = consultar_potencia(tn, 0,1,0,0)    
                            # if datos:
                            #     guardar_sqlite(datos,"ont")

                                # time.sleep(10)
                                # tn.write(b"save\r\n")
                                # time.sleep(0.3)
                                # out = tn.read_very_eager().decode("utf-8",errors="ignore")
                                # print("Salida final:\n", out)                    
                                # print(repr(out))
                                # # guardar_sqlite(out, tipo)

                                # tn.close()
                                # return out

            # output = tn.read_very_eager().decode("utf-8", errors="ignore")
            # print("Salida final:\n", output)
            # return output
    except Exception as e:
        print("Error:", e.with_traceback())
        tn.close()
        return f"Error al dar de alta ONT: {e} {estado} {resultado}"

def extraer_onus(texto):
    onus = []
    bloques = []
    bloque_actual = []

    # Separar líneas, eliminando vacías
    lineas = [line.strip() for line in texto.strip().splitlines() if line.strip()]

    # Palabras clave que indican fin de sección válida de ONTs
    fin_seccion = [ "[platform-config]", "<platform-config>"]

    for linea in lineas:
        if any(linea.startswith(fin) for fin in fin_seccion):
            break  # termina el procesamiento al detectar la siguiente sección

        if re.match(r"^ont add \d+ \d+", linea):  # nueva ONU
            if bloque_actual:
                bloques.append(bloque_actual)
            bloque_actual = [linea]
        else:
            bloque_actual.append(linea)

    if bloque_actual:
        bloques.append(bloque_actual)

    for bloque in bloques:
        texto_bloque = " ".join(bloque)
        match = re.search(r"ont add (\d+) (\d+).*?sn-auth \"([A-F0-9]+)\"", texto_bloque)
        if match:
            frame, slot, sn = match.groups()
            ont_id = int(slot)
            onus.append({
                "ont_id": ont_id,
                "sn": sn,
                "texto": texto_bloque
            })

    return onus

def extraer_onus_2(texto):
    onus = []
    bloques = []
    bloque_actual = []
    
    # Separar el texto por líneas, eliminando vacíos
    lineas = [line.strip() for line in texto.strip().splitlines() if line.strip()]

    for linea in lineas:
        if re.match(r"^ont add \d+ \d+", linea):  # Inicio de una nueva ONU
            if bloque_actual:
                bloques.append(bloque_actual)
            bloque_actual = [linea]
        else:
            bloque_actual.append(linea)

    if bloque_actual:
        bloques.append(bloque_actual)

    # Procesar cada bloque
    for bloque in bloques:
        texto_bloque = " ".join(bloque)
        match = re.search(r"ont add (\d+) (\d+).*?sn-auth \"([A-F0-9]+)\"", texto_bloque)
        if match:
            frame, slot, sn = match.groups()
            ont_id = int(slot)
            onus.append({
                "ont_id": ont_id,
                "sn": sn,
                "texto": texto_bloque
            })

    return onus


def delete_ont_db(sn):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("UPDATE onus SET deleted = 1 WHERE SN = ?", (sn,))
    conn.commit()
    conn.close()

def buscar_sp_ont_sn(sn):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("""select sp.service_port 
        from onus 
        join service_ports sp  on sp.card_id = onus.card_id  and sp.slot_id = onus.slot_id  and sp.port_id = onus.port_id  and sp.ont_id = onus.ont_id AND  sp.deleted = 0
        where onus.deleted = 0 and  SN  = ? 
    """, (sn,))
    sp = c.fetchall()
    conn.close()
    return sp
def delete_ont_sn(sn):
    items = buscar_sp_ont_sn(sn)
    print("items:", items)
    if items:
        for sp in items:
            print("borrar_sp_ont_sn:", sp[0])
            delete_sp(sp[0])
            time.sleep(0.5)

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT card_id, slot_id, port_id, ont_id  FROM onus where SN = ? and deleted = 0 ORDER BY id DESC LIMIT 1" , (sn,))
        row = c.fetchone()
        conn.close()

            # delete_ont_db(sn)
        if row:
            card_id, slot_id, port_id, ont_id = row
            result, texto = delete_ont_cont(card_id, slot_id, port_id, ont_id)
            return result, texto

def delete_sp_ma(sp):
    tn, estado, resultado = conectar_ma()
    print(estado)
    if estado == "error":
        print("Error " + tn)
        return "Conexion cerrada"
    else:
        tn.write(b"enable\n")
        tn.write(b"config\n")
        if isinstance(tn, str):
            return tn

        res, txt = undo_service_port(tn, sp)

        if res == True:
            tn.close()
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute("UPDATE service_ports set deleted = 1 WHERE service_port = ?", (sp,))
            conn.commit()
            conn.close()
            return txt

        tn.close()
        return txt

def delete_ont_cont_ma(frame, slot, port, ontid):
    tn, estado, resultado = conectar_ma()
    print(estado)
    if estado == "error":
        print("Error " + tn)
        return "Conexion cerrada"
    else:
        tn.write(b"enable\n")
        tn.write(b"config\n")
        if isinstance(tn, str):
            return tn

        result, txt = delete_only_str(tn, frame, slot, port, ontid)
        if result == True:
            tn.close()
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute("UPDATE onus set deleted = 1 WHERE card_id = ? AND slot_id = ? AND port_id = ? AND ont_id = ?", (frame, slot, port, ontid))
            conn.commit()
            conn.close()

    return result, txt

def delete_ont_sn_ma(sn):
    items = buscar_sp_ont_sn(sn)
    print("items:", items)
    if items:
        for sp in items:
            print("borrar_sp_ont_sn MA:", sp[0])
            delete_sp_ma(sp[0])
            time.sleep(0.5)

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT card_id, slot_id, port_id, ont_id FROM onus where SN = ? and deleted = 0 ORDER BY id DESC LIMIT 1", (sn,))
        row = c.fetchone()
        conn.close()

        if row:
            card_id, slot_id, port_id, ont_id = row
            result, texto = delete_ont_cont_ma(card_id, slot_id, port_id, ont_id)
            return result, texto

def send_cmd_telnet_add_onu(tn,cmd):
    tn.write(cmd.encode("ascii") + b"\r\n")
    time.sleep(2)

    out = tn.read_very_eager().decode("utf-8",errors="ignore")
    print(repr(out))
    PATRON_CR = re.compile(r"{\s*<cr>.*?}", re.IGNORECASE)
    if PATRON_CR.search(out):
        # print("OLT espera ENTER, enviando...")
        tn.write(b"\r\n")
        time.sleep(0.9)

        out = tn.read_very_eager().decode("utf-8",errors="ignore")
        # print(repr(out))

        if "Failure: The ONT ID has already existed" in out:
            # return "existe"
            tn.close()
            # print("-----------------------------------------------existe " + out)
            return False, out
        elif "Failure: SN already exists" in out:
            # return "existe"
            tn.close()
            # print("-----------------------------------------------existe " + out)
            return False, out
        elif re.search(r"PortID\s*:\s*\d+,\s*ONTID\s*:\s*\d+", out):
            return True, out


def send_cmd_telnet_add_onu_two(tn,cmd):
    tn.write(cmd.encode("ascii") + b"\r\n")
    time.sleep(0.5)
    out = tn.read_very_eager().decode("utf-8",errors="ignore")
    # print(repr(out))
    PATRON_fail = re.compile(
        r"(failure|error|Conflicted service virtual port index:\s*(\d+))",
        re.IGNORECASE
    )
    PATRON_CR = re.compile(r"{\s*<cr>.*?}", re.IGNORECASE)

    if PATRON_fail.search(out):
        print(f"error: {out}")
        tn.close()
        # return f"⚠️ El service-port {match.group(2)} ya existe. No se pudo crear. {out}"
        return False, f"⚠️ Error: se detectó un conflicto . {out}"
    elif PATRON_CR.search(out):
        print("OLT espera ENTER, enviando...")
        tn.write(b"\r\n")
        time.sleep(0.3)

        out = tn.read_very_eager().decode("utf-8",errors="ignore")
        print(repr(out))                                                               
        if(PATRON_fail.search(out)):
            print(f"error: {out}")
            tn.close()
            return False , f"⚠️ El service-port. No se pudo crear. {out}"                        
        else:
            print(f"success: {out}")
            return True, out
    else:
        print(f"success: {out}")
        return True, out
 
def alta_ont_version_three(frame, slot, port, ontid, sn, desc, service_port):
    try:
        tipo = 'alta_onu_version_three'
        PATRON_CR = re.compile(r"{\s*<cr>.*?}", re.IGNORECASE)
        
        tn,estado, resultado = conectar()
        print(estado)
        if estado == "error":
            print("Error ")
            return redirect(url_for("dashboard"))
        else:
            tn.write(b"enable\n")
            tn.write(b"config\n")
            print("config")
            if isinstance(tn, str):
                return tn  # error de conexión


            interface_cmd = f"interface gpon {frame}/{slot}\n"
            
            add_ont_cmd = (
                f'ont add {port} {ontid} sn-auth "{sn}" omci '
                f'ont-lineprofile-id {LINE_PROFILE_V2} ont-srvprofile-id {SRV_PROFILE_V2} '
                f'desc "{desc}"'
            )

            add_ont_cmd_two = (
                f'ont ipconfig {port} {ontid} dhcp'
                f' vlan {VLAN_TR} priority 5'                
            )

            add_ont_cmd_three = (
                f'ont tr069-server-config {port} {ontid} profile-id 1'
            )
            PATRON_SP = re.compile(
                r"service-port\s+(\d+)\s+vlan\s+(\d+)\s+gpon\s+(\d+/\d+/\d+)",
                re.IGNORECASE
            )

            service_cmd = (
                f'service-port {service_port} vlan {VLAN_INT}  '
                f'gpon {frame}/{slot}/{port} ont {ontid} '
                f'gemport {GEMPORT_INT} multi-service user-vlan {VLAN_INT} tag-transform translate'
            )
            # convertir a numero
            service_port_two = int(service_port) + 1
            service_cmd_two = (
                f'service-port {service_port_two} vlan {VLAN_TR} gpon {frame}/{slot}/{port} ont {ontid} '
                f'gemport {GEMPORT_TR} multi-service user-vlan {VLAN_TR} tag-transform translate'
            )

            # interface gpon 1/1 ----------------------------------------------------
            tn.write(interface_cmd.encode("ascii"))
            time.sleep(0.3)
            # add ont -------------------------------------------------------------------
            print("ADD ONT command----------------------------------------------------:", add_ont_cmd)
            result, out = send_cmd_telnet_add_onu(tn, add_ont_cmd)
            if result == False:
                # tn.close()
                print("-----------------------------------------------existe " + out)
                return tn,out
            else:
                r2, out2 = send_cmd_telnet_add_onu_two(tn, add_ont_cmd_two)
                if r2 == False:
                    # tn.close()
                    print("-----------------------------------------------existe " + out2)
                    return tn,out2
                else:
                    r3, out3 = send_cmd_telnet_add_onu_two(tn, add_ont_cmd_three)
                    if r3 == False:
                        # tn.close()
                        print("-----------------------------------------------existe " + out3)
                        return tn,out3
                    else:
                        cmd = f"quit\r\n"    
                        r4, out4 = send_cmd_telnet_add_onu_two(tn, cmd)
                        if r4 == False:
                            # tn.close()
                            print("-----------------------------------------------existe " + out4)
                            return tn,out4
                        else:
                            insert_onu_table(frame, slot, port, ontid, sn, desc)
                            print("OLT espera ENTER, enviando...")
                            # //send enter
                            cmd = (" ")                            
                            
                            r4, out4 = send_cmd_telnet_add_onu_two(tn, cmd)
                            if r4 == False:
                                # tn.close()
                                print("-----------------------------------------------existe " + out4)
                                return tn,out4
                            else:
                                r5, out5 = send_cmd_telnet_add_onu_two(tn, service_cmd)
                                if r5 == False:
                                    # tn.close()
                                    print("-----------------------------------------------existe " + out5)
                                    return tn,out5
                                else:
                                    cmd = (" ")                            
                                    r6, out6 = send_cmd_telnet_add_onu_two(tn, cmd)
                                    if r6 == False:
                                        # tn.close()
                                        print("-----------------------------------------------existe " + out6)
                                        return tn,out6
                                    else:
                                        insert_service_table(service_port, VLAN_INT, frame, slot, port, ontid,  service_cmd)
                                        r7, out7 = send_cmd_telnet_add_onu_two(tn, service_cmd_two)
                                        if r7 == False:
                                            # tn.close()
                                            print("-----------------------------------------------existe " + out7)
                                            return tn,out7
                                        else:
                                            cmd = (" ")                            
                                            r8, out8 = send_cmd_telnet_add_onu_two(tn, cmd)
                                            if r8 == False:
                                                # tn.close()
                                                print("-----------------------------------------------existe " + out8)
                                                return tn,out8
                                            else:
                                                insert_service_table(service_port_two, VLAN_TR, frame, slot, port, ontid,  service_cmd_two)
                                                return tn,out8



            return

            # tn.write(add_ont_cmd.encode("ascii") + b"\r\n")
            # time.sleep(0.5)

            # out = tn.read_very_eager().decode("utf-8",errors="ignore")
            # print(repr(out))

            # if PATRON_CR.search(out):
                # print("OLT espera ENTER, enviando...")
                # tn.write(b"\r\n")
                # time.sleep(0.3)

                # out = tn.read_very_eager().decode("utf-8",errors="ignore")
                # print(repr(out))

                # PATRON_CONFLICTO = re.compile(
                #     r"(Failure.*?|Conflicted service virtual port index:\s*(\d+))",
                #     re.IGNORECASE | re.DOTALL
                # )
                # if "Failure: The ONT ID has already existed" in out:
                    # return "existe"
                    # tn.close()
                    # print("-----------------------------------------------existe " + out)
                    # return out
                # elif "Failure: SN already exists" in out:
                    # return "existe"
                    # tn.close()
                    # print("-----------------------------------------------existe " + out)
                    # return out
                # elif re.search(r"PortID\s*:\s*\d+,\s*ONTID\s*:\s*\d+", out):
                    # ----------------------comando dos ----------------------------
                    # PATRON_fail = re.compile(
                    #     r"(failure|error|Conflicted service virtual port index:\s*(\d+))",
                    #     re.IGNORECASE
                    # )
                    # print("ADD ONT command--------------------------------:", add_ont_cmd_two)
                    # tn.write(add_ont_cmd_two.encode("ascii") + b"\r\n")
                    # time.sleep(0.1)
                    # out = tn.read_very_eager().decode("utf-8",errors="ignore")
                    # print(repr(out))

                    # if PATRON_fail.search(out):
                    #     print(f"error: {out}")
                    #     tn.close()
                    #     # return f"⚠️ El service-port {match.group(2)} ya existe. No se pudo crear. {out}"
                    #     return "⚠️ Error: se detectó un conflicto . {out}"
                    # else:
                    #     # ---------------------------comando tres ----------------------------
                    #     # print("ADD ONT command tres--------------------------------:", add_ont_cmd_three)
                    #     tn.write(add_ont_cmd_three.encode("ascii") + b"\r\n")
                    #     time.sleep(0.1)
                    #     out = tn.read_very_eager().decode("utf-8",errors="ignore")
                    #     time.sleep(3)
                        


                    #     match = PATRON_fail.search(out)
                    #     if PATRON_fail.search(out):
                    #         print(f"error: {out}")
                    #         tn.close()
                    #         # return f"⚠️ El service-port {match.group(2)} ya existe. No se pudo crear. {out}"
                    #         return "⚠️ Error: se detectó un conflicto . {out}"
                    #     else:
                    #         # ---------------------------comando cuarto ----------------------------
                    #         # print("out --------------------------------:", out)
                    #         #service port ------------------------------------------------------
                    #         tn.write(b"quit\r\n")
                    #         time.sleep(0.1)
                    #         out = tn.read_very_eager().decode("utf-8",errors="ignore")                            
                    #         # print((out))
                    #         if "quit" in out:
                    #             print(f"quit found : {out}")
                                
                    #             # print("-----------------------------------------------existe " + out)                            
                    #             print("service-port command-----------------------------------------:", service_cmd)
                    #             time.sleep(0.1)
                    #             tn.write(service_cmd.encode("ascii")+ b"\r\n") #
                    #             # tn.write(b"\r\n")
                    #             time.sleep(1.5)
                    #             out = tn.read_very_eager().decode("utf-8")                            
                    #             print(repr(out))
                    #             if PATRON_CR.search(out):
                    #                 print("OLT espera ENTER, enviando...")
                    #                 tn.write(b"\r\n")
                    #                 time.sleep(0.3)

                    #                 out = tn.read_very_eager().decode("utf-8",errors="ignore")
                    #                 print(repr(out))                                                               
                    #                 if(PATRON_fail.search(out)):
                    #                     print(f"error: {out}")
                    #                     tn.close()
                    #                     return f"⚠️ El service-port. No se pudo crear. {out}"                        
                    #                 else:
                    #                     print(f"else ................................................... {out}")
                    #                     tn.write(service_cmd_two.encode("ascii")+ b"\r\n") #
                    #                     # tn.write(b"\r\n")
                    #                     time.sleep(1.5)
                    #                     out = tn.read_very_eager().decode("utf-8")                            
                    #                     print(repr(out))

                    #                     if PATRON_CR.search(out):
                    #                         print("OLT espera ENTER, enviando...")
                    #                         tn.write(b"\r\n")
                    #                         time.sleep(0.3)

                    #                         out = tn.read_very_eager().decode("utf-8",errors="ignore")
                    #                         print(repr(out))                                                               
                    #                         if(PATRON_fail.search(out)):
                    #                             print(f"error: {out}")
                    #                             tn.close()
                    #                             return f"⚠️ El service-port. No se pudo crear. {out}"                        
                    #                         else:
                    #                             print(f"else ................................................... {out}")
                    #                             tn.close()
                    #                             return out
                        
    except Exception as e:
        print("Error:", e)
        traceback.print_exc()
        tn.close()
        return f"Error al dar de alta ONT: {e} {estado} {resultado}"

def alta_ont_version_three_ma(frame, slot, port, ontid, sn, desc, service_port):
    try:
        tipo = 'alta_onu_version_three_ma'
        PATRON_CR = re.compile(r"{\s*<cr>.*?}", re.IGNORECASE)

        tn, estado, resultado = conectar_ma()
        print(estado)
        if estado == "error":
            print("Error ")
            return redirect(url_for("dashboard"))
        else:
            tn.write(b"enable\n")
            tn.write(b"config\n")
            print("config")
            if isinstance(tn, str):
                return tn

            interface_cmd = f"interface gpon {frame}/{slot}\n"

            add_ont_cmd = (
                f'ont add {port} {ontid} sn-auth "{sn}" omci '
                f'ont-lineprofile-id {LINE_PROFILE_V2} ont-srvprofile-id {SRV_PROFILE_V2} '
                f'desc "{desc}"'
            )

            add_ont_cmd_two = (
                f'ont ipconfig {port} {ontid} dhcp'
                f' vlan {VLAN_TR_MA} priority 5'
            )

            add_ont_cmd_three = (
                f'ont tr069-server-config {port} {ontid} profile-id 1'
            )

            service_cmd = (
                f'service-port {service_port} vlan {VLAN_INT_MA}  '
                f'gpon {frame}/{slot}/{port} ont {ontid} '
                f'gemport {GEMPORT_INT} multi-service user-vlan {VLAN_INT_MA} tag-transform translate'
            )
            service_port_two = int(service_port) + 1
            service_cmd_two = (
                f'service-port {service_port_two} vlan {VLAN_TR_MA} gpon {frame}/{slot}/{port} ont {ontid} '
                f'gemport {GEMPORT_TR} multi-service user-vlan {VLAN_TR_MA} tag-transform translate'
            )

            tn.write(interface_cmd.encode("ascii"))
            time.sleep(0.3)

            print("ADD ONT command----------------------------------------------------:", add_ont_cmd)
            result, out = send_cmd_telnet_add_onu(tn, add_ont_cmd)
            if result == False:
                print("-----------------------------------------------existe " + out)
                return tn, out
            else:
                r2, out2 = send_cmd_telnet_add_onu_two(tn, add_ont_cmd_two)
                if r2 == False:
                    print("-----------------------------------------------existe " + out2)
                    return tn, out2
                else:
                    r3, out3 = send_cmd_telnet_add_onu_two(tn, add_ont_cmd_three)
                    if r3 == False:
                        print("-----------------------------------------------existe " + out3)
                        return tn, out3
                    else:
                        cmd = f"quit\r\n"
                        r4, out4 = send_cmd_telnet_add_onu_two(tn, cmd)
                        if r4 == False:
                            print("-----------------------------------------------existe " + out4)
                            return tn, out4
                        else:
                            insert_onu_table(frame, slot, port, ontid, sn, desc, olt='MA')
                            print("OLT espera ENTER, enviando...")
                            cmd = (" ")
                            r4, out4 = send_cmd_telnet_add_onu_two(tn, cmd)
                            if r4 == False:
                                print("-----------------------------------------------existe " + out4)
                                return tn, out4
                            else:
                                r5, out5 = send_cmd_telnet_add_onu_two(tn, service_cmd)
                                if r5 == False:
                                    print("-----------------------------------------------existe " + out5)
                                    return tn, out5
                                else:
                                    cmd = (" ")
                                    r6, out6 = send_cmd_telnet_add_onu_two(tn, cmd)
                                    if r6 == False:
                                        print("-----------------------------------------------existe " + out6)
                                        return tn, out6
                                    else:
                                        insert_service_table(service_port, VLAN_INT_MA, frame, slot, port, ontid, service_cmd, olt='MA')
                                        r7, out7 = send_cmd_telnet_add_onu_two(tn, service_cmd_two)
                                        if r7 == False:
                                            print("-----------------------------------------------existe " + out7)
                                            return tn, out7
                                        else:
                                            cmd = (" ")
                                            r8, out8 = send_cmd_telnet_add_onu_two(tn, cmd)
                                            if r8 == False:
                                                print("-----------------------------------------------existe " + out8)
                                                return tn, out8
                                            else:
                                                insert_service_table(service_port_two, VLAN_TR_MA, frame, slot, port, ontid, service_cmd_two, olt='MA')
                                                return tn, out8

            return

    except Exception as e:
        print("Error:", e)
        traceback.print_exc()
        tn.close()
        return f"Error al dar de alta ONT MA: {e} {estado} {resultado}"

def insert_onu_table(card_id, slot_id, port_id, ont_id, sn, description, olt='EA'):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("UPDATE onus SET deleted = 1 WHERE card_id = ? AND slot_id = ? AND port_id = ? AND ont_id = ? ", (card_id, slot_id, port_id, ont_id))
    conn.commit()
    c.execute("""
    INSERT INTO onus (card_id, slot_id, port_id, ont_id, SN, description, deleted, olt)
        VALUES (?, ?, ?, ?, ?, ?, 0, ?)
    """, (card_id, slot_id, port_id, ont_id, sn, description, olt))
    conn.commit()
    conn.close()

def insert_service_table(service_port, vlan, card_id, slot_id, port_id, ont_id, cadena, olt='EA'):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("UPDATE service_ports SET deleted = 1 WHERE service_port = ? ", (service_port,))
    conn.commit()
    c.execute("""
    INSERT INTO service_ports (service_port, vlan, card_id, slot_id, port_id, ont_id, cadena, deleted, olt)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
    """, (service_port, vlan, card_id, slot_id, port_id, ont_id, cadena, olt))
    conn.commit()
    conn.close()

# def parse_ont_info(texto):
#     puertos = defaultdict(list)
#     current_port = None
#     parsing_ont_info = False
#     parsing_ont_detail = False
#     ont_data_temp = {}

#     lines = texto.splitlines()

#     for line in lines:
#         line = line.strip()

#         # Detectar puerto
#         match_port = re.match(r"In port (\d+/\d+/\d+),", line)
#         if match_port:
#             current_port = match_port.group(1)
#             continue

#         # Detectar inicio de tabla de estado ONT
#         if re.match(r"ONT\s+Run\s+Last", line):
#             parsing_ont_info = True
#             parsing_ont_detail = False
#             continue

#         # Detectar inicio de tabla de detalle ONT
#         if re.match(r"ONT\s+SN\s+Type\s+Distance", line):
#             parsing_ont_info = False
#             parsing_ont_detail = True
#             continue

#         # Detectar fin de tabla (líneas de guiones)
#         if re.match(r"^-+$", line):
#             continue

#         if not current_port:
#             continue

#         # Parsear tabla de estado ONT
#         if parsing_ont_info and re.match(r"\d+\s+\w+", line):
#             partes = line.split()
#             ont_id = int(partes[0])
#             puertos[current_port].append({
#                 "ont_id": ont_id,
#                 "state": partes[1],
#                 "uptime": partes[2] + " " + partes[3] if partes[2] != "-" else "-",
#                 "downtime": partes[4] + " " + partes[5] if partes[4] != "-" else "-",
#                 "down_cause": " ".join(partes[6:]) if len(partes) > 6 else "-"
#             })

#         # Parsear tabla de detalles ONT
#         elif parsing_ont_detail and re.match(r"\d+\s+[A-F0-9]+", line):
#             partes = line.split()
#             ont_id = int(partes[0])
#             try:
#                 puertos[current_port][ont_id].update({
#                     "sn": partes[1],
#                     "type": partes[2],
#                     "distance": int(partes[3]),
#                     "rx_tx": partes[4],
#                     "description": " ".join(partes[5:]) if len(partes) > 5 else ""
#                 })
#             except IndexError:
#                 # En caso de que ont_id no esté en la lista (posible mismatch)
#                 pass

#     return puertos

# def parse_ont_info(texto):
#     texto = limpiar_salida_olt(texto)

#     puertos = defaultdict(dict)
#     current_port = None
#     parsing_ont_info = False
#     parsing_ont_detail = False

#     lines = texto.splitlines()

#     for line in lines:
#         line = line.strip()

#         # Detectar puerto
#         match_port = re.match(r"In port (\d+/\d+/\d+),", line)
#         if match_port:
#             current_port = match_port.group(1)
#             continue

#         # Detectar encabezados
#         if re.match(r"ONT\s+Run\s+Last", line):
#             parsing_ont_info = True
#             parsing_ont_detail = False
#             continue
#         if re.match(r"ONT\s+SN\s+Type", line):
#             parsing_ont_info = False
#             parsing_ont_detail = True
#             continue

#         if re.match(r"^-+$", line):
#             continue

#         if not current_port:
#             continue

#         # Parsear sección de estado
#         if parsing_ont_info and re.match(r"\d+\s+\w+", line):
#             partes = line.split()
#             ont_id = int(partes[0])
#             puertos[current_port][ont_id] = {
#                 "ont_id": ont_id,
#                 "state": partes[1],
#                 "uptime": partes[2] + " " + partes[3] if partes[2] != "-" else "-",
#                 "downtime": partes[4] + " " + partes[5] if partes[4] != "-" else "-",
#                 "down_cause": " ".join(partes[6:]) if len(partes) > 6 else "-"
#             }

#         # Parsear sección de detalles
#         elif parsing_ont_detail and re.match(r"\d+\s+[A-F0-9]+", line):
#             partes = line.split()
#             ont_id = int(partes[0])
#             if ont_id in puertos[current_port]:
#                 puertos[current_port][ont_id].update({
#                     "sn": partes[1],
#                     "type": partes[2],
#                     "distance": int(partes[3]),
#                     "rx_tx": partes[4],
#                     "description": " ".join(partes[5:]) if len(partes) > 5 else ""
#                 })

#     return puertos


# def parse_ont_info(texto):

#     conn = sqlite3.connect("users.db")
#     c = conn.cursor()
#     c.execute("SELECT datos, id FROM configuration where tipo = 'current' ORDER BY id DESC LIMIT 1")
#     row = c.fetchone()
#     conn.close()

#     current = row[0] if row else ""

#     puertos = defaultdict(dict)
#     current_port = None
#     parsing_ont_info = False
#     parsing_ont_detail = False
#     errores = []
    
#     PATRON_SERVICE_PORT = re.compile(
#         r"service-port\s+(\d+)\s+vlan\s+\d+\s+gpon\s+(\d+/\d+/\d+)\s+ont\s+(\d+)",
#         re.IGNORECASE
#     )
#     # Extraer service-port antes de procesar ONTs
#     sp_asignados = set()
#     service_ports = defaultdict(set)  # puerto => set(ont_id)
#     print(texto)
#     for match in PATRON_SERVICE_PORT.finditer(current):
#         sp_id = int(match.group(1))
#         puerto = match.group(2)
#         ont_id = int(match.group(3))
#         service_ports[puerto].add(ont_id)
#         sp_asignados.add((puerto, ont_id))

#     lines = texto.splitlines()
#     for line in lines:
#         original_line = line
#         line = line.strip()

#         match_port = re.match(r"In port (\d+/\d+/\d+),", line)
#         if match_port:
#             current_port = match_port.group(1)
#             continue

#         if re.match(r"ONT\s+Run\s+Last", line):
#             parsing_ont_info = True
#             parsing_ont_detail = False
#             continue

#         if re.match(r"ONT\s+SN\s+Type\s+Distance", line):
#             parsing_ont_info = False
#             parsing_ont_detail = True
#             continue

#         if re.match(r"^-+$", line) or not current_port:
#             continue

#         if parsing_ont_info and re.match(r"\d+\s+\w+", line):
#             partes = line.split()
#             if partes[0].isdigit():
#                 ont_id = int(partes[0])
#                 puertos[current_port][ont_id] = {
#                     "ont_id": ont_id,
#                     "state": partes[1],
#                     "uptime": partes[2] + " " + partes[3] if partes[2] != "-" else "-",
#                     "downtime": partes[4] + " " + partes[5] if partes[4] != "-" else "-",
#                     "down_cause": " ".join(partes[6:]) if len(partes) > 6 else "-",
#                     "has_service_port": (ont_id in service_ports.get(current_port, set())),
#                     "editar_url": f"/editar/{current_port}/{ont_id}",
#                     "borrar_url": f"/borrar/{current_port}/{ont_id}"
#                 }
#             else:
#                 errores.append(f"[ONT INFO] Línea ignorada: {original_line}")

#         elif parsing_ont_detail and re.match(r"\d+\s+[A-F0-9]+", line):
#             partes = line.split()
#             if partes[0].isdigit():
#                 ont_id = int(partes[0])
#                 if ont_id in puertos[current_port]:
#                     puertos[current_port][ont_id].update({
#                         "sn": partes[1],
#                         "type": partes[2],
#                         "distance": partes[3],
#                         "rx_tx": partes[4],
#                         "description": " ".join(partes[5:]) if len(partes) > 5 else ""
#                     })
#                 else:
#                     errores.append(f"[DETALLE] ID {ont_id} no está en sección anterior → {original_line}")
#             else:
#                 errores.append(f"[DETALLE] Línea ignorada: {original_line}")

#     return puertos, errores

# def parse_ont_info(texto):
#     puertos = defaultdict(dict)
#     current_port = None
#     parsing_ont_info = False
#     parsing_ont_detail = False
#     errores = []  # ← aquí guardaremos las líneas que no se pudieron procesar

#     lines = texto.splitlines()

#     for line in lines:
#         original_line = line
#         line = line.strip()

#         match_port = re.match(r"In port (\d+/\d+/\d+),", line)
#         if match_port:
#             current_port = match_port.group(1)
#             continue

#         if re.match(r"ONT\s+Run\s+Last", line):
#             parsing_ont_info = True
#             parsing_ont_detail = False
#             continue

#         if re.match(r"ONT\s+SN\s+Type\s+Distance", line):
#             parsing_ont_info = False
#             parsing_ont_detail = True
#             continue

#         if re.match(r"^-+$", line) or not current_port:
#             continue

#         if parsing_ont_info and re.match(r"\d+\s+\w+", line):
#             partes = line.split()
#             if partes[0].isdigit():
#                 ont_id = int(partes[0])
#                 puertos[current_port][ont_id] = {
#                     "ont_id": ont_id,
#                     "state": partes[1],
#                     "uptime": partes[2] + " " + partes[3] if partes[2] != "-" else "-",
#                     "downtime": partes[4] + " " + partes[5] if partes[4] != "-" else "-",
#                     "down_cause": " ".join(partes[6:]) if len(partes) > 6 else "-"
#                 }
#             else:
#                 errores.append(f"[ONT INFO] Línea ignorada: {original_line}")

#         elif parsing_ont_detail and re.match(r"\d+\s+[A-F0-9]+", line):
#             partes = line.split()
#             if partes[0].isdigit():
#                 ont_id = int(partes[0])
#                 if ont_id in puertos[current_port]:
#                     puertos[current_port][ont_id].update({
#                         "sn": partes[1],
#                         "type": partes[2],
#                         "distance": (partes[3]),
#                         "rx_tx": partes[4],
#                         "description": " ".join(partes[5:]) if len(partes) > 5 else ""
#                     })
#                 else:
#                     errores.append(f"[DETALLE] ID {ont_id} no está en sección anterior → {original_line}")
#             else:
#                 errores.append(f"[DETALLE] Línea ignorada: {original_line}")

#     return puertos, errores
