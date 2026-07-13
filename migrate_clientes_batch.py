"""
Migración: carga masiva de clientes desde un xlsx a la tabla 'clientes'.
- Columnas esperadas en el xlsx: NOMBRE_PP, APELLIDO_PP (fila 1 = encabezado).
- Hace backup automático de la base antes de insertar.
- Es seguro correrlo más de una vez: si ya existe un cliente con el mismo
  nombre+apellidos, esa fila se omite (no se duplica).
- Campos que no vienen en el xlsx se insertan con:
    user_name='', direccion='', localidad='', coordenadas='',
    numero_celular='', tiene_whatsapp=0, tipo_conexion='pppoe',
    plan_id=NULL, fecha_alta='', activo=1

Uso:
    python migrate_clientes_batch.py [ruta_xlsx] [ruta_db]

Por defecto usa usuarios_Activos.xlsx y users.db en el directorio actual.
"""

import sqlite3
import shutil
import sys
import os
from datetime import datetime

import openpyxl

XLSX_PATH = sys.argv[1] if len(sys.argv) > 1 else "usuarios_Activos.xlsx"
DB_PATH = sys.argv[2] if len(sys.argv) > 2 else "users.db"
BACKUP_PATH = f"users_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"


def leer_clientes(xlsx_path):
    wb = openpyxl.load_workbook(xlsx_path, read_only=True)
    ws = wb.active
    filas = ws.iter_rows(min_row=2, max_col=2, values_only=True)
    clientes = []
    for nombre, apellidos in filas:
        nombre = (nombre or "").strip()
        apellidos = (apellidos or "").strip()
        if not nombre:
            continue
        clientes.append((nombre, apellidos))
    return clientes


def main():
    if not os.path.exists(XLSX_PATH):
        print(f"ERROR: No se encontró {XLSX_PATH}")
        return
    if not os.path.exists(DB_PATH):
        print(f"ERROR: No se encontró {DB_PATH}")
        return

    clientes = leer_clientes(XLSX_PATH)
    print(f"Leídos {len(clientes)} clientes desde {XLSX_PATH}")

    shutil.copy2(DB_PATH, BACKUP_PATH)
    print(f"Backup creado: {BACKUP_PATH}")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    insertados = 0
    omitidos = 0
    for nombre, apellidos in clientes:
        c.execute(
            "SELECT 1 FROM clientes WHERE nombre = ? AND apellidos = ?",
            (nombre, apellidos),
        )
        if c.fetchone():
            omitidos += 1
            continue
        c.execute(
            """INSERT INTO clientes
               (nombre, apellidos, direccion, localidad, coordenadas, numero_celular,
                tiene_whatsapp, user_name, tipo_conexion, plan_id, fecha_alta, activo)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (nombre, apellidos, "", "", "", "", 0, "", "pppoe", None, "", 1),
        )
        insertados += 1

    conn.commit()

    c.execute("SELECT COUNT(*) FROM clientes")
    total = c.fetchone()[0]
    conn.close()

    print(f"\nInsertados: {insertados}")
    print(f"Omitidos (ya existían): {omitidos}")
    print(f"Total en tabla clientes: {total}")
    print(f"\nSi algo salió mal, restaura con: copy {BACKUP_PATH} {DB_PATH}")


if __name__ == "__main__":
    main()
