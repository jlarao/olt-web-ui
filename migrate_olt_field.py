"""
Migración: agrega columna 'olt' a las tablas onus y service_ports.
- Hace backup automático antes de modificar.
- Es seguro correrlo más de una vez (detecta si la columna ya existe).
"""

import sqlite3
import shutil
import os
from datetime import datetime

DB_PATH = "users.db"
BACKUP_PATH = f"users_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"


def columna_existe(cursor, tabla, columna):
    cursor.execute(f"PRAGMA table_info({tabla})")
    return any(row[1] == columna for row in cursor.fetchall())


def main():
    if not os.path.exists(DB_PATH):
        print(f"ERROR: No se encontró {DB_PATH}")
        return

    # Backup
    shutil.copy2(DB_PATH, BACKUP_PATH)
    print(f"Backup creado: {BACKUP_PATH}")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # --- onus ---
    if not columna_existe(c, "onus", "olt"):
        c.execute("ALTER TABLE onus ADD COLUMN olt TEXT DEFAULT 'EA'")
        print("onus: columna 'olt' agregada")
    else:
        print("onus: columna 'olt' ya existe, omitiendo ALTER")

    c.execute("UPDATE onus SET olt = 'EA' WHERE olt IS NULL")
    actualizados = c.rowcount
    print(f"onus: {actualizados} registros actualizados a 'EA'")

    # --- service_ports ---
    if not columna_existe(c, "service_ports", "olt"):
        c.execute("ALTER TABLE service_ports ADD COLUMN olt TEXT DEFAULT 'EA'")
        print("service_ports: columna 'olt' agregada")
    else:
        print("service_ports: columna 'olt' ya existe, omitiendo ALTER")

    c.execute("UPDATE service_ports SET olt = 'EA' WHERE olt IS NULL")
    actualizados = c.rowcount
    print(f"service_ports: {actualizados} registros actualizados a 'EA'")

    conn.commit()

    # Verificación final
    print("\n--- Verificación final ---")
    c.execute("SELECT olt, count(*) FROM onus GROUP BY olt")
    print("onus:", c.fetchall())
    c.execute("SELECT olt, count(*) FROM service_ports GROUP BY olt")
    print("service_ports:", c.fetchall())

    conn.close()
    print("\nMigración completada exitosamente.")
    print(f"Si algo salió mal, restaura con: copy {BACKUP_PATH} {DB_PATH}")


if __name__ == "__main__":
    main()
