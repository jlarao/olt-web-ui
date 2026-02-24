import sqlite3
from werkzeug.security import generate_password_hash

# Base de datos de usuarios
db = "users.db"

# Crear tabla si no existe
def crear_tabla():
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Crear un nuevo usuario
def crear_usuario(username, password):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    password_hash = generate_password_hash(password)
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        print(f"✅ Usuario '{username}' creado correctamente.")
    except sqlite3.IntegrityError:
        print("❌ Ese nombre de usuario ya existe.")
    conn.close()

if __name__ == "__main__":
    crear_tabla()
    print("=== Crear usuario administrador ===")
    usuario = input("Nombre de usuario: ")
    clave = input("Contraseña: ")
    crear_usuario(usuario, clave)

# python crear_usuario.py
# Nombre de usuario: admin
# Contraseña: admin123
# ✅ Usuario 'admin' creado correctamente.
