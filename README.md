# OLT Web UI Huawei – Gestión vía Telnet con Flask

Sistema web en Python + Flask para gestionar una OLT Huawei EA5801E usando Telnet.

## ✅ Funciones principales

- Ingreso seguro con usuario y contraseña
- Alta de ONTs desde una interfaz web
- Consulta de potencia óptica (RX) de ONTs
- Gestión de múltiples VLANs
- Configuración vía archivo `.env`

---

## 📦 Requisitos

- Ubuntu 20.04 o 22.04
- Python 3.8 o superior
- Acceso Telnet habilitado en la OLT Huawei

---

## 🛠 Instalación

```bash
# 1. Clonar o copiar el proyecto
git clone <repositorio> olt-web-ui
cd olt-web-ui

# 2. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Configurar conexión a la OLT
cp .env.example .env
nano .env  # Ajusta IP, usuario y contraseña Telnet

# 5. Crear usuario admin para ingresar
python crear_usuario.py

# 6. Iniciar la aplicación en el puerto 8080
python app.py
