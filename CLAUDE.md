# CLAUDE.md — OLT Web UI

## Project Overview
Web-based management system for a Huawei EA5801E OLT (Optical Line Terminal). Built with Python/Flask, it manages fiber optic ONTs via Telnet, provisions PPPoE accounts on MikroTik routers, and integrates with Google Sheets and an ACS server.

## Tech Stack
- **Backend:** Python 3.8+ / Flask
- **Frontend:** Jinja2 templates + Bootstrap 5.3 + jQuery
- **Database:** SQLite (users.db, potencia.db, service_ports.db)
- **Integrations:** Huawei OLT (Telnet), MikroTik RouterOS API, Google Sheets (gspread), ACS (HTTP REST)

## Project Structure
```
app.py              — Main Flask application (routes, auth, views)
olt_telnet.py       — Telnet communication & OLT command functions
crear_usuario.py    — CLI utility to create admin users
templates/          — Jinja2 HTML templates (17 files)
static/css/         — Bootstrap CSS
static/js/          — Bootstrap, jQuery, TableSorter, custom JS
*.db                — SQLite databases (users, potencia, service_ports)
.env                — Configuration (OLT credentials, profiles, integrations)
```

## Setup & Run
```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example.txt .env      # Then edit .env with real values
python crear_usuario.py       # Create initial admin user
python app.py                 # Runs on https://0.0.0.0:8080
```

## Key Commands
- **Install deps:** `pip install -r requirements.txt`
- **Run server:** `python app.py`
- **Create user:** `python crear_usuario.py`

## Architecture Notes
- MVC pattern: `app.py` (controller/routes), `olt_telnet.py` (model/service), `templates/` (views)
- Multiple ONT provisioning versions (v1–v4) reflect iterative feature additions
- Authentication via Flask-Login with session-based auth and Werkzeug password hashing
- Some routes intentionally lack `@login_required` for AJAX/API use
- SSL/TLS enabled with certificate files (fullchain.pem, privkey.pem)

## Code Conventions
- Language: Code in English, UI/comments mostly in Spanish
- Route naming: kebab-case (`/alta-ont`, `/service_port`)
- Template naming: snake_case (`alta_ont_v2.html`, `resultado_alta.html`)
- Configuration via `.env` using `python-dotenv`

## Important Files
- `.env` — Contains secrets (OLT credentials, MikroTik creds, PPPoE passwords). Never commit.
- `olt_telnet.py` — Core business logic; all OLT Telnet commands live here
- `app.py` — All Flask routes and request handling

## Security Notes
- Never commit `.env`, `*.pem`, `pass.txt`, or `*.db` files
- Debug mode is currently enabled — disable for production
- Telnet is inherently unencrypted; this is a hardware limitation of the OLT
