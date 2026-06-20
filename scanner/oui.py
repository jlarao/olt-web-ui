"""
Clasificación de dispositivos por OUI (primeros 3 octetos de la MAC).
Más confiable que UDP discovery en redes donde los equipos no responden al puerto 10001.
"""

# Ubiquiti Networks, Inc. — OUIs airOS Legacy (XM/XW firmware)
UBNT_LEGACY_OUI = {
    '00:15:6D', '00:27:22',
    '04:18:D6', '0A:18:D6',
    '18:E8:29',
    '20:23:51',
    '24:2F:D0', '24:A4:3C',
    '28:EE:52',
    '44:D9:E7',
    '5C:E9:31',
    '68:72:51',
    '70:4F:57',
    '74:83:C2',
    '78:8A:20',
    '80:2A:A8',
    'AC:84:C6',
    'B0:4E:26', 'B0:BE:76',
    'B4:FB:E4',
    'DC:9F:DB',
    'E0:63:DA',
    'F0:9F:C2',
    'FC:EC:DA',
}

# Ubiquiti Networks, Inc. — OUIs airMAX AC / UniFi (WA firmware, 24:5A:4C, etc.)
UBNT_AC_OUI = {
    '00:AA:23',
    '24:5A:4C',
    '60:22:32',
    '68:D7:9A',
    '74:AC:B9',
    '78:45:58',
    'B4:FB:E4',  # compartido legacy/AC según modelo
    'C4:AD:34',  # también en Hap, pero común en airMAX AC
    'E4:38:83',  # airMAX AC confirmado en campo
    'F4:92:BF',
}

# Unión para clasificación genérica
UBNT_OUI = UBNT_LEGACY_OUI | UBNT_AC_OUI

# MikroTik SIA — OUIs conocidos
MIKROTIK_OUI = {
    '00:0C:42',
    '2C:C8:1B',
    '48:8F:5A',
    '4C:5E:0C',
    '64:D1:54',
    '6C:3B:6B',
    '08:55:31',
    '18:FD:74',
    '74:4D:28',
    'B8:69:F4',
    'C4:AD:34',
    'CC:2D:E0',
    'D4:01:C3',
    'DC:2C:6E',
    'E4:8D:8C',
    '04:F4:1C',
}

# Huawei — OUIs frecuentes en ONTs
HUAWEI_OUI = {
    '00:E0:FC', '00:18:82', '00:1E:10',
    '34:6B:D3', '40:4D:8E', '48:AD:08',
    '54:89:98', '68:81:E0', '70:7B:E8',
    '88:E3:AB', '90:17:AC', '98:F5:37',
    'AC:4E:91', 'C8:51:95', 'D0:7E:28',
    'E8:08:8B', 'F8:98:B9',
}

# Cambium Networks — ePMP, PMP, cnPilot
CAMBIUM_OUI = {
    '00:04:56',
    '58:C1:7A',
    '74:9D:8F',
    '04:F0:21',
    '0A:F0:21',
}

# ZTE — OUIs frecuentes en ONTs
ZTE_OUI = {
    '00:19:C6', '00:26:ED',
    '08:F6:9C', '10:C6:1F',
    '20:89:84', '2C:26:5F',
    '40:E8:A6', '58:87:BA',
    '78:32:1B', '80:D0:9B',
    '90:5E:44', 'A0:E0:AF',
    'BC:14:EF', 'D0:27:88',
}


def classify_by_oui(mac: str) -> str:
    """
    Clasifica un dispositivo según su OUI (primeros 3 bytes de la MAC).
    Retorna: 'mikrotik', 'ubnt', 'cambium', 'huawei_ont', 'zte_ont', o 'unknown'
    """
    if not mac:
        return 'unknown'
    parts = mac.upper().replace(':', '').replace('-', '')
    if len(parts) < 6:
        return 'unknown'
    oui = ':'.join([parts[0:2], parts[2:4], parts[4:6]])

    if oui in MIKROTIK_OUI:
        return 'mikrotik'
    if oui in UBNT_AC_OUI:
        return 'ubnt_ac'
    if oui in UBNT_LEGACY_OUI:
        return 'ubnt_legacy'
    if oui in CAMBIUM_OUI:
        return 'cambium'
    if oui in HUAWEI_OUI:
        return 'huawei_ont'
    if oui in ZTE_OUI:
        return 'zte_ont'
    return 'unknown'


# Patrones de firmware para detectar fabricante desde /ip neighbor print
import re

# UBNT airOS: XM.v5.x, XW.v6.x, WA.ar934x, XC.qca955x, XA.v, BZ.v, TI.v
# Permitir cualquier carácter tras el punto (qca, ar, v, ipq, etc.)
_UBNT_FW_RE = re.compile(r'^(XM|XW|XC|XA|WA|BZ|TI|U[A-Z0-9])\.', re.I)
# UBNT airFiber: AF24.v, AF5.v
_UBNT_AF_RE  = re.compile(r'^AF\d+\.', re.I)
# Cambium ePMP/PMP: 4.x.x, 3.x.x patterns with board starting F3, e5, ePMP
_CAMBIUM_FW_RE = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
# RouterOS: 6.x.x, 7.x.x (three-part version, no letters)
_ROUTEROS_RE = re.compile(r'^\d+\.\d+(\.\d+)?$')


def classify_by_version(version: str, board: str = '', identity: str = '') -> str:
    """
    Clasifica por versión/board anunciados en MNDP cuando la MAC no está disponible.
    Retorna el mismo conjunto de tipos que classify_by_oui, o '' si no reconoce.
    """
    if not version:
        return ''
    v = version.strip()
    b = (board or '').strip()

    # RouterOS pattern (6.49.10, 7.18.2) → MikroTik
    if _ROUTEROS_RE.match(v):
        return 'mikrotik'

    if _UBNT_FW_RE.match(v) or _UBNT_AF_RE.match(v):
        # WA.ar934x or WA.v8+ → airMAX AC
        if re.match(r'^WA\.(v[89]|ar)', v, re.I):
            return 'ubnt_ac'
        # XC/XA/BZ/TI → AC series
        if re.match(r'^(XC|XA|BZ|TI)\.', v, re.I):
            return 'ubnt_ac'
        return 'ubnt_legacy'

    # Cambium ePMP: version pura numérica tipo 4.6.0.1, board F3xx o vacío
    if _CAMBIUM_FW_RE.match(v) and (re.match(r'^F3', b, re.I) or not b):
        return 'cambium'

    return ''
