"""
SNMP-коннектор для получения информации об устройствах.

Использует pysnmp-lextudio для опроса sysDescr, sysName, sysLocation
по SNMP v2c с community 'public'.
"""
import logging

logger = logging.getLogger(__name__)

# Попытка импорта pysnmp
try:
    from pysnmp.hlapi import (
        getCmd, SnmpEngine, CommunityData,
        UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity
    )
    HAS_PYSNMP = True
except ImportError:
    HAS_PYSNMP = False
    logger.debug("pysnmp не установлен. SNMP-опрос не будет работать. "
                 "Установите: pip install pysnmp-lextudio")


# Стандартные OID-ы из MIB-II (RFC 1213)
SNMP_OIDS = {
    'sysDescr':    '1.3.6.1.2.1.1.1.0',
    'sysObjectID': '1.3.6.1.2.1.1.2.0',
    'sysName':     '1.3.6.1.2.1.1.5.0',
    'sysLocation': '1.3.6.1.2.1.1.6.0',
}

# Маппинг enterprise OID → vendor
_ENTERPRISE_VENDORS = {
    '1.3.6.1.4.1.2021': 'Linux (net-snmp)',
    '1.3.6.1.4.1.8072': 'Linux (net-snmp)',
    '1.3.6.1.4.1.14988': 'MikroTik',
    '1.3.6.1.4.1.9': 'Cisco',
    '1.3.6.1.4.1.2636': 'Juniper',
    '1.3.6.1.4.1.39165': 'Hikvision',
    '1.3.6.1.4.1.1004849': 'Hikvision',
    '1.3.6.1.4.1.3224': 'Juniper (ScreenOS)',
    '1.3.6.1.4.1.25506': 'H3C/HPE',
    '1.3.6.1.4.1.2011': 'Huawei',
    '1.3.6.1.4.1.311': 'Microsoft',
    '1.3.6.1.4.1.11': 'HP',
    '1.3.6.1.4.1.1602': 'Canon',
    '1.3.6.1.4.1.18334': 'Konica Minolta',
    '1.3.6.1.4.1.367': 'Ricoh',
    '1.3.6.1.4.1.2435': 'Brother',
    '1.3.6.1.4.1.253': 'Xerox',
    '1.3.6.1.4.1.6574': 'Synology',
    '1.3.6.1.4.1.24681': 'QNAP',
    '1.3.6.1.4.1.1369': 'Dahua',
    '1.3.6.1.4.1.4413': 'Samsung',
}


def is_available():
    """Доступен ли SNMP-модуль."""
    return HAS_PYSNMP


def snmp_get_info(ip, community='public', timeout=2, port=161):
    """
    Получить базовую информацию по SNMP v2c.

    Args:
        ip: IP-адрес устройства
        community: SNMP community string (по умолчанию 'public')
        timeout: таймаут в секундах
        port: UDP-порт SNMP (по умолчанию 161)

    Returns:
        dict: {'sysDescr': ..., 'sysName': ..., 'sysLocation': ...}
              Пустой dict если SNMP недоступен или не ответил.
    """
    if not HAS_PYSNMP:
        logger.debug(f"SNMP недоступен для {ip}: pysnmp не установлен")
        return {}

    result = {}
    engine = SnmpEngine()

    for name, oid in SNMP_OIDS.items():
        try:
            iterator = getCmd(
                engine,
                CommunityData(community, mpModel=1),  # mpModel=1 = SNMPv2c
                UdpTransportTarget((ip, port), timeout=timeout, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            error_indication, error_status, error_index, var_binds = next(iterator)

            if error_indication:
                logger.debug(f"SNMP {ip} {name}: {error_indication}")
                continue
            if error_status:
                logger.debug(f"SNMP {ip} {name}: error status {error_status}")
                continue

            for var_bind in var_binds:
                value = str(var_bind[1]).strip()
                if value:
                    result[name] = value

        except Exception as e:
            logger.debug(f"SNMP {ip} {name}: {e}")

    if result:
        logger.info(f"SNMP {ip}: {result}")
    else:
        logger.debug(f"SNMP {ip}: нет ответа")

    return result


def _resolve_enterprise_vendor(sys_object_id):
    """Определить vendor по sysObjectID (enterprise OID)."""
    if not sys_object_id:
        return None
    oid = str(sys_object_id)
    # Ищем наиболее длинный совпадающий префикс
    best_match = None
    best_len = 0
    for prefix, vendor in _ENTERPRISE_VENDORS.items():
        if oid.startswith(prefix) and len(prefix) > best_len:
            best_match = vendor
            best_len = len(prefix)
    return best_match


def _extract_model_from_descr(sys_descr_raw):
    """
    Извлечь модель устройства из sysDescr.
    Возвращает (vendor, model) или (None, None).
    """
    import re
    descr = sys_descr_raw.strip()
    descr_lower = descr.lower()

    # Hikvision: "DS-2CD2T47G2-L" или "iDS-2DE5225IW-AE"
    m = re.search(r'(i?DS-[A-Z0-9\-]+)', descr, re.IGNORECASE)
    if m:
        return 'Hikvision', m.group(1)

    # Dahua: "DH-IPC-HFW2831T-ZAS" или "IPC-HFW2831T"
    m = re.search(r'((?:DH-)?IPC-[A-Z0-9\-]+)', descr, re.IGNORECASE)
    if m:
        return 'Dahua', m.group(1)
    m = re.search(r'(DH-[A-Z0-9\-]+)', descr, re.IGNORECASE)
    if m:
        return 'Dahua', m.group(1)

    # HP/HPE принтеры: "HP LaserJet 400 MFP M425dn"
    m = re.search(r'(HP\s+(?:LaserJet|Color\s+LaserJet|OfficeJet|DeskJet)[^;\n]{0,60})', descr, re.IGNORECASE)
    if m:
        return 'HP', m.group(1).strip()

    # Kyocera: "KYOCERA ECOSYS M2040dn"
    m = re.search(r'(KYOCERA\s+[A-Z0-9\s\-]+)', descr, re.IGNORECASE)
    if m:
        return 'Kyocera', m.group(1).strip()

    # Konica Minolta: "KONICA MINOLTA bizhub C258"
    m = re.search(r'(?:KONICA\s+MINOLTA|bizhub)\s+([A-Z0-9\s]+)', descr, re.IGNORECASE)
    if m:
        return 'Konica Minolta', f"bizhub {m.group(1).strip()}"

    # Canon: "Canon iR-ADV C5235"
    m = re.search(r'Canon\s+([A-Za-z0-9\-\s]+)', descr, re.IGNORECASE)
    if m:
        return 'Canon', m.group(1).strip()

    # Xerox: "Xerox WorkCentre 7845"
    m = re.search(r'Xerox\s+([A-Za-z0-9\-\s]+)', descr, re.IGNORECASE)
    if m:
        return 'Xerox', m.group(1).strip()

    # Brother: "Brother HL-L2350DW"
    m = re.search(r'Brother\s+([A-Za-z0-9\-]+)', descr, re.IGNORECASE)
    if m:
        return 'Brother', m.group(1).strip()

    # Ricoh: "RICOH Aficio MP 2352"
    m = re.search(r'RICOH\s+([A-Za-z0-9\-\s]+)', descr, re.IGNORECASE)
    if m:
        return 'Ricoh', m.group(1).strip()

    # MikroTik: "RouterOS CHR 7.14.3"
    if 'routeros' in descr_lower or 'mikrotik' in descr_lower:
        m = re.search(r'RouterOS\s+([^\s]+)', descr, re.IGNORECASE)
        model = m.group(1) if m else 'RouterOS'
        return 'MikroTik', model

    # Samsung: "SNP-6321RH"
    m = re.search(r'(S[ND]P-[A-Z0-9]+)', descr, re.IGNORECASE)
    if m:
        return 'Samsung/Hanwha', m.group(1)

    return None, None


def parse_snmp_os(snmp_info):
    """
    Определить ОС/тип/vendor/model по sysDescr и sysObjectID.

    Args:
        snmp_info: dict из snmp_get_info()

    Returns:
        dict: {'os': ..., 'os_type': ..., 'type': ..., 'vendor': ..., 'model': ...}
              Только заполненные поля. Пустой dict если нечего определить.
    """
    sys_descr = snmp_info.get('sysDescr', '')
    sys_descr_lower = sys_descr.lower()
    if not sys_descr_lower:
        return {}

    result = {}

    # Определяем vendor по sysObjectID (enterprise OID)
    enterprise_vendor = _resolve_enterprise_vendor(snmp_info.get('sysObjectID', ''))
    if enterprise_vendor:
        result['snmp_enterprise_vendor'] = enterprise_vendor

    # Извлекаем vendor/model из sysDescr
    descr_vendor, descr_model = _extract_model_from_descr(sys_descr)
    if descr_vendor:
        result['vendor'] = descr_vendor
    if descr_model:
        result['model'] = descr_model

    # MikroTik RouterOS
    if 'routeros' in sys_descr_lower or 'mikrotik' in sys_descr_lower:
        result['os'] = f"MikroTik RouterOS ({sys_descr[:60]})"
        result['os_type'] = 'linux'
        result['type'] = 'mikrotik'
        result.setdefault('vendor', 'MikroTik')
        return result

    # Cisco IOS / IOS-XE / NX-OS
    if 'cisco' in sys_descr_lower:
        result['os'] = f"Cisco ({sys_descr[:60]})"
        result['os_type'] = 'linux'
        result['type'] = 'network'
        result.setdefault('vendor', 'Cisco')
        return result

    # Камеры — Hikvision, Dahua, Axis и т.д.
    camera_keywords = ['hikvision', 'dahua', 'axis', 'ipcam', 'ip camera', 'network camera']
    if any(kw in sys_descr_lower for kw in camera_keywords):
        result['os'] = 'IP Camera'
        result['os_type'] = 'linux'
        result['type'] = 'camera'
        # Дополнительно: версия прошивки из sysDescr
        import re
        fw = re.search(r'[Vv](\d+\.\d+\.\d+[\w.]*)', sys_descr)
        if fw:
            result['firmware'] = fw.group(1)
        return result

    # Принтеры — HP/Canon/Xerox/Ricoh/Brother/Kyocera
    printer_keywords = ['printer', 'laserjet', 'jetdirect', 'canon', 'xerox',
                        'ricoh', 'konica', 'brother', 'kyocera', 'bizhub', 'ecosys']
    if any(kw in sys_descr_lower for kw in printer_keywords):
        result['os'] = 'Printer'
        result['os_type'] = 'linux'
        result['type'] = 'printer'
        return result

    # Linux
    if 'linux' in sys_descr_lower:
        result['os'] = f"Linux ({sys_descr[:60]})"
        result['os_type'] = 'linux'
        result['type'] = 'server'
        return result

    # Windows
    if 'windows' in sys_descr_lower:
        result['os'] = f"Windows ({sys_descr[:60]})"
        result['os_type'] = 'windows'
        result['type'] = 'server'
        return result

    # NAS: Synology / QNAP
    if 'synology' in sys_descr_lower:
        result['os'] = f"Synology DSM ({sys_descr[:60]})"
        result['os_type'] = 'linux'
        result['type'] = 'server'
        result.setdefault('vendor', 'Synology')
        return result
    if 'qnap' in sys_descr_lower:
        result['os'] = f"QNAP QTS ({sys_descr[:60]})"
        result['os_type'] = 'linux'
        result['type'] = 'server'
        result.setdefault('vendor', 'QNAP')
        return result

    # Если enterprise vendor определён, используем его
    if enterprise_vendor:
        result['os'] = f"{enterprise_vendor} ({sys_descr[:50]})"
        result['os_type'] = 'linux'
        result['type'] = 'network'
        result.setdefault('vendor', enterprise_vendor)
        return result

    # Неизвестное устройство, но SNMP ответил
    result['os'] = f"SNMP Device ({sys_descr[:60]})"
    result['os_type'] = 'linux'
    result['type'] = 'network'
    return result
