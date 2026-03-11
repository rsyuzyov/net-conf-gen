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
    'sysName':     '1.3.6.1.2.1.1.5.0',
    'sysLocation': '1.3.6.1.2.1.1.6.0',
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


def parse_snmp_os(snmp_info):
    """
    Определить ОС/тип устройства по sysDescr.

    Args:
        snmp_info: dict из snmp_get_info()

    Returns:
        dict: {'os': ..., 'os_type': ..., 'type': ...} или пустой dict
    """
    sys_descr = snmp_info.get('sysDescr', '').lower()
    if not sys_descr:
        return {}

    result = {}

    # MikroTik RouterOS
    if 'routeros' in sys_descr or 'mikrotik' in sys_descr:
        result['os'] = f"MikroTik RouterOS ({snmp_info.get('sysDescr', '')})"
        result['os_type'] = 'linux'
        result['type'] = 'mikrotik'
        return result

    # Cisco IOS / IOS-XE / NX-OS
    if 'cisco' in sys_descr:
        result['os'] = f"Cisco ({snmp_info.get('sysDescr', '')[:60]})"
        result['os_type'] = 'linux'
        result['type'] = 'network'
        return result

    # Linux
    if 'linux' in sys_descr:
        result['os'] = f"Linux ({snmp_info.get('sysDescr', '')[:60]})"
        result['os_type'] = 'linux'
        result['type'] = 'server'
        return result

    # Windows
    if 'windows' in sys_descr:
        result['os'] = f"Windows ({snmp_info.get('sysDescr', '')[:60]})"
        result['os_type'] = 'windows'
        result['type'] = 'server'
        return result

    # Принтеры — часто HP/Canon/Xerox
    printer_keywords = ['printer', 'laserjet', 'jetdirect', 'canon', 'xerox', 'ricoh', 'konica']
    if any(kw in sys_descr for kw in printer_keywords):
        result['os'] = 'Printer'
        result['os_type'] = 'linux'
        result['type'] = 'printer'
        return result

    # Камеры
    camera_keywords = ['hikvision', 'dahua', 'axis', 'ipcam']
    if any(kw in sys_descr for kw in camera_keywords):
        result['os'] = 'IP Camera'
        result['os_type'] = 'linux'
        result['type'] = 'camera'
        return result

    # Неизвестное устройство, но SNMP ответил — скорее network
    result['os'] = f"SNMP Device ({snmp_info.get('sysDescr', '')[:60]})"
    result['os_type'] = 'linux'
    result['type'] = 'network'
    return result
