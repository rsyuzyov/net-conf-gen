"""Быстрая классификация хоста по портам, MAC vendor и TTL.

Определяет категорию устройства для выбора стратегии сканирования.
НЕ делает сетевых запросов — работает только с уже известными данными.
"""
import logging

logger = logging.getLogger(__name__)

# Категории
WINDOWS = 'windows'
LINUX = 'linux'
MIKROTIK = 'mikrotik'
PRINTER = 'printer'
CAMERA = 'camera'
NETWORK = 'network'
UNKNOWN = 'unknown'

# Маркерные порты
_WINDOWS_PORTS = {135, 5985}
_MIKROTIK_PORTS = {8728, 8729}
_MIKROTIK_WINBOX = 8291
_PRINTER_PORTS = {9100, 515}
_CAMERA_PORTS = {554, 8899, 34567}
_NETWORK_PORTS = {4081, 4040}

# MAC vendor → категория
_VENDOR_CATEGORY = {
    # MikroTik
    'mikrotik': MIKROTIK, 'routerboard': MIKROTIK,
    # Camera
    'hikvision': CAMERA, 'dahua': CAMERA,
    # Printer
    'hewlett packard': PRINTER, 'hp inc': PRINTER,
    'canon': PRINTER, 'epson': PRINTER, 'brother': PRINTER,
    'xerox': PRINTER, 'ricoh': PRINTER, 'konica minolta': PRINTER,
    # Network
    'cisco': NETWORK, 'ubiquiti': NETWORK, 'd-link': NETWORK,
    'netgear': NETWORK, 'juniper': NETWORK, 'aruba': NETWORK,
    'tp-link': NETWORK,
    # Mobile (не сканируем глубоко)
    'xiaomi': UNKNOWN, 'samsung': UNKNOWN, 'apple': UNKNOWN,
    'huawei': UNKNOWN, 'oppo': UNKNOWN, 'vivo': UNKNOWN,
}


def classify(open_ports, mac_vendor='', ttl=None):
    """Классифицирует хост по категории для выбора стратегии сканирования.

    Args:
        open_ports: список открытых портов (из discovery)
        mac_vendor: MAC vendor string (из ARP + mac-vendor-lookup)
        ttl: TTL значение (из ping)

    Returns:
        str: одна из категорий: windows, linux, mikrotik, printer, camera, network, unknown
    """
    ports = set(open_ports or [])

    # 1. Однозначные маркеры MikroTik (API порты)
    if _MIKROTIK_PORTS & ports:
        return MIKROTIK

    # Winbox (8291) — может быть и у HP-принтеров (порт 9100)
    if _MIKROTIK_WINBOX in ports and not (_PRINTER_PORTS & ports):
        return MIKROTIK

    # 2. Камера (RTSP, ONVIF, XMEye)
    if _CAMERA_PORTS & ports:
        return CAMERA

    # 3. Принтер (JetDirect, LPR) — но НЕ если есть Windows-порты
    if _PRINTER_PORTS & ports and not (_WINDOWS_PORTS & ports):
        return PRINTER

    # 4. Windows (RPC, WinRM)
    if _WINDOWS_PORTS & ports:
        return WINDOWS

    # 5. Сетевое оборудование (Kerio admin и т.п.)
    if _NETWORK_PORTS & ports:
        return NETWORK

    # 6. MAC vendor
    if mac_vendor:
        vendor_lower = mac_vendor.lower()
        for pattern, category in _VENDOR_CATEGORY.items():
            if pattern in vendor_lower:
                return category

    # 7. SSH → скорее всего Linux
    if 22 in ports:
        return LINUX

    # 8. TTL fallback
    if ttl is not None:
        if 110 <= ttl <= 128:
            return WINDOWS
        elif 50 <= ttl <= 64:
            return LINUX
        elif ttl > 200:
            return NETWORK

    return UNKNOWN
