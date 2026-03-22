"""База данных vendor/model и логика определения.

Одна точка правды для всех маппингов vendor → normalized name,
HTTP title → vendor/model, hostname → type, etc.
"""
import re
import logging

from src.os_detection import linux_distro_from_kernel, windows_name_from_kernel

logger = logging.getLogger(__name__)


# ===== MAC vendor → нормализованный vendor =====
MAC_VENDOR_MAP = {
    'hewlett packard': 'HP',
    'hp inc': 'HP',
    'routerboard': 'MikroTik',
    'mikrotik': 'MikroTik',
    'tp-link': 'TP-Link',
    'cisco': 'Cisco',
    'ubiquiti': 'Ubiquiti',
    'd-link': 'D-Link',
    'netgear': 'Netgear',
    'juniper': 'Juniper',
    'aruba': 'Aruba',
    'apple': 'Apple',
    'samsung': 'Samsung',
    'xiaomi': 'Xiaomi',
    'huawei': 'Huawei',
    'canon': 'Canon',
    'epson': 'Epson',
    'brother': 'Brother',
    'xerox': 'Xerox',
    'ricoh': 'Ricoh',
    'konica minolta': 'Konica Minolta',
    'intel': 'Intel',
    'dell': 'Dell',
    'lenovo': 'Lenovo',
    'asus': 'ASUS',
    'espressif': 'Espressif',
    'tuya': 'Tuya',
    'hikvision': 'Hikvision',
    'dahua': 'Dahua',
}

# ===== HTTP title keywords → (vendor, model) =====
HTTP_TITLE_VENDOR_MAP = {
    'laserjet': ('HP', None),
    'hp ': ('HP', None),
    'canon': ('Canon', None),
    'epson': ('Epson', None),
    'brother': ('Brother', None),
    'xerox': ('Xerox', None),
    'ricoh': ('Ricoh', None),
    'konica': ('Konica Minolta', None),
    'pi-hole': ('Pi-hole', 'Pi-hole'),
    'proxmox': ('Proxmox', None),
    'synology': ('Synology', None),
    'qnap': ('QNAP', None),
    'mikrotik': ('MikroTik', None),
    'hikvision': ('Hikvision', None),
    'dahua': ('Dahua', None),
    'ubiquiti': ('Ubiquiti', None),
    'unifi': ('Ubiquiti', None),
    'kerio': ('Kerio', None),
}

# ===== Camera title keywords → (vendor, model) =====
CAMERA_TITLE_KEYWORDS = {
    'netsurveillance': ('XMEye', 'NETSurveillance DVR/NVR'),
    'webpackspa': ('Hikvision', 'IP Camera'),
    'web viewer': ('Samsung/Hanwha', 'IP Camera'),
    'hikvision': ('Hikvision', 'IP Camera'),
    'dahua': ('Dahua', 'IP Camera'),
    'ipcamera': (None, 'IP Camera'),
    'ip camera': (None, 'IP Camera'),
    'dvr': (None, 'DVR'),
    'nvr': (None, 'NVR'),
    'xmeye': ('XMEye', 'DVR/NVR'),
    'surveillance': (None, None),
    'onvif': (None, None),
}

# ===== Printer hostname prefixes =====
PRINTER_HOSTNAME_PREFIXES = ('npi', 'km')
PRINTER_TITLE_KEYWORDS = ('laserjet', 'canon', 'epson', 'brother', 'xerox', 'ricoh', 'konica', 'lbp')

# ===== Camera ports =====
CAMERA_PORTS = {554, 8899, 34567}

# ===== Server indicator ports =====
SERVER_PORTS = {88, 389, 636, 1540, 1541, 1560, 1561, 2049, 5985}

# ===== Network equipment vendors =====
NETWORK_VENDORS = ('TP-Link', 'ASUS', 'D-Link', 'Netgear', 'Tenda', 'Zyxel')


def normalize_mac_vendor(raw_vendor):
    """Нормализует MAC vendor name по маппингу.

    Returns:
        str: Нормализованный vendor или исходная строка.
    """
    if not raw_vendor:
        return ''
    vendor_lower = raw_vendor.lower()
    for pattern, normalized in MAC_VENDOR_MAP.items():
        if pattern in vendor_lower:
            return normalized
    return raw_vendor


def classify_windows_type(hostname, open_ports, os_name=''):
    """Уточнение типа Windows: server vs workstation.

    Единственное место в коде для этой логики.
    """
    if os_name and 'server' in os_name.lower():
        return 'server'
    if hostname and hostname.lower().startswith('srv-'):
        return 'server'
    if SERVER_PORTS & set(open_ports or []):
        return 'server'
    return 'workstation'


def detect_vendor_from_http_title(title):
    """Определяет vendor по HTTP title.

    Returns:
        tuple: (vendor, model) или (None, None)
    """
    if not title:
        return None, None
    title_lower = title.lower()
    for kw, (vendor, model) in HTTP_TITLE_VENDOR_MAP.items():
        if kw in title_lower:
            return vendor, model or title
    return None, None


def detect_camera_from_title(title):
    """Определяет, является ли устройство камерой по HTTP title.

    Returns:
        tuple: (is_camera, vendor, model)
    """
    if not title:
        return False, None, None
    title_lower = title.lower()
    vendor = None
    model = None
    is_camera = False
    for kw, (v, m) in CAMERA_TITLE_KEYWORDS.items():
        if kw in title_lower:
            is_camera = True
            if v and not vendor:
                vendor = v
            if m and not model:
                model = m
    return is_camera, vendor, model


def is_printer_by_hostname(hostname):
    """Определяет, является ли устройство принтером по hostname."""
    if not hostname:
        return False
    return hostname.lower().startswith(PRINTER_HOSTNAME_PREFIXES)


def is_printer_by_title(title):
    """Определяет, является ли устройство принтером по HTTP title."""
    if not title:
        return False
    title_lower = title.lower()
    return any(kw in title_lower for kw in PRINTER_TITLE_KEYWORDS)


def determine_vendor_model(update_data, host_info):
    """Определяет vendor и model по всем источникам.

    Приоритет:
      1. SSL cert issuer
      2. SNMP sysDescr
      3. HTTP title
      4. OS / hostname
      5. MAC vendor (fallback)

    Записывает 'vendor' и 'model' в update_data.
    """
    vendor = ''
    model = ''
    mac_vendor = host_info.get('vendor', '')
    os_name = update_data.get('os', '')
    http_title = update_data.get('http_title', '')
    ssl_cert = update_data.get('ssl_cert', {})
    snmp_info = update_data.get('snmp_info', {})
    host_type = update_data.get('type', '')

    # --- 1. SSL cert issuer ---
    ssl_issuer = ''
    if isinstance(ssl_cert, dict):
        ssl_issuer = ssl_cert.get('issuer_cn', '').lower()
    if 'kerio' in ssl_issuer:
        vendor = vendor or 'Kerio'
        model = model or 'Kerio Control'
    elif 'proxmox' in ssl_issuer:
        vendor = vendor or 'Proxmox'
        model = model or 'Proxmox VE'

    # --- 2. SNMP sysDescr ---
    sys_descr = ''
    if isinstance(snmp_info, dict):
        sys_descr = snmp_info.get('sysDescr', '')
    if sys_descr:
        sd_lower = sys_descr.lower()
        if 'routeros' in sd_lower or 'mikrotik' in sd_lower:
            vendor = vendor or 'MikroTik'
            model = model or sys_descr.strip()[:80]
        elif 'cisco' in sd_lower:
            vendor = vendor or 'Cisco'
            model = model or sys_descr.strip()[:80]
        elif 'linux' in sd_lower:
            model = model or sys_descr.strip()[:80]
        elif 'windows' in sd_lower:
            vendor = vendor or 'Microsoft'
            model = model or sys_descr.strip()[:80]

    # --- 3. HTTP title ---
    if http_title:
        title_v, title_m = detect_vendor_from_http_title(http_title)
        if title_v:
            vendor = vendor or title_v
        if title_m:
            model = model or title_m

    # --- 4. OS / hostname ---
    if os_name:
        os_lower = os_name.lower()
        if 'mikrotik' in os_lower:
            vendor = vendor or 'MikroTik'
            model = model or 'RouterOS'
        elif 'kerio' in os_lower:
            vendor = vendor or 'Kerio'
            model = model or 'Kerio Control'
        elif 'proxmox' in os_lower:
            vendor = vendor or 'Proxmox'
            model = model or 'Proxmox VE'
        elif 'windows' in os_lower:
            vendor = vendor or 'Microsoft'
            if not model:
                kernel_ver = host_info.get('kernel_version', '')
                if kernel_ver:
                    model = windows_name_from_kernel(kernel_ver, is_server=(host_type == 'server'))
                if not model and os_name != 'Windows' and 'windows' in os_lower:
                    clean = os_name.replace('Microsoft ', '').strip()
                    if clean and clean != 'Windows':
                        model = clean
        elif 'linux' in os_lower or 'unix' in os_lower:
            if not model:
                distro = host_info.get('distribution', '')
                if distro:
                    model = distro
                elif os_name not in ('Linux', 'Linux/Unix', 'Unknown'):
                    model = os_name
                else:
                    kernel_ver = host_info.get('kernel_version', '')
                    if kernel_ver:
                        model = linux_distro_from_kernel(kernel_ver)

    # --- 5. Hostname-based ---
    hostname = update_data.get('hostname', '') or host_info.get('hostname', '')
    if hostname and not vendor:
        if hostname.upper().startswith('NPI'):
            vendor = 'HP'

    # --- 6. MAC vendor (fallback) ---
    if mac_vendor:
        normalized = normalize_mac_vendor(mac_vendor)
        vendor = vendor or normalized

    # --- Санитизация model ---
    if model:
        model = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '', model).strip()
        model = re.sub(r'\s{2,}', ' ', model).strip()
        if re.search(r'(Apache|nginx|OpenSSL|httpd)', model, re.IGNORECASE):
            model = ''

    if vendor:
        update_data['vendor'] = vendor
    if model:
        update_data['model'] = model
