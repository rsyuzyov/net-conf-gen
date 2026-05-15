import re

from src.constants import CATEGORY_UNKNOWN, TYPE_UNKNOWN
from src.vendor_db import (
    classify_windows_type,
    collect_host_text,
    detect_from_server_header,
    extract_model_from_realm,
    infer_vendor_from_host,
)


def _hints_from_server_headers(host):
    """Merges hints from Server-headers across all web_probes. First hit wins per key."""
    merged = {}
    for probe in (host.get('web_probes') or {}).values():
        if not isinstance(probe, dict):
            continue
        hints = detect_from_server_header(probe.get('server', ''))
        for key, value in hints.items():
            merged.setdefault(key, value)
    return merged


WINDOWS_PORTS = {135, 139, 445, 3389, 5985, 5986}
WINDOWS_STRONG_PORTS = {3389, 5985, 5986}
DOMAIN_SERVICE_PORTS = {88, 389, 445, 636}
NETWORK_PORTS = {53, 161, 8080, 8443, 8728, 8729, 8291}
PRINTER_PORTS = {515, 631, 9100}
CAMERA_PORTS = {554, 8554, 8899, 34567}
LINUX_MARKERS = ('linux', 'unix', 'debian', 'ubuntu', 'centos', 'rocky', 'almalinux', 'synology', 'qnap', 'webmin', 'miniserv')
NETWORK_MARKERS = (
    'openwrt', 'router', 'switch', 'ubiquiti', 'cisco', 'kerio', 'tp-link', 'nag',
    'rompager', 'virata-emweb', 'switchexplorer', 'gs1910', 'allegro-software',
    'zyxel', 'apc ', 'schneider electric', 'managed ups', 'smart-ups', 'pdu-',
)
WINDOWS_MARKERS = ('windows', 'microsoft rpc', 'microsoft-ds', 'winrm', 'wsman', 'rdp')
CAMERA_MARKERS = ('camera', 'hikvision', 'dahua', 'onvif', 'xmeye', 'rtsp', 'gsoap', 'mobotix', 'wmi v')
PRINTER_MARKERS = (
    'printer',
    'jetdirect',
    'laserjet',
    'ipps',
    'ipp',
    'kyocera',
    'xerox',
    'ricoh',
    'brother',
    'canon',
    'imagerunner',
    'epson',
    'lexmark',
    'pantum',
    'phaser',
)


def _contains_any(text, patterns):
    return any(pattern in text for pattern in patterns)


def _looks_like_printer(text, ports):
    if 8006 in ports or 'proxmox' in text:
        return False
    has_printer_port = bool(PRINTER_PORTS & ports and not ({22, 135, 445} & ports))
    return has_printer_port or _contains_any(text, PRINTER_MARKERS)


def _looks_like_mikrotik(text, ports):
    if {8728, 8729} & ports:
        return True
    if 'routeros' not in text and 'mikrotik' not in text:
        return False
    if _looks_like_printer(text, ports):
        return False
    return True


def _network_model_from_text(text):
    return re.search(
        r'(TL-[A-Z0-9-]+|Archer\s+[A-Z0-9]+|RT-[A-Z0-9-]+|Deco\s+[A-Z0-9]+|DGN\d{3,5}[A-Za-z0-9-]*)',
        text,
        re.IGNORECASE,
    )


def _camera_model_from_text(text):
    return re.search(r'(i?DS-[A-Z0-9-]+|DH-[A-Z0-9-]+|IPC-[A-Z0-9-]+)', text, re.IGNORECASE)


def classify_host(host):
    ports = set(host.get('open_ports', []))
    text = collect_host_text(host)
    hostname = host.get('hostname', '')
    os_name = host.get('os', '')
    vendor = infer_vendor_from_host(host, text)

    category = CATEGORY_UNKNOWN
    if _looks_like_mikrotik(text, ports):
        category = 'mikrotik'
    elif _contains_any(text, ('nanokvm', 'ip-kvm', 'pikvm')):
        category = 'ipkvm'
    elif _looks_like_printer(text, ports):
        category = 'printer'
    elif _contains_any(text, CAMERA_MARKERS) or ({554} & ports and any(v in (vendor or '').lower() for v in ('hikvision', 'dahua'))):
        category = 'camera'
    elif _contains_any(text, NETWORK_MARKERS) or NETWORK_PORTS & ports == {8728} or NETWORK_PORTS & ports == {8729}:
        category = 'network'
    elif _contains_any(text, WINDOWS_MARKERS) or WINDOWS_STRONG_PORTS & ports:
        category = 'windows'
    elif _contains_any(text, LINUX_MARKERS) or (
        22 in ports and (
            _contains_any(text, LINUX_MARKERS + ('openssh', 'dropbear', 'gnu/linux', 'samba'))
            or bool(DOMAIN_SERVICE_PORTS & ports)
        )
    ):
        category = 'linux'

    server_hints = _hints_from_server_headers(host)
    if category == CATEGORY_UNKNOWN and server_hints.get('category'):
        category = server_hints['category']
    if not vendor and server_hints.get('vendor'):
        vendor = server_hints['vendor']

    os_type = ''
    host_type = TYPE_UNKNOWN
    normalized_os = os_name

    if category != 'mikrotik' and normalized_os == 'MikroTik RouterOS':
        normalized_os = ''
    if category != 'printer' and normalized_os == 'Printer':
        normalized_os = ''
    if category != 'camera' and normalized_os == 'IP Camera':
        normalized_os = ''
    if category != 'network' and normalized_os == 'Network Equipment':
        normalized_os = ''

    if category == 'windows':
        os_type = 'windows'
        host_type = classify_windows_type(hostname, ports, os_name)
        if not normalized_os:
            normalized_os = 'Windows Server' if host_type == 'server' else 'Windows'
    elif category in ('linux', 'mikrotik', 'network', 'printer', 'camera', 'ipkvm'):
        os_type = 'linux'
        type_map = {
            'linux': 'server',
            'mikrotik': 'mikrotik',
            'network': 'network',
            'printer': 'printer',
            'camera': 'camera',
            'ipkvm': 'ipkvm',
        }
        host_type = type_map[category]
        if category == 'mikrotik':
            normalized_os = 'MikroTik RouterOS'
        elif category == 'network' and not normalized_os:
            normalized_os = 'Network Equipment'
        elif category == 'printer' and not normalized_os:
            normalized_os = 'Printer'
        elif category == 'camera' and not normalized_os:
            normalized_os = 'IP Camera'

    model = host.get('model', '')
    if not model:
        if category == 'mikrotik' and 'routeros' in text:
            model = 'RouterOS'
        elif category == 'network':
            model_match = _network_model_from_text(text)
            if model_match:
                model = model_match.group(1)
        elif category == 'camera':
            model_match = _camera_model_from_text(text)
            if model_match:
                model = model_match.group(1)

    if not model and category in ('network', 'camera'):
        for probe in (host.get('web_probes') or {}).values():
            if not isinstance(probe, dict):
                continue
            realm_model = extract_model_from_realm(probe.get('www_authenticate', ''))
            if realm_model:
                model = realm_model
                break

    return {
        'category': category,
        'type': host_type,
        'os_type': os_type,
        'os': normalized_os,
        'vendor': vendor,
        'model': model,
    }
