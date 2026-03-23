import re

from src.constants import CATEGORY_UNKNOWN, TYPE_UNKNOWN
from src.vendor_db import classify_windows_type, collect_host_text, infer_vendor_from_host


WINDOWS_PORTS = {135, 139, 445, 3389, 5985, 5986}
WINDOWS_STRONG_PORTS = {3389, 5985, 5986}
DOMAIN_SERVICE_PORTS = {88, 389, 445, 636}
NETWORK_PORTS = {53, 161, 8080, 8443, 8728, 8729, 8291}
PRINTER_PORTS = {515, 631, 9100}
CAMERA_PORTS = {554, 8554, 8899, 34567}
LINUX_MARKERS = ('linux', 'unix', 'debian', 'ubuntu', 'centos', 'rocky', 'almalinux', 'synology', 'qnap')
NETWORK_MARKERS = ('openwrt', 'router', 'switch', 'ubiquiti', 'cisco', 'kerio', 'tp-link')
WINDOWS_MARKERS = ('windows', 'microsoft rpc', 'microsoft-ds', 'winrm', 'wsman', 'rdp')
CAMERA_MARKERS = ('camera', 'hikvision', 'dahua', 'onvif', 'xmeye', 'rtsp')
PRINTER_MARKERS = ('printer', 'jetdirect', 'laserjet', 'ipps', 'ipp', 'kyocera', 'xerox', 'ricoh', 'brother')


def _contains_any(text, patterns):
    return any(pattern in text for pattern in patterns)


def _network_model_from_text(text):
    return re.search(r'(TL-[A-Z0-9-]+|Archer\s+[A-Z0-9]+|RT-[A-Z0-9-]+|Deco\s+[A-Z0-9]+)', text, re.IGNORECASE)


def _camera_model_from_text(text):
    return re.search(r'(i?DS-[A-Z0-9-]+|DH-[A-Z0-9-]+|IPC-[A-Z0-9-]+)', text, re.IGNORECASE)


def classify_host(host):
    ports = set(host.get('open_ports', []))
    text = collect_host_text(host)
    hostname = host.get('hostname', '')
    os_name = host.get('os', '')
    vendor = infer_vendor_from_host(host, text)

    category = CATEGORY_UNKNOWN
    if {8728, 8729} & ports or 'mikrotik' in text or 'routeros' in text:
        category = 'mikrotik'
    elif _contains_any(text, ('nanokvm', 'ip-kvm', 'pikvm')):
        category = 'ipkvm'
    elif _contains_any(text, CAMERA_MARKERS) or ({554} & ports and any(v in (vendor or '').lower() for v in ('hikvision', 'dahua'))):
        category = 'camera'
    elif (PRINTER_PORTS & ports and not ({22, 135, 445} & ports)) or _contains_any(text, PRINTER_MARKERS):
        category = 'printer'
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

    os_type = ''
    host_type = TYPE_UNKNOWN
    normalized_os = os_name

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

    return {
        'category': category,
        'type': host_type,
        'os_type': os_type,
        'os': normalized_os,
        'vendor': vendor,
        'model': model,
    }
