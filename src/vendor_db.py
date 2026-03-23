"""Нормализация vendor/model для current native discovery pipeline."""
import re

from src.os_detection import linux_distro_from_kernel, windows_name_from_kernel

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

# ===== Text patterns → normalized vendor =====
TEXT_VENDOR_PATTERNS = {
    'mikrotik': 'MikroTik',
    'routeros': 'MikroTik',
    'tp-link': 'TP-Link',
    'openwrt': 'OpenWrt',
    'ubiquiti': 'Ubiquiti',
    'netgear': 'Netgear',
    'hikvision': 'Hikvision',
    'dahua': 'Dahua',
    'xmeye': 'XMEye',
    'xmsecu': 'XMEye',
    'web viewer': 'XMEye',
    'canon': 'Canon',
    'imagerunner': 'Canon',
    'nanokvm': 'NanoKVM',
    'lexmark': 'Lexmark',
    'pantum': 'Pantum',
    'phaser': 'Xerox',
    'kyocera': 'Kyocera',
    'xerox': 'Xerox',
    'ricoh': 'Ricoh',
    'brother': 'Brother',
    'epson': 'Epson',
    'konica': 'Konica Minolta',
    'synology': 'Synology',
    'qnap': 'QNAP',
    'proxmox': 'Proxmox',
    'cisco': 'Cisco',
    'kerio': 'Kerio',
    'xiaomi': 'Xiaomi',
    'miwifi': 'Xiaomi',
    '小米路由器': 'Xiaomi',
}

# ===== IOT / Mobile Vendors that should not be classified as servers =====
IOT_VENDORS = {
    'Xiaomi', 'Dreame', 'Samsung', 'Apple', 'Oppo', 'Vivo', 'Huawei',
    'Realme', 'OnePlus', 'Google', 'Amazon', 'Nintendo', 'Sony', 'Lg',
    'Motorola', 'Tuya', 'Espressif', 'Roku', 'Sonos'
}

# ===== HTTP title keywords → (vendor, model) =====
HTTP_TITLE_VENDOR_MAP = {
    'laserjet': ('HP', None),
    'hp ': ('HP', None),
    'canon': ('Canon', None),
    'imagerunner': ('Canon', None),
    'epson': ('Epson', None),
    'brother': ('Brother', None),
    'lexmark': ('Lexmark', None),
    'pantum': ('Pantum', None),
    'phaser': ('Xerox', None),
    'xerox': ('Xerox', None),
    'ricoh': ('Ricoh', None),
    'konica': ('Konica Minolta', None),
    'pi-hole': ('Pi-hole', 'Pi-hole'),
    'proxmox': ('Proxmox', None),
    'synology': ('Synology', None),
    'qnap': ('QNAP', None),
    'mikrotik': ('MikroTik', None),
    'netgear': ('Netgear', None),
    'hikvision': ('Hikvision', None),
    'dahua': ('Dahua', None),
    'ubiquiti': ('Ubiquiti', None),
    'unifi': ('Ubiquiti', None),
    'kerio': ('Kerio', None),
    'nanokvm': ('NanoKVM', 'NanoKVM'),
    '小米路由器': ('Xiaomi', 'Mi Router'),
}

# ===== Server indicator ports =====
SERVER_PORTS = {88, 389, 636, 1540, 1541, 1560, 1561, 2049, 5985}

CANON_MODEL_RE = re.compile(
    r'\b('
    r'MF\d{3,4}(?:/\d{3})?\s+Series'
    r'|LBP\d{3,4}'
    r'|imageRUNNER\s*\d+[A-Za-z]*\s*series'
    r')\b',
    re.IGNORECASE,
)
HP_MODEL_RE = re.compile(r'\bHP\s+(LaserJet(?:\s+Professional)?(?:\s+(?!\d{1,3}(?:\.\d{1,3}){3}\b)[A-Z0-9-]+){1,3})\b', re.IGNORECASE)
BROTHER_MODEL_RE = re.compile(r'\b((?:DCP|MFC|HL|ADS|PT|QL)-[A-Z0-9]+(?:\s+series)?)\b', re.IGNORECASE)
LEXMARK_MODEL_RE = re.compile(r'\b(?:Lexmark\s+)?((?:MX|MS|CS|CX|XM|C|M|B)\d{3,4}[A-Za-z]{0,4})\b')
XEROX_MODEL_RE = re.compile(r'\b(Phaser\s+[A-Z0-9-]+)\b', re.IGNORECASE)
PANTUM_MODEL_RE = re.compile(r'\b((?:BP|BM|CM|CP|M|P)\d{4,5}[A-Z]{0,4})\b')
NETGEAR_MODEL_RE = re.compile(r'\bNETGEAR(?:\s+Router)?\s+([A-Z]{2,5}\d{3,5}[A-Za-z0-9-]*)\b', re.IGNORECASE)


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


def collect_host_text(host):
    """Собирает текстовые сигналы хоста в одну строку для эвристик."""
    chunks = [
        host.get('vendor', ''),
        host.get('hostname', ''),
        host.get('os', ''),
    ]
    for details in host.get('service_details', {}).values():
        chunks.extend([
            details.get('name', ''),
            details.get('product', ''),
            details.get('version', ''),
            details.get('extrainfo', ''),
        ])
    for probe in host.get('web_probes', {}).values():
        chunks.extend([
            probe.get('server', ''),
            probe.get('title', ''),
            probe.get('location', ''),
            probe.get('content_type', ''),
            probe.get('auth_scheme', ''),
            probe.get('tls_subject', ''),
            probe.get('tls_issuer', ''),
        ])
        chunks.extend(probe.get('tls_san', []))
    return ' '.join(str(chunk) for chunk in chunks if chunk).lower()


def infer_vendor_from_host(host, text=None):
    """Определяет normalized vendor по MAC и текстовым сигналам."""
    text = text if text is not None else collect_host_text(host)
    ports = set(host.get('open_ports', []) or [])
    category = str(host.get('category', '') or '').lower()
    host_type = str(host.get('type', '') or '').lower()
    has_camera_shape = category == 'camera' or host_type == 'camera' or 554 in ports
    nas_text_chunks = [
        str(host.get('hostname', '') or ''),
        str(host.get('os', '') or ''),
    ]
    for probe in (host.get('web_probes') or {}).values():
        if not isinstance(probe, dict):
            continue
        nas_text_chunks.extend([
            str(probe.get('title', '') or ''),
            str(probe.get('server', '') or ''),
            str(probe.get('location', '') or ''),
            str(probe.get('content_type', '') or ''),
        ])
    nas_text = ' '.join(nas_text_chunks).lower()
    strong_nas_signal = any(
        signal in nas_text
        for signal in (
            'diskstation',
            'disk station',
            'synology dsm',
            'web station',
            'qnap',
            'qts',
            'qumagie',
        )
    )
    vendor = normalize_mac_vendor(host.get('vendor', ''))
    if vendor:
        if not (vendor in ('Synology', 'QNAP') and has_camera_shape and not strong_nas_signal):
            return vendor

    for probe in (host.get('web_probes') or {}).values():
        if not isinstance(probe, dict):
            continue
        title_vendor, _ = detect_vendor_from_http_title(str(probe.get('title', '') or ''))
        if title_vendor:
            return title_vendor
        realm_vendor, _ = detect_vendor_from_http_title(str(probe.get('www_authenticate', '') or ''))
        if realm_vendor:
            return realm_vendor

    for pattern, normalized in TEXT_VENDOR_PATTERNS.items():
        if normalized in ('Synology', 'QNAP') and has_camera_shape and not strong_nas_signal:
            continue
        if pattern in text:
            return normalized
    return ''


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
            return vendor, model
    return None, None


def _clean_model(model):
    if not model:
        return ''
    cleaned = re.sub(r'\s{2,}', ' ', str(model)).strip(' -:\t\r\n')
    return cleaned.strip()


def extract_model_from_web_text(vendor, probe):
    if not vendor or not isinstance(probe, dict):
        return ''

    http_title = str(probe.get('title', '')).strip()
    tls_subject = str(probe.get('tls_subject', '')).strip()
    tls_issuer = str(probe.get('tls_issuer', '')).strip()
    location = str(probe.get('location', '')).strip()
    candidates = [http_title, tls_subject, tls_issuer, location]

    for value in candidates:
        if not value:
            continue
        if vendor == 'Canon':
            match = CANON_MODEL_RE.search(value)
            if match:
                return _clean_model(match.group(1))
        elif vendor == 'HP':
            match = HP_MODEL_RE.search(value)
            if match:
                return _clean_model(match.group(1))
        elif vendor == 'Brother':
            match = BROTHER_MODEL_RE.search(value)
            if match:
                return _clean_model(match.group(1))
        elif vendor == 'Lexmark':
            match = LEXMARK_MODEL_RE.search(value)
            if match:
                return _clean_model(match.group(1))
        elif vendor == 'Xerox':
            match = XEROX_MODEL_RE.search(value)
            if match:
                return _clean_model(match.group(1))
        elif vendor == 'Pantum':
            match = PANTUM_MODEL_RE.search(value)
            if match:
                return _clean_model(match.group(1))
        elif vendor == 'Netgear':
            match = NETGEAR_MODEL_RE.search(value)
            if match:
                return _clean_model(match.group(1))

    return ''


def _collect_web_candidates(update_data, host_info):
    probes = update_data.get('web_probes')
    if probes is None:
        probes = host_info.get('web_probes', {})
    if not isinstance(probes, dict):
        return []

    ordered = []
    for port, probe in probes.items():
        if not isinstance(probe, dict):
            continue
        try:
            numeric_port = int(port)
        except (TypeError, ValueError):
            numeric_port = 0
        ordered.append((numeric_port, probe))
    ordered.sort(key=lambda item: item[0])
    return [probe for _, probe in ordered]


def determine_vendor_model(update_data, host_info):
    """Определяет vendor и model по всем источникам.

    Приоритет:
      1. Web/TLS fingerprints
      2. OS / hostname
      3. MAC vendor (fallback)

    Записывает 'vendor' и 'model' в update_data.
    """
    vendor = ''
    model = ''
    mac_vendor = host_info.get('vendor', '')
    os_name = update_data.get('os', '')
    host_type = update_data.get('type', '')
    web_probes = _collect_web_candidates(update_data, host_info)

    # --- 1. Web/TLS fingerprints ---
    for probe in web_probes:
        http_title = str(probe.get('title', '')).strip()
        auth_scheme = str(probe.get('auth_scheme', '')).lower()
        tls_issuer = str(probe.get('tls_issuer', '')).lower()
        web_text = ' '.join([
            http_title,
            str(probe.get('server', '')),
            str(probe.get('location', '')),
            str(probe.get('tls_subject', '')),
            str(probe.get('tls_issuer', '')),
            ' '.join(probe.get('tls_san', [])),
        ]).lower()

        if 'kerio' in tls_issuer or 'kerio' in web_text:
            vendor = vendor or 'Kerio'
            model = model or 'Kerio Control'
        elif 'proxmox' in tls_issuer or 'proxmox' in web_text:
            vendor = vendor or 'Proxmox'
            model = model or 'Proxmox VE'
        elif 'routeros' in web_text or 'mikrotik' in web_text:
            vendor = vendor or 'MikroTik'
            model = model or 'RouterOS'

        if http_title:
            title_v, title_m = detect_vendor_from_http_title(http_title)
            if title_v:
                vendor = vendor or title_v
            if title_m:
                model = model or title_m

        candidate_vendor = vendor or update_data.get('vendor', '') or host_info.get('vendor', '')
        if candidate_vendor and not model:
            extracted_model = extract_model_from_web_text(candidate_vendor, probe)
            if extracted_model:
                model = extracted_model

        if auth_scheme == 'basic' and probe.get('scheme') in ('http', 'https') and not model:
            model = 'HTTP Basic Auth'

    # --- 2. OS / hostname ---
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

    # --- 3. Hostname-based ---
    hostname = update_data.get('hostname', '') or host_info.get('hostname', '')
    if hostname and not vendor:
        if hostname.upper().startswith('NPI'):
            vendor = 'HP'

    # --- 4. MAC vendor (fallback) ---
    if mac_vendor:
        normalized = normalize_mac_vendor(mac_vendor)
        # Если это ПК или сервер, то MAC-вендор (Realtek, Intel, Proxmox, VMware) обычно не является системным вендором
        if host_type in ('server', 'workstation', 'windows', 'linux'):
            ignore_vendors = ['realtek', 'intel', 'proxmox', 'vmware', 'qemu', 'asrock', 'gigabyte', 'micro-star', 'azurewave', 'liteon', 'hon hai', 'shenzhen', 'microsoft']
            if not any(ign in normalized.lower() for ign in ignore_vendors):
                vendor = vendor or normalized
        else:
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
