"""Нормализация vendor/model для нового nmap-centered pipeline."""
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
    'hikvision': 'Hikvision',
    'dahua': 'Dahua',
    'canon': 'Canon',
    'kyocera': 'Kyocera',
    'xerox': 'Xerox',
    'ricoh': 'Ricoh',
    'brother': 'Brother',
    'konica': 'Konica Minolta',
    'synology': 'Synology',
    'qnap': 'QNAP',
    'proxmox': 'Proxmox',
    'cisco': 'Cisco',
    'kerio': 'Kerio',
    'xiaomi': 'Xiaomi',
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

# ===== Server indicator ports =====
SERVER_PORTS = {88, 389, 636, 1540, 1541, 1560, 1561, 2049, 5985}


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
        chunks.extend(details.get('scripts', {}).values())
    chunks.extend(host.get('scripts', {}).values())
    return ' '.join(str(chunk) for chunk in chunks if chunk).lower()


def infer_vendor_from_host(host, text=None):
    """Определяет normalized vendor по MAC и текстовым сигналам."""
    vendor = normalize_mac_vendor(host.get('vendor', ''))
    if vendor:
        return vendor

    text = text if text is not None else collect_host_text(host)
    for pattern, normalized in TEXT_VENDOR_PATTERNS.items():
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
            return vendor, model or title
    return None, None


def _collect_nmap_script_text(host_info):
    chunks = []
    for service in host_info.get('service_details', {}).values():
        for output in service.get('scripts', {}).values():
            if output:
                chunks.append(str(output))
    for output in host_info.get('scripts', {}).values():
        if output:
            chunks.append(str(output))
    return '\n'.join(chunks)


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
    script_text = _collect_nmap_script_text(host_info)
    script_lower = script_text.lower()

    if not http_title:
        title_match = re.search(r'http-title[:\s]+([^\n]+)', script_text, re.IGNORECASE)
        if title_match:
            http_title = title_match.group(1).strip()
        else:
            for service in host_info.get('service_details', {}).values():
                script_title = service.get('scripts', {}).get('http-title')
                if script_title:
                    http_title = script_title.strip()
                    break

    # --- 1. SSL cert issuer ---
    ssl_issuer = ''
    if isinstance(ssl_cert, dict):
        ssl_issuer = ssl_cert.get('issuer_cn', '').lower()
    if not ssl_issuer and 'issuer:' in script_lower:
        issuer_match = re.search(r'issuer[:=]\s*([^\n]+)', script_text, re.IGNORECASE)
        if issuer_match:
            ssl_issuer = issuer_match.group(1).strip().lower()
    if 'kerio' in ssl_issuer:
        vendor = vendor or 'Kerio'
        model = model or 'Kerio Control'
    elif 'proxmox' in ssl_issuer:
        vendor = vendor or 'Proxmox'
        model = model or 'Proxmox VE'

    # --- 2. nmap scripts / SNMP-like data ---
    sys_descr = ''
    if isinstance(snmp_info, dict):
        sys_descr = snmp_info.get('sysDescr', '')
    if not sys_descr:
        descr_match = re.search(r'sysdescr[:=]\s*([^\n]+)', script_text, re.IGNORECASE)
        if descr_match:
            sys_descr = descr_match.group(1).strip()
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

    if not vendor:
        if 'routeros' in script_lower:
            vendor = 'MikroTik'
            model = model or 'RouterOS'
        elif 'hikvision' in script_lower:
            vendor = 'Hikvision'
        elif 'dahua' in script_lower:
            vendor = 'Dahua'
        elif 'kerio' in script_lower:
            vendor = 'Kerio'
        elif 'proxmox' in script_lower:
            vendor = 'Proxmox'

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
