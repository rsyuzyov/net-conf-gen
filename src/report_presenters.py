import html
import re
from datetime import datetime

from src.constants import STATUS_UNKNOWN


WEB_PORTS = {
    80: 'http', 443: 'https',
    8080: 'http', 8443: 'https',
    8006: 'https',
    4081: 'https',
    9090: 'http',
    3000: 'http',
    8291: 'http',
    8728: 'http',
}

SERVICE_TO_PORT = {
    'HTTP': 80, 'HTTPS': 443,
    'HTTP-Alt': 8080, 'HTTPS-Alt': 8443,
    'Proxmox': 8006, 'Kerio-Admin': 4081,
    'Prometheus': 9090, 'Grafana': 3000,
}

CSV_KEYS = [
    'ip', 'hostname', 'type', 'os_type', 'os', 'vendor', 'model', 'mac',
    'scan_status', 'auth_method', 'open_ports', 'services', 'last_updated'
]


def field_value(host, name, default=''):
    if hasattr(host, name):
        value = getattr(host, name)
        return default if value is None else value
    if isinstance(host, dict):
        value = host.get(name, default)
        return default if value is None else value
    getter = getattr(host, 'get', None)
    if getter:
        value = getter(name, default)
        return default if value is None else value
    return default


def escape_value(value):
    if value is None or value == '':
        return ''
    return html.escape(str(value))


def format_datetime(dt_str, logger=None):
    if not dt_str:
        return ''
    try:
        dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        if logger:
            logger.warning("Некорректный формат datetime: %s, %s", dt_str, e)
        return str(dt_str)


def make_link(label, link_type, ip, hostname, domain, port='', user='', target=''):
    fqdn = f"{hostname}.{domain}" if hostname and domain else ip
    target_attr = f' target="{target}"' if target else ''
    return (f'<a class="host-link" href="#"'
            f' data-ip="{html.escape(ip)}"'
            f' data-name="{html.escape(hostname or ip)}"'
            f' data-fqdn="{html.escape(fqdn)}"'
            f' data-type="{link_type}"'
            f' data-port="{port}"'
            f' data-user="{html.escape(user)}"'
            f'{target_attr}>{label}</a>')


def format_ports_html(ip, hostname, ports, domain, ssh_user=None):
    if not ports:
        return ''
    if not isinstance(ports, list):
        return html.escape(str(ports))
    parts = []
    for port in sorted(ports):
        if port == 22:
            parts.append(make_link(str(port), 'ssh', ip, hostname, domain, user=ssh_user or ''))
        elif port == 3389:
            parts.append(make_link(str(port), 'rdp', ip, hostname, domain))
        elif port == 445:
            parts.append(make_link(str(port), 'smb', ip, hostname, domain))
        elif port in (5985, 5986):
            parts.append(make_link(str(port), 'winrm', ip, hostname, domain, user=ssh_user or ''))
        elif port in WEB_PORTS:
            proto = WEB_PORTS[port]
            parts.append(make_link(str(port), proto, ip, hostname, domain, port=str(port), target='_blank'))
        else:
            parts.append(str(port))
    return ', '.join(parts)


def format_services_html(ip, hostname, services, open_ports, domain, ssh_user=None):
    if not services:
        return ''
    if not isinstance(services, list):
        return html.escape(str(services))
    open_ports_set = set(open_ports) if open_ports else set()
    parts = []
    for svc in services:
        if svc == 'SSH' and 22 in open_ports_set:
            parts.append(make_link('SSH', 'ssh', ip, hostname, domain, user=ssh_user or ''))
        elif svc == 'RDP' and 3389 in open_ports_set:
            parts.append(make_link('RDP', 'rdp', ip, hostname, domain))
        elif svc == 'SMB' and 445 in open_ports_set:
            parts.append(make_link('SMB', 'smb', ip, hostname, domain))
        elif svc == 'WinRM' and (5985 in open_ports_set or 5986 in open_ports_set):
            parts.append(make_link('WinRM', 'winrm', ip, hostname, domain, user=ssh_user or ''))
        else:
            port = SERVICE_TO_PORT.get(svc)
            if port and port in open_ports_set and port in WEB_PORTS:
                proto = WEB_PORTS[port]
                parts.append(make_link(html.escape(svc), proto, ip, hostname, domain, port=str(port), target='_blank'))
            else:
                parts.append(html.escape(svc))
    return ', '.join(parts)


def inventory_group_for_host(host):
    os_type = str(field_value(host, 'os_type', '')).lower()
    host_type = str(field_value(host, 'type', '')).lower()
    vendor = str(field_value(host, 'vendor', '')).lower()
    os_name = str(field_value(host, 'os', '')).lower()

    if host_type == 'mikrotik' or 'mikrotik' in vendor or 'routerboard' in vendor or 'mikrotik' in os_name:
        return 'mikrotik', None
    if host_type == 'printer':
        return 'printers', None
    if host_type == 'camera':
        return 'cameras', None
    if host_type == 'network':
        return 'network_devices', None
    if os_type == 'windows':
        return 'windows', 'windows_servers' if host_type == 'server' else 'windows_workstations'
    if os_type == 'linux':
        return 'linux', 'linux_servers' if host_type == 'server' else None
    return STATUS_UNKNOWN, None


def ansible_connection_for_host(auth_method=''):
    return auth_method if auth_method in ('ssh', 'winrm', 'psexec') else None


def csv_row_for_host(host, get_scan_status, get_primary_auth_method, format_ports, format_services):
    row = {key: field_value(host, key, '') for key in CSV_KEYS}
    row['scan_status'] = get_scan_status(host)
    row['auth_method'] = get_primary_auth_method(host)
    if isinstance(row.get('open_ports'), list):
        row['open_ports'] = format_ports(row['open_ports'])
    if isinstance(row.get('services'), list):
        row['services'] = format_services(row['services'])
    return row


def html_row_for_host(host, domain, sanitize_host_alias, get_primary_auth_method, get_scan_status):
    os_type = field_value(host, 'os_type', '')
    ip = field_value(host, 'ip', '')
    raw_hostname = field_value(host, 'hostname', '')
    hostname = sanitize_host_alias(raw_hostname) or raw_hostname
    user = field_value(host, 'user', '')
    auth_method = get_primary_auth_method(host)
    scan_status = get_scan_status(host)
    row_class = f"host-{os_type}"
    status_class = re.sub(r'[^a-z0-9]+', '-', scan_status.lower()).strip('-')
    if status_class:
        row_class += f" scan-{status_class}"

    open_ports = field_value(host, 'open_ports', [])
    services = field_value(host, 'services', [])
    ports_html = format_ports_html(ip, hostname, open_ports, domain, ssh_user=user)
    services_html = format_services_html(ip, hostname, services, open_ports, domain, ssh_user=user)

    if auth_method == 'ssh' and user:
        auth_html = make_link(html.escape(auth_method), 'ssh', ip, hostname, domain, user=user)
    elif auth_method in ('winrm', 'psexec') and 3389 in (open_ports or []):
        auth_html = make_link(html.escape(auth_method), 'rdp', ip, hostname, domain)
    else:
        auth_html = escape_value(auth_method)

    os_val = field_value(host, 'os', '')
    model_val = field_value(host, 'model', '')
    if os_val and model_val and (model_val.lower() in os_val.lower() or os_val.lower() == model_val.lower()):
        model_val = ''

    vendor_val = field_value(host, 'vendor', '')
    if field_value(host, 'type', '') in ('server', 'workstation'):
        ignore_vendors = [
            'realtek', 'intel', 'vmware', 'qemu', 'asrock',
            'gigabyte', 'micro-star', 'azurewave', 'liteon', 'hon hai',
            'shenzhen'
        ]
        if any(ign in vendor_val.lower() for ign in ignore_vendors):
            vendor_val = ''

    return f"""                <tr class="{row_class}">
                    <td>{escape_value(field_value(host, 'ip'))}</td>
                    <td>{escape_value(raw_hostname)}</td>
                    <td>{escape_value(field_value(host, 'type'))}</td>
                    <td>{escape_value(field_value(host, 'os_type'))}</td>
                    <td>{escape_value(os_val)}</td>
                    <td>{escape_value(vendor_val)}</td>
                    <td>{escape_value(model_val)}</td>
                    <td>{escape_value(field_value(host, 'mac'))}</td>
                    <td>{escape_value(scan_status)}</td>
                    <td title="{escape_value(user)}">{auth_html}</td>
                    <td>{ports_html}</td>
                    <td>{services_html}</td>
                    <td>{escape_value(format_datetime(field_value(host, 'last_updated')))}</td>
                </tr>
"""
