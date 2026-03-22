import logging
import xml.etree.ElementTree as ET

from src.classification import classify_nmap_host
from src.constants import STATUS_DISCOVERED, STATUS_UNKNOWN
from src.models import HostRecord


logger = logging.getLogger(__name__)


def _service_label(port, service, port_labels=None):
    product = service.get('product', '')
    name = service.get('name', '')
    if product:
        return product
    if name in ('', STATUS_UNKNOWN, 'tcpwrapped') and port_labels:
        return port_labels.get(port, f'Port-{port}')
    if name:
        return name.upper()
    return f'Port-{port}'


def parse_nmap_xml(xml_text, port_labels=None):
    root = ET.fromstring(xml_text)
    records = []

    for host in root.findall('host'):
        status_el = host.find('status')
        if status_el is not None and status_el.get('state') != 'up':
            continue

        ip = ''
        mac = ''
        vendor = ''
        for address in host.findall('address'):
            addr_type = address.get('addrtype')
            if addr_type == 'ipv4':
                ip = address.get('addr', '')
            elif addr_type == 'mac':
                mac = address.get('addr', '').lower()
                vendor = address.get('vendor', '')

        if not ip:
            continue

        hostname_values = []
        hostnames = host.find('hostnames')
        if hostnames is not None:
            for hostname in hostnames.findall('hostname'):
                value = hostname.get('name')
                if value:
                    hostname_values.append(value)

        record = HostRecord(
            ip=ip,
            hostname=hostname_values[0].split('.')[0] if hostname_values else '',
            hostnames=hostname_values,
            mac=mac,
            vendor=vendor,
        )

        ports_el = host.find('ports')
        if ports_el is not None:
            for port_el in ports_el.findall('port'):
                state_el = port_el.find('state')
                if state_el is None or state_el.get('state') != 'open':
                    continue

                port = int(port_el.get('portid'))
                service_el = port_el.find('service')
                service_info = {
                    'name': '',
                    'product': '',
                    'version': '',
                    'extrainfo': '',
                    'tunnel': '',
                    'scripts': {},
                }
                if service_el is not None:
                    for key in ('name', 'product', 'version', 'extrainfo', 'tunnel'):
                        service_info[key] = service_el.get(key, '')

                for script in port_el.findall('script'):
                    script_id = script.get('id', '')
                    output = script.get('output', '')
                    if script_id and output:
                        service_info['scripts'][script_id] = output

                record.open_ports.append(port)
                record.service_details[port] = service_info
                record.services.append(_service_label(port, service_info, port_labels=port_labels))

        hostscript = host.find('hostscript')
        if hostscript is not None:
            for script in hostscript.findall('script'):
                script_id = script.get('id', '')
                output = script.get('output', '')
                if script_id and output:
                    record.scripts[script_id] = output

        os_el = host.find('os')
        if os_el is not None:
            osmatch = os_el.find('osmatch')
            if osmatch is not None:
                record.os = osmatch.get('name', '')

        classified = classify_nmap_host(record.to_dict())
        for key, value in classified.items():
            if value:
                setattr(record, key, value)
        record.scan_status = STATUS_DISCOVERED

        records.append(record)

    logger.info("Parsed %s active hosts from nmap XML", len(records))
    return records
