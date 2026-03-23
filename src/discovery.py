import asyncio
import ipaddress
import json
import logging
import os
import re
import subprocess

from src.classification import classify_host
from src.constants import STATUS_DISCOVERED
from src.models import HostRecord
from src.utils import reverse_dns_name


logger = logging.getLogger(__name__)

TIMEOUT = 0.5
CONCURRENCY_LIMIT = 1000
PTR_PORT_HINTS = {88, 135, 389, 445, 3389, 5985, 5986}
PTR_SERVICE_HINTS = {'KERBEROS', 'RPC', 'LDAP', 'LDAPS', 'SMB', 'RDP', 'WINRM'}


def load_port_config(config_path='ports.json'):
    if not os.path.isabs(config_path):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        config_path = os.path.join(project_root, config_path)

    with open(config_path, 'r', encoding='utf-8') as f:
        ports_dict = json.load(f)

    ports_list = []
    port_to_service = {}
    for port_str, service in ports_dict.items():
        port = int(port_str)
        ports_list.append(port)
        port_to_service[port] = service
    return sorted(ports_list), port_to_service


def get_arp_table():
    arp_map = {}
    try:
        output = subprocess.check_output(['arp', '-a'], stderr=subprocess.DEVNULL)
        for encoding in ('cp866', 'cp1251', 'utf-8'):
            try:
                output_str = output.decode(encoding, errors='ignore')
                break
            except UnicodeDecodeError:
                continue
        else:
            output_str = output.decode('utf-8', errors='ignore')

        regex = r'(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})'
        for line in output_str.splitlines():
            match = re.search(regex, line)
            if not match:
                continue
            ip = match.group(1)
            mac = match.group(2).replace('-', ':').lower()
            arp_map[ip] = mac
    except Exception as e:
        logger.warning("Failed to get ARP table: %s", e)

    return arp_map


class NativeDiscovery:
    def __init__(self, ports_file='ports.json'):
        self.target_ports, self.port_to_service = load_port_config(ports_file)

    async def _check_port(self, ip, port, sem):
        async with sem:
            try:
                conn = asyncio.open_connection(str(ip), port)
                reader, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return True
            except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                return False
            except Exception:
                return False

    async def _scan_host(self, ip, sem):
        open_ports = []
        services = []
        service_details = {}

        for port in self.target_ports:
            if not await self._check_port(ip, port, sem):
                continue
            open_ports.append(port)
            service_name = self.port_to_service.get(port, f'Port-{port}')
            services.append(service_name)
            service_details[port] = {
                'name': '',
                'product': service_name,
                'version': '',
                'extrainfo': '',
                'tunnel': '',
            }

        if not open_ports:
            return None

        return {
            'ip': str(ip),
            'open_ports': sorted(open_ports),
            'services': services,
            'service_details': service_details,
        }

    async def _run_async_scan(self, hosts):
        sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
        tasks = [self._scan_host(ip, sem) for ip in hosts]
        return await asyncio.gather(*tasks)

    def scan(self, subnets, exclusions=None):
        target_ips = set()
        excluded = set(exclusions or [])

        for subnet_str in subnets:
            try:
                network = ipaddress.ip_network(subnet_str, strict=False)
            except ValueError:
                logger.error("Invalid subnet: %s", subnet_str)
                continue
            for ip in network.hosts():
                ip_str = str(ip)
                if ip_str not in excluded:
                    target_ips.add(ip)

        if not target_ips:
            return []

        logger.info("Starting native discovery scan for %s targets...", len(target_ips))
        results = asyncio.run(self._run_async_scan(sorted(target_ips)))
        arp_table = get_arp_table()

        records = []
        active_ips = set()
        for result in results:
            if not result:
                continue
            active_ips.add(result['ip'])
            record = HostRecord(
                ip=result['ip'],
                open_ports=result['open_ports'],
                services=result['services'],
                service_details=result['service_details'],
                mac=arp_table.get(result['ip'], ''),
            )
            if self._should_resolve_ptr(result['open_ports'], result['services']):
                hostname, hostnames = reverse_dns_name(result['ip'])
                if hostname:
                    record.hostname = hostname
                    record.hostnames = hostnames
            classified = classify_host(record.to_dict())
            for key, value in classified.items():
                if value:
                    setattr(record, key, value)
            record.scan_status = STATUS_DISCOVERED
            records.append(record)

        for arp_ip, mac in arp_table.items():
            if arp_ip in active_ips or arp_ip in excluded:
                continue
            try:
                ip_obj = ipaddress.ip_address(arp_ip)
            except ValueError:
                continue
            if ip_obj not in target_ips:
                continue
            record = HostRecord(
                ip=arp_ip,
                mac=mac,
            )
            classified = classify_host(record.to_dict())
            for key, value in classified.items():
                if value:
                    setattr(record, key, value)
            record.scan_status = STATUS_DISCOVERED
            records.append(record)

        logger.info("Native discovery found %s active hosts", len(records))
        return records
    def _should_resolve_ptr(self, open_ports, services):
        if PTR_PORT_HINTS & set(open_ports or []):
            return True
        service_names = {str(service).upper() for service in (services or [])}
        return bool(PTR_SERVICE_HINTS & service_names)
