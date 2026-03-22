import logging
import json
import re
import shlex

import paramiko

from src.constants import STATUS_COMPLETED, STATUS_VIRTUALIZATION_COMPLETED
from src.credentials import CredentialManager
from src.models import HostRecord
from src.utils import normalize_os_name
from src.vendor_db import determine_vendor_model, classify_windows_type


logger = logging.getLogger(__name__)
logging.getLogger('paramiko').setLevel(logging.WARNING)
logging.getLogger('paramiko.transport').setLevel(logging.WARNING)


class HypervisorSSHRunner:
    def __init__(self, credentials):
        self.credential_manager = CredentialManager(credentials)

    def _candidate_credentials(self, host):
        candidates = []
        seen = set()

        def add_candidate(user, password='', key_path=''):
            key = (user or '', password or '', key_path or '')
            if not user or key in seen:
                return
            seen.add(key)
            candidates.append({
                'user': user,
                'password': password or '',
                'key_path': key_path or '',
            })

        host_user = getattr(host, 'user', '') if isinstance(host, HostRecord) else host.get('user', '')
        host_key_path = getattr(host, 'key_path', '') if isinstance(host, HostRecord) else host.get('key_path', '')
        if host_user and host_key_path:
            add_candidate(host_user, key_path=host_key_path)

        normalized = list(self.credential_manager)
        normalized.sort(key=lambda cred: 0 if cred.get('user') == host_user else 1)
        for cred in normalized:
            if cred.get('type') != 'ssh':
                continue
            user = cred.get('user')
            for key_path in cred.get('key_paths', []):
                add_candidate(user, key_path=key_path)
            for password in cred.get('passwords', []):
                add_candidate(user, password=password)

        return candidates

    def connect(self, host):
        ip = host.ip if isinstance(host, HostRecord) else host.get('ip', '')
        for candidate in self._candidate_credentials(host):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                connect_kwargs = {
                    'hostname': ip,
                    'username': candidate['user'],
                    'timeout': 5,
                }
                if candidate['key_path']:
                    connect_kwargs['key_filename'] = candidate['key_path']
                elif candidate['password']:
                    connect_kwargs['password'] = candidate['password']
                else:
                    continue
                client.connect(**connect_kwargs)
                logger.debug(
                    "Virtualization SSH connected to %s as %s via %s",
                    ip,
                    candidate['user'],
                    'key' if candidate['key_path'] else 'password',
                )
                return client
            except Exception as e:
                logger.debug(
                    "Virtualization SSH failed for %s as %s: %s",
                    ip,
                    candidate['user'],
                    e,
                )
                try:
                    client.close()
                except Exception:
                    pass
        return None

    def run(self, client, command, timeout=15):
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace').strip()
        if error:
            logger.debug("Remote command stderr for %s: %s", command, error)
        return output


class PveGuestCollector:
    def __init__(self, credentials, runner=None):
        self.runner = runner or HypervisorSSHRunner(credentials)

    def _run(self, client, command, timeout=15):
        return self.runner.run(client, command, timeout=timeout)

    def _is_pve_host(self, client):
        output = self._run(client, "command -v pct >/dev/null 2>&1 && echo pct || true")
        return output.strip() == 'pct'

    def _list_containers(self, client):
        output = self._run(client, "pct list 2>/dev/null || true")
        containers = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.lower().startswith('vmid'):
                continue
            parts = line.split()
            if len(parts) < 2 or not parts[0].isdigit():
                continue
            containers.append({
                'id': parts[0],
                'status': parts[1].lower(),
            })
        return containers

    def _list_vms(self, client):
        output = self._run(client, "qm list 2>/dev/null || true")
        vms = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.lower().startswith('vmid'):
                continue
            parts = line.split()
            if len(parts) < 2 or not parts[0].isdigit():
                continue
            vms.append({
                'id': parts[0],
                'status': parts[2].lower() if len(parts) > 2 else '',
            })
        return vms

    def _parse_pct_config(self, text):
        parsed = {
            'hostname': '',
            'ips': [],
            'macs': [],
        }
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith('hostname:'):
                parsed['hostname'] = line.split(':', 1)[1].strip()
                continue
            if not re.match(r'^net\d+:', line):
                continue
            options = line.split(':', 1)[1].strip()
            for chunk in options.split(','):
                if '=' not in chunk:
                    continue
                key, value = chunk.split('=', 1)
                key = key.strip().lower()
                value = value.strip()
                if key == 'hwaddr' and value:
                    parsed['macs'].append(value.lower())
                elif key == 'ip' and value and value.lower() != 'dhcp':
                    parsed['ips'].append(value.split('/', 1)[0])
        return parsed

    def _parse_qm_config(self, text):
        parsed = {
            'hostname': '',
            'ips': [],
            'macs': [],
            'ostype': '',
            'agent_enabled': False,
        }
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith('name:'):
                parsed['hostname'] = line.split(':', 1)[1].strip()
                continue
            if line.startswith('ostype:'):
                parsed['ostype'] = line.split(':', 1)[1].strip().lower()
                continue
            if line.startswith('agent:'):
                value = line.split(':', 1)[1].strip().lower()
                parsed['agent_enabled'] = value not in ('0', 'no', 'false', 'off')
                continue
            if re.match(r'^net\d+:', line):
                options = line.split(':', 1)[1].strip()
                for chunk in options.split(','):
                    chunk = chunk.strip()
                    for prefix in ('virtio=', 'e1000=', 'rtl8139=', 'vmxnet3='):
                        if chunk.startswith(prefix):
                            mac = chunk[len(prefix):].split(',', 1)[0].strip().lower()
                            if mac:
                                parsed['macs'].append(mac)
                continue
            if re.match(r'^ipconfig\d+:', line):
                options = line.split(':', 1)[1].strip()
                for chunk in options.split(','):
                    if '=' not in chunk:
                        continue
                    key, value = chunk.split('=', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    if key == 'ip' and value and value.lower() not in ('dhcp', 'auto'):
                        parsed['ips'].append(value.split('/', 1)[0])
        return parsed

    def _pct_exec(self, client, vmid, command, timeout=15):
        wrapped = f"pct exec {vmid} -- sh -lc {shlex.quote(command)} 2>/dev/null || true"
        return self._run(client, wrapped, timeout=timeout).strip()

    def _qm_guest_cmd(self, client, vmid, command, timeout=20):
        output = self._run(client, f"qm guest cmd {vmid} {command} 2>/dev/null || true", timeout=timeout).strip()
        if not output:
            return None
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            logger.debug("Failed to parse qm guest cmd output for VM %s command %s", vmid, command)
            return None

    def _parse_ip_addrs(self, text):
        ips = []
        for line in text.splitlines():
            match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/', line)
            if match:
                ips.append(match.group(1))
        return ips

    def _parse_mac_addrs(self, text):
        macs = []
        for line in text.splitlines():
            value = line.strip().lower()
            if value == '00:00:00:00:00:00':
                continue
            if re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', value):
                macs.append(value)
        return macs

    def _extract_guest_agent_interfaces(self, payload):
        ips = []
        macs = []
        if not isinstance(payload, list):
            return ips, macs
        for iface in payload:
            if not isinstance(iface, dict):
                continue
            mac = str(iface.get('hardware-address', '')).strip().lower()
            if mac and mac != '00:00:00:00:00:00' and mac not in macs:
                macs.append(mac)
            for addr in iface.get('ip-addresses', []):
                if not isinstance(addr, dict):
                    continue
                if addr.get('ip-address-type') != 'ipv4':
                    continue
                ip = str(addr.get('ip-address', '')).strip()
                if not ip or ip.startswith('127.') or ip.startswith('169.254.') or ip.startswith('10.0.85.'):
                    continue
                if ip not in ips:
                    ips.append(ip)
        return ips, macs

    def _classify_vm(self, hostname, ostype, os_name, ips):
        os_lower = (os_name or '').lower()
        host_lower = (hostname or '').lower()
        if ostype.startswith('win') or 'windows' in os_lower:
            return {
                'category': 'windows',
                'os_type': 'windows',
                'type': classify_windows_type(hostname, [3389] if ips else [], os_name),
                'os': normalize_os_name(os_name or 'Windows'),
            }
        if 'openwrt' in host_lower or 'openwrt' in os_lower:
            return {
                'category': 'network',
                'os_type': 'linux',
                'type': 'network',
                'os': normalize_os_name(os_name or 'OpenWrt'),
            }
        return {
            'category': 'linux',
            'os_type': 'linux',
            'type': 'server',
            'os': normalize_os_name(os_name or 'Linux'),
        }

    def _build_guest_record(self, vmid, config_data, runtime_data):
        hostname = runtime_data.get('hostname') or config_data.get('hostname', '')
        distribution = runtime_data.get('distribution', '')
        kernel_version = runtime_data.get('kernel_version', '')
        ips = []
        macs = []
        for value in [*runtime_data.get('ips', []), *config_data.get('ips', [])]:
            if value and value not in ips:
                ips.append(value)
        for value in [*runtime_data.get('macs', []), *config_data.get('macs', [])]:
            if value and value not in macs:
                macs.append(value)

        update = {
            'hostname': hostname,
            'hostnames': [hostname] if hostname else [],
            'vendor': '',
            'os': normalize_os_name(distribution or 'Linux'),
            'distribution': distribution,
            'kernel_version': kernel_version,
            'mac': macs[0] if macs else '',
            'category': 'linux',
            'os_type': 'linux',
            'type': 'server',
        }
        determine_vendor_model(update, {
            'hostname': hostname,
            'os': update['os'],
            'distribution': distribution,
            'kernel_version': kernel_version,
            'vendor': '',
            'service_details': {},
            'scripts': {},
        })

        return {
            'id': vmid,
            'kind': 'ct',
            'ips': ips,
            'macs': macs,
            'update': update,
        }

    def _build_vm_record(self, vmid, config_data, runtime_data):
        hostname = runtime_data.get('hostname') or config_data.get('hostname', '')
        os_name = runtime_data.get('os') or runtime_data.get('distribution', '')
        kernel_version = runtime_data.get('kernel_version', '')
        ips = []
        macs = []
        for value in [*runtime_data.get('ips', []), *config_data.get('ips', [])]:
            if value and value not in ips:
                ips.append(value)
        for value in [*runtime_data.get('macs', []), *config_data.get('macs', [])]:
            if value and value not in macs:
                macs.append(value)

        classified = self._classify_vm(hostname, config_data.get('ostype', ''), os_name, ips)
        update = {
            'hostname': hostname,
            'hostnames': [hostname] if hostname else [],
            'vendor': '',
            'os': classified['os'],
            'distribution': runtime_data.get('distribution', ''),
            'kernel_version': kernel_version,
            'mac': macs[0] if macs else '',
            'category': classified['category'],
            'os_type': classified['os_type'],
            'type': classified['type'],
        }
        determine_vendor_model(update, {
            'hostname': hostname,
            'os': update['os'],
            'distribution': runtime_data.get('distribution', ''),
            'kernel_version': kernel_version,
            'vendor': '',
            'service_details': {},
            'scripts': {},
        })

        return {
            'id': vmid,
            'kind': 'vm',
            'ips': ips,
            'macs': macs,
            'update': update,
        }

    def _collect_container(self, client, container):
        vmid = container['id']
        config_text = self._run(client, f"pct config {vmid} 2>/dev/null || true")
        if not config_text.strip():
            return None

        config_data = self._parse_pct_config(config_text)
        runtime_data = {
            'hostname': '',
            'distribution': '',
            'kernel_version': '',
            'ips': [],
            'macs': [],
        }

        if container.get('status') == 'running':
            runtime_data['hostname'] = self._pct_exec(client, vmid, 'hostname')
            runtime_data['distribution'] = self._pct_exec(
                client,
                vmid,
                "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'",
            )
            runtime_data['kernel_version'] = self._pct_exec(client, vmid, 'uname -r')
            runtime_data['ips'] = self._parse_ip_addrs(
                self._pct_exec(client, vmid, 'ip -o -4 addr show scope global')
            )
            runtime_data['macs'] = self._parse_mac_addrs(
                self._pct_exec(client, vmid, "cat /sys/class/net/*/address 2>/dev/null")
            )

        guest = self._build_guest_record(vmid, config_data, runtime_data)
        if not guest['ips'] and not guest['macs']:
            return None
        return guest

    def _collect_vm(self, client, vm):
        vmid = vm['id']
        config_text = self._run(client, f"qm config {vmid} 2>/dev/null || true")
        if not config_text.strip():
            return None

        config_data = self._parse_qm_config(config_text)
        runtime_data = {
            'hostname': '',
            'distribution': '',
            'os': '',
            'kernel_version': '',
            'ips': [],
            'macs': [],
        }

        if vm.get('status') == 'running' and config_data.get('agent_enabled'):
            interfaces = self._qm_guest_cmd(client, vmid, 'network-get-interfaces')
            agent_ips, agent_macs = self._extract_guest_agent_interfaces(interfaces)
            runtime_data['ips'] = agent_ips
            runtime_data['macs'] = agent_macs

            osinfo = self._qm_guest_cmd(client, vmid, 'get-osinfo')
            if isinstance(osinfo, dict):
                runtime_data['os'] = str(osinfo.get('pretty-name') or osinfo.get('name') or '').strip()
                runtime_data['kernel_version'] = str(
                    osinfo.get('kernel-release') or osinfo.get('kernel-version') or ''
                ).strip()

        guest = self._build_vm_record(vmid, config_data, runtime_data)
        if not guest['ips'] and not guest['macs']:
            return None
        return guest

    def collect_guests(self, host):
        client = self.runner.connect(host)
        if client is None:
            logger.warning("Could not connect to virtualization host %s", host.ip)
            return []

        try:
            if not self._is_pve_host(client):
                return []

            guests = []
            for container in self._list_containers(client):
                guest = self._collect_container(client, container)
                if guest:
                    guests.append(guest)
            for vm in self._list_vms(client):
                guest = self._collect_vm(client, vm)
                if guest:
                    guests.append(guest)
            logger.info("Collected %s PVE guests from %s", len(guests), host.ip)
            return guests
        finally:
            try:
                client.close()
            except Exception:
                pass


class VirtualizationEnricher:
    def __init__(self, storage, credentials, collector=None):
        self.storage = storage
        self.collector = collector or PveGuestCollector(credentials)

    def _is_pve_host(self, host):
        if host.scan_status != STATUS_COMPLETED or host.auth_method != 'ssh':
            return False
        text = ' '.join([
            host.vendor or '',
            host.model or '',
            host.os or '',
            ' '.join(host.services or []),
        ]).lower()
        return (
            host.vendor == 'Proxmox'
            or 'proxmox' in text
            or 8006 in (host.open_ports or [])
        )

    def _build_target_maps(self, target_hosts):
        ip_map = {}
        mac_map = {}
        mac_counts = {}

        for host in target_hosts:
            ip_map[host.ip] = host
            mac = (host.mac or '').lower()
            if mac:
                mac_counts[mac] = mac_counts.get(mac, 0) + 1

        for host in target_hosts:
            mac = (host.mac or '').lower()
            if mac and mac_counts.get(mac) == 1:
                mac_map[mac] = host

        return ip_map, mac_map

    def _match_guest(self, guest, ip_map, mac_map):
        candidates = []
        for ip in guest.get('ips', []):
            host = ip_map.get(ip)
            if host and host not in candidates:
                candidates.append(host)
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            return None

        for mac in guest.get('macs', []):
            host = mac_map.get(mac.lower())
            if host and host not in candidates:
                candidates.append(host)
        if len(candidates) == 1:
            return candidates[0]
        return None

    def _is_sufficient_guest(self, guest):
        update = guest.get('update', {})
        return bool(
            guest.get('ips') or guest.get('macs')
        ) and bool(
            update.get('hostname')
        ) and bool(
            update.get('os') or update.get('distribution') or update.get('kernel_version')
        )

    def _apply_guest(self, host, guest):
        update = dict(guest.get('update', {}))
        if self._is_sufficient_guest(guest):
            update['scan_status'] = STATUS_VIRTUALIZATION_COMPLETED
        self.storage.update_host(host.ip, update, overwrite_protected=True)
        return bool(update.get('scan_status') == STATUS_VIRTUALIZATION_COMPLETED)

    def _collect_guest_candidates(self, pve_hosts):
        collected = []
        for pve_host in pve_hosts:
            guests = self.collector.collect_guests(pve_host)
            for guest in guests:
                guest_copy = dict(guest)
                guest_copy['source_ip'] = pve_host.ip
                collected.append(guest_copy)
        return collected

    def _build_guest_conflicts(self, guests):
        ip_counts = {}
        mac_counts = {}
        for guest in guests:
            for ip in guest.get('ips', []):
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            for mac in guest.get('macs', []):
                mac_lower = mac.lower()
                mac_counts[mac_lower] = mac_counts.get(mac_lower, 0) + 1
        return ip_counts, mac_counts

    def _is_guest_ambiguous(self, guest, ip_counts, mac_counts):
        return any(ip_counts.get(ip, 0) > 1 for ip in guest.get('ips', [])) or any(
            mac_counts.get(mac.lower(), 0) > 1 for mac in guest.get('macs', [])
        )

    def enrich_all(self, target_ips=None):
        all_hosts = list(self.storage.iter_host_records())
        target_filter = set(target_ips or [])
        target_hosts = [
            host for host in all_hosts
            if host.scan_status != STATUS_COMPLETED
            and (not target_filter or host.ip in target_filter)
        ]
        if not target_hosts:
            return

        pve_hosts = [host for host in all_hosts if self._is_pve_host(host)]
        if not pve_hosts:
            logger.info("No completed PVE hosts available for virtualization enrichment.")
            return

        ip_map, mac_map = self._build_target_maps(target_hosts)
        guests = self._collect_guest_candidates(pve_hosts)
        ip_counts, mac_counts = self._build_guest_conflicts(guests)
        updated_ips = set()

        for guest in guests:
            if self._is_guest_ambiguous(guest, ip_counts, mac_counts):
                logger.warning(
                    "Skipping ambiguous virtualization guest %s from %s due to duplicate IP/MAC",
                    guest.get('id', ''),
                    guest.get('source_ip', ''),
                )
                continue

            matched_host = self._match_guest(guest, ip_map, mac_map)
            if not matched_host or matched_host.ip in updated_ips:
                continue
            if self._apply_guest(matched_host, guest):
                logger.info(
                    "Virtualization enrichment completed for %s via %s %s %s",
                    matched_host.ip,
                    guest.get('source_ip', ''),
                    guest.get('kind', 'guest'),
                    guest.get('id', ''),
                )
            updated_ips.add(matched_host.ip)

        self.storage.flush()
