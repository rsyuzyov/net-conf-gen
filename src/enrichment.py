import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.classification import classify_host
from src.constants import (
    CATEGORY_UNKNOWN,
    STATUS_AUTH_AVAILABLE_NO_ACCESS,
    STATUS_COMPLETED,
    STATUS_SCANNED,
    STATUS_WEB_COMPLETED,
    TYPE_UNKNOWN,
)
from src.credentials import CredentialManager
from src.models import HostRecord
from src.utils import normalize_os_name
from src.vendor_db import classify_windows_type, determine_vendor_model


logger = logging.getLogger(__name__)


LINUX_OS_MARKERS = (
    'debian', 'ubuntu', 'centos', 'red hat', 'rocky', 'almalinux',
    'openwrt', 'linux', 'buildroot', 'routeros', 'unix', 'samba',
)
WINDOWS_OS_MARKERS = (
    'windows', 'microsoft windows', 'windows server', 'microsoft corporation',
    'win32', 'nt ',
)
NETWORK_OS_MARKERS = ('openwrt', 'vyos', 'routeros')
IPKVM_MARKERS = ('nanokvm', 'pikvm', 'ip-kvm', 'buildroot')
WINDOWS_SERVICE_HINTS = ('winrm', 'wsman', 'microsoft rpc', 'rdp')
SSH_TEXT_HINTS = ('openssh', 'dropbear', 'ssh')


class AuthenticatedEnricher:
    def __init__(self, storage, credentials, concurrency=10):
        self.storage = storage
        self.credential_manager = CredentialManager(credentials)
        self.concurrency = concurrency
        self._ssh = None
        self._winrm = None
        self._psexec = None

    def _field(self, host, name, default=None):
        if isinstance(host, HostRecord):
            value = getattr(host, name, default)
            return default if value is None else value
        value = host.get(name, default)
        return default if value is None else value

    @property
    def ssh_connector(self):
        if self._ssh is None:
            from src.connectors.ssh import SSHConnector
            self._ssh = SSHConnector()
        return self._ssh

    @property
    def winrm_connector(self):
        if self._winrm is None:
            from src.connectors.winrm import WinRMConnector
            self._winrm = WinRMConnector()
        return self._winrm

    @property
    def psexec_connector(self):
        if self._psexec is None:
            from src.connectors.psexec import PsExecConnector
            self._psexec = PsExecConnector()
        return self._psexec

    def _combined_text(self, host):
        parts = [
            self._field(host, 'hostname', ''),
            self._field(host, 'vendor', ''),
            self._field(host, 'os', ''),
            ' '.join(self._field(host, 'services', [])),
        ]
        for details in self._field(host, 'service_details', {}).values():
            parts.extend([
                details.get('name', ''),
                details.get('product', ''),
                details.get('version', ''),
                details.get('extrainfo', ''),
            ])
        for probe in self._field(host, 'web_probes', {}).values():
            parts.extend([
                probe.get('server', ''),
                probe.get('title', ''),
                probe.get('location', ''),
                probe.get('content_type', ''),
                probe.get('auth_scheme', ''),
                probe.get('tls_subject', ''),
                probe.get('tls_issuer', ''),
                'login-page' if probe.get('is_login_page') else '',
            ])
        return ' '.join(str(part) for part in parts if part).lower()

    def _protocol_order(self, host):
        category = self._field(host, 'category', CATEGORY_UNKNOWN)
        if category == 'windows':
            return ['winrm', 'psexec', 'ssh']
        if category in ('linux', 'mikrotik', 'network', 'ipkvm'):
            return ['ssh', 'winrm', 'psexec']
        return ['ssh', 'winrm', 'psexec']

    def _required_ports(self, protocol):
        return {
            'ssh': {22},
            'winrm': {5985, 5986},
            'psexec': {445},
        }.get(protocol, set())

    def _has_fallback_signals(self, host, protocol):
        category = self._field(host, 'category', CATEGORY_UNKNOWN)
        auth_methods = set(self._field(host, 'auth_methods', []))
        text = self._combined_text(host)
        ports = set(self._field(host, 'open_ports', []))

        if protocol == 'ssh':
            return (
                category in ('linux', 'mikrotik', 'network', 'ipkvm')
                or 'ssh' in auth_methods
                or any(marker in text for marker in SSH_TEXT_HINTS)
            )

        if protocol == 'winrm':
            return (
                category == 'windows'
                or 'winrm' in auth_methods
                or any(marker in text for marker in WINDOWS_SERVICE_HINTS)
                or {88, 135, 389, 445, 636} <= ports
            )

        if protocol == 'psexec':
            return (
                category == 'windows'
                or 'psexec' in auth_methods
                or 445 in ports
                or {88, 135, 389, 445, 636} <= ports
            )

        return False

    def _should_try_protocol(self, host, protocol):
        open_ports = set(self._field(host, 'open_ports', []))
        required_ports = self._required_ports(protocol)
        if open_ports & required_ports:
            return True
        return self._has_fallback_signals(host, protocol)

    def _get_connector(self, protocol):
        if protocol in ('ssh', 'ssh_key'):
            return self.ssh_connector
        if protocol == 'winrm':
            return self.winrm_connector
        if protocol == 'psexec':
            return self.psexec_connector
        return None

    def _record_attempt(self, update_data, method, user, status, error=''):
        update_data.setdefault('auth_attempts', []).append({
            'method': method,
            'user': user or '',
            'status': status,
            'error': error,
        })

    def _append_auth_method(self, update_data, method):
        base_method = method.replace('_key', '')
        if base_method not in update_data['auth_methods']:
            update_data['auth_methods'].append(base_method)

    def _finalize_success(self, host, info, method, current_data, attempted_user='', key_path=''):
        result = {
            'auth_methods': list(current_data.get('auth_methods', self._field(host, 'auth_methods', []))),
            'auth_attempts': list(current_data.get('auth_attempts', self._field(host, 'auth_attempts', []))),
        }
        if 'os' in info:
            info['os'] = normalize_os_name(info['os'])

        result.update(info)
        result['key_path'] = key_path or ''
        result['scan_status'] = STATUS_COMPLETED
        self._append_auth_method(result, method)
        self._record_attempt(result, method, attempted_user or info.get('user', ''), 'success')

        merged = host.to_dict() if isinstance(host, HostRecord) else dict(host)
        merged.update(result)

        protocol = info.get('auth_method') or method.replace('_key', '')
        final_model = self._build_final_model(merged, protocol)
        result.update(final_model)

        determine_vendor_model(result, merged | final_model)
        return result

    def _try_single_connect(self, connector, ip, method, host, update_data, user=None, password=None, key_path=None):
        try:
            info = connector.connect(ip, user, password=password, key_path=key_path)
        except Exception as e:
            self._record_attempt(update_data, method, user, 'error', str(e))
            return False

        if not info:
            self._record_attempt(update_data, method, user, 'failed', 'No response')
            return False

        if info.get('auth_failed'):
            self._append_auth_method(update_data, method)
            self._record_attempt(update_data, method, user or info.get('user', ''), 'auth_failed', info.get('error', ''))
            return False

        if info.get('success') or info.get('hostname'):
            final_data = self._finalize_success(
                host,
                info,
                method,
                update_data,
                attempted_user=user,
                key_path=key_path or '',
            )
            update_data.clear()
            update_data.update(final_data)
            return True

        self._record_attempt(update_data, method, user, 'failed', 'Incomplete connector response')
        return False

    def _try_protocol(self, ip, host, protocol, update_data):
        if not self._should_try_protocol(host, protocol):
            return False

        connector = self._get_connector(protocol)
        if connector is None:
            return False

        cred_type = {'ssh': 'ssh', 'winrm': 'winrm', 'psexec': 'winrm'}[protocol]

        if protocol == 'winrm':
            if self._try_single_connect(connector, ip, protocol, host, update_data, user=None, password=None):
                return True

        for cred in self.credential_manager:
            if cred.get('type') != cred_type:
                continue

            user = cred.get('user')
            if protocol == 'ssh':
                for key_path in cred.get('key_paths', []):
                    if self._try_single_connect(connector, ip, 'ssh_key', host, update_data, user=user, key_path=key_path):
                        return True
                for password in cred.get('passwords', []):
                    if self._try_single_connect(connector, ip, protocol, host, update_data, user=user, password=password):
                        return True
            else:
                for password in cred.get('passwords', []):
                    if self._try_single_connect(connector, ip, protocol, host, update_data, user=user, password=password):
                        return True

        return False

    def _linux_category_from_authenticated_data(self, merged):
        os_name = (merged.get('os') or '').lower()
        text = self._combined_text(merged)
        current_category = merged.get('category', CATEGORY_UNKNOWN)

        if 'routeros' in os_name or 'mikrotik' in text:
            return 'mikrotik', 'linux', 'mikrotik'
        if any(marker in text or marker in os_name for marker in IPKVM_MARKERS):
            return 'ipkvm', 'linux', 'ipkvm'
        if any(marker in os_name for marker in NETWORK_OS_MARKERS) or current_category in ('network', 'mikrotik', 'ipkvm'):
            mapped_type = {
                'network': 'network',
                'mikrotik': 'mikrotik',
                'ipkvm': 'ipkvm',
            }.get(current_category, 'network')
            return current_category if current_category != CATEGORY_UNKNOWN else 'network', 'linux', mapped_type
        return 'linux', 'linux', 'server'

    def _is_windows_like(self, merged):
        text = self._combined_text(merged)
        os_name = (merged.get('os') or '').lower()
        return any(marker in os_name for marker in WINDOWS_OS_MARKERS) or any(marker in text for marker in WINDOWS_SERVICE_HINTS)

    def _is_linux_like(self, merged):
        text = self._combined_text(merged)
        os_name = (merged.get('os') or '').lower()
        return any(marker in os_name for marker in LINUX_OS_MARKERS) or any(marker in text for marker in LINUX_OS_MARKERS)

    def _build_final_model(self, merged, protocol):
        hostname = merged.get('hostname', '')
        os_name = normalize_os_name(merged.get('os', '')) if merged.get('os') else ''
        open_ports = merged.get('open_ports', [])

        final = {
            'hostname': hostname,
            'os': os_name,
        }

        if protocol in ('winrm', 'psexec'):
            final['category'] = 'windows'
            final['os_type'] = 'windows'
            final['type'] = classify_windows_type(hostname, open_ports, os_name)
            if not final['os']:
                final['os'] = 'Windows Server' if final['type'] == 'server' else 'Windows'
            return final

        if protocol == 'ssh':
            if self._is_linux_like(merged):
                category, os_type, host_type = self._linux_category_from_authenticated_data(merged)
                final['category'] = category
                final['os_type'] = os_type
                final['type'] = host_type
                return final

            if self._is_windows_like(merged):
                final['category'] = 'windows'
                final['os_type'] = 'windows'
                final['type'] = classify_windows_type(hostname, open_ports, os_name)
                if not final['os']:
                    final['os'] = 'Windows Server' if final['type'] == 'server' else 'Windows'
                return final

        discovery_view = classify_host(merged)
        if discovery_view.get('category', CATEGORY_UNKNOWN) != CATEGORY_UNKNOWN:
            final.update({
                'category': discovery_view.get('category', CATEGORY_UNKNOWN),
                'os_type': discovery_view.get('os_type', ''),
                'type': discovery_view.get('type', TYPE_UNKNOWN),
            })
            if not final.get('os') and discovery_view.get('os'):
                final['os'] = discovery_view['os']
            if discovery_view.get('model') and not merged.get('model'):
                final['model'] = discovery_view['model']
            return final

        final.setdefault('category', CATEGORY_UNKNOWN)
        final.setdefault('os_type', '')
        final.setdefault('type', TYPE_UNKNOWN)
        return final

    def _finalize_without_auth(self, host, update_data):
        merged = host.to_dict() if isinstance(host, HostRecord) else dict(host)
        merged.update(update_data)
        discovery_view = classify_host(merged)
        for key in ('category', 'os_type', 'type', 'os'):
            value = discovery_view.get(key)
            if value:
                update_data[key] = value
        determine_vendor_model(update_data, merged | discovery_view)

    def enrich_host(self, ip, force=False):
        host = self.storage.get_host_record(ip)
        if not host:
            return
        if not force and self._field(host, 'scan_status', '') == STATUS_COMPLETED:
            return

        update_data = {
            'auth_methods': [],
            'auth_attempts': [],
            'auth_method': '',
            'user': '',
            'key_path': '',
        }

        success = False
        for protocol in self._protocol_order(host):
            if self._try_protocol(ip, host, protocol, update_data):
                success = True
                break

        if success:
            self.storage.update_host(ip, update_data)
            return

        if update_data.get('auth_methods'):
            update_data['scan_status'] = STATUS_AUTH_AVAILABLE_NO_ACCESS
        else:
            previous_status = self._field(host, 'scan_status', '')
            update_data['scan_status'] = STATUS_WEB_COMPLETED if previous_status == STATUS_WEB_COMPLETED else STATUS_SCANNED

        self._finalize_without_auth(host, update_data)
        self.storage.update_host(ip, update_data)

    def enrich_all(self, ips, force=False):
        if not ips:
            return

        with ThreadPoolExecutor(max_workers=min(self.concurrency, len(ips))) as executor:
            futures = {executor.submit(self.enrich_host, ip, force): ip for ip in ips}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error("Authenticated enrichment failed for %s: %s", ip, e)

        self.storage.flush()
