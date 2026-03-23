import tempfile
import unittest
from unittest.mock import patch

from src.constants import (
    STATUS_AUTH_AVAILABLE_NO_ACCESS,
    STATUS_COMPLETED,
    STATUS_DISCOVERED,
    STATUS_WEB_COMPLETED,
)
from src.enrichment import AuthenticatedEnricher
from src.storage import Storage


class StubConnector:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def connect(self, ip, user, password=None, key_path=None):
        self.calls.append({
            'ip': ip,
            'user': user,
            'password': password,
            'key_path': key_path,
        })
        return self.response


class StubEnricher(AuthenticatedEnricher):
    def __init__(self, storage, credentials, ssh_response=None, winrm_response=None, psexec_response=None):
        super().__init__(storage=storage, credentials=credentials, concurrency=1)
        self._ssh = StubConnector(ssh_response)
        self._winrm = StubConnector(winrm_response)
        self._psexec = StubConnector(psexec_response)


class EnrichmentTests(unittest.TestCase):
    def test_successful_ssh_enrichment_marks_host_completed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.10', {
                'ip': '192.168.1.10',
                'hostname': 'srv-app1',
                'category': 'linux',
                'type': 'server',
                'os_type': 'linux',
                'open_ports': [22],
                'services': ['SSH'],
                'scan_status': STATUS_DISCOVERED,
            })
            storage.flush()

            enricher = StubEnricher(
                storage=storage,
                credentials=[{
                    'protocol': 'ssh',
                    'accounts': [{'user': 'root', 'password': 'secret'}],
                }],
                ssh_response={
                    'success': True,
                    'hostname': 'srv-app1',
                    'os': 'Ubuntu 24.04',
                    'os_type': 'linux',
                    'auth_method': 'ssh',
                    'user': 'root',
                },
            )

            enricher.enrich_host('192.168.1.10')

            host = storage.get_host_record('192.168.1.10')
            self.assertEqual(STATUS_COMPLETED, host.scan_status)
            self.assertEqual(['ssh'], host.auth_methods)
            self.assertEqual('root', host.user)
            self.assertEqual('Ubuntu 24.04', host.os)

    def test_auth_fail_sets_auth_available_no_access(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.20', {
                'ip': '192.168.1.20',
                'hostname': 'ws-1',
                'category': 'windows',
                'type': 'workstation',
                'open_ports': [5985],
                'services': ['WinRM'],
                'scan_status': STATUS_DISCOVERED,
            })
            storage.flush()

            enricher = StubEnricher(
                storage=storage,
                credentials=[{
                    'protocol': 'winrm',
                    'accounts': [{'user': 'admin', 'password': 'bad'}],
                }],
                winrm_response={'auth_failed': True, 'error': 'Authentication failed'},
            )

            enricher.enrich_host('192.168.1.20')

            host = storage.get_host_record('192.168.1.20')
            self.assertEqual(STATUS_AUTH_AVAILABLE_NO_ACCESS, host.scan_status)
            self.assertEqual(['winrm'], host.auth_methods)
            self.assertEqual('server', host.type)
            self.assertEqual([5985], host.open_ports)
            self.assertEqual(['WinRM'], host.services)

    def test_successful_ssh_reclassifies_windows_guess_to_linux(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.30', {
                'ip': '192.168.1.30',
                'hostname': 'srv-file1',
                'category': 'windows',
                'type': 'workstation',
                'os_type': 'windows',
                'open_ports': [22, 445],
                'services': ['OpenSSH', 'Samba smbd'],
                'scan_status': STATUS_DISCOVERED,
            })
            storage.flush()

            enricher = StubEnricher(
                storage=storage,
                credentials=[{
                    'protocol': 'ssh',
                    'accounts': [{'user': 'root', 'password': 'secret'}],
                }],
                ssh_response={
                    'success': True,
                    'hostname': 'srv-file1',
                    'os': 'Debian GNU/Linux 12 (bookworm)',
                    'auth_method': 'ssh',
                    'user': 'root',
                },
            )

            enricher.enrich_host('192.168.1.30')

            host = storage.get_host_record('192.168.1.30')
            self.assertEqual(STATUS_COMPLETED, host.scan_status)
            self.assertEqual('linux', host.category)
            self.assertEqual('linux', host.os_type)
            self.assertEqual('server', host.type)
            self.assertEqual('Debian GNU/Linux 12 (bookworm)', host.os)

    def test_successful_winrm_is_authoritative_for_windows(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.40', {
                'ip': '192.168.1.40',
                'hostname': 'ws-legacy',
                'category': 'linux',
                'type': 'server',
                'os_type': 'linux',
                'open_ports': [5985],
                'services': ['WinRM'],
                'scan_status': STATUS_DISCOVERED,
            })
            storage.flush()

            enricher = StubEnricher(
                storage=storage,
                credentials=[{
                    'protocol': 'winrm',
                    'accounts': [{'user': 'admin', 'password': 'secret'}],
                }],
                winrm_response={
                    'success': True,
                    'hostname': 'srv-ad1',
                    'os': 'Microsoft Windows Server 2022 Standard',
                    'auth_method': 'winrm',
                    'user': 'admin',
                },
            )

            enricher.enrich_host('192.168.1.40')

            host = storage.get_host_record('192.168.1.40')
            self.assertEqual(STATUS_COMPLETED, host.scan_status)
            self.assertEqual('windows', host.category)
            self.assertEqual('windows', host.os_type)
            self.assertEqual('server', host.type)
            self.assertEqual('Microsoft Windows Server 2022 Standard', host.os)

    def test_successful_ssh_can_reclassify_linux_guess_to_windows(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.50', {
                'ip': '192.168.1.50',
                'hostname': 'ws-ssh',
                'category': 'linux',
                'type': 'server',
                'os_type': 'linux',
                'open_ports': [22],
                'services': ['OpenSSH'],
                'scan_status': STATUS_DISCOVERED,
            })
            storage.flush()

            enricher = StubEnricher(
                storage=storage,
                credentials=[{
                    'protocol': 'ssh',
                    'accounts': [{'user': 'admin', 'password': 'secret'}],
                }],
                ssh_response={
                    'success': True,
                    'hostname': 'ws-ssh',
                    'os': 'Microsoft Windows 11 Pro',
                    'auth_method': 'ssh',
                    'user': 'admin',
                },
            )

            enricher.enrich_host('192.168.1.50')

            host = storage.get_host_record('192.168.1.50')
            self.assertEqual(STATUS_COMPLETED, host.scan_status)
            self.assertEqual('windows', host.category)
            self.assertEqual('windows', host.os_type)
            self.assertEqual('workstation', host.type)
            self.assertEqual('Microsoft Windows 11 Pro', host.os)

    def test_winrm_auth_fail_preserves_specific_error_message(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.60', {
                'ip': '192.168.1.60',
                'category': 'windows',
                'type': 'server',
                'os_type': 'windows',
                'open_ports': [5985],
                'services': ['WinRM'],
                'scan_status': STATUS_DISCOVERED,
            })
            storage.flush()

            enricher = StubEnricher(
                storage=storage,
                credentials=[{
                    'protocol': 'winrm',
                    'accounts': [{'user': 'ag\\agent', 'password': 'secret'}],
                }],
                winrm_response={'auth_failed': True, 'error': 'Access is denied'},
            )

            enricher.enrich_host('192.168.1.60')

            host = storage.get_host_record('192.168.1.60')
            self.assertEqual('Access is denied', host.auth_attempts[0]['error'])

    def test_force_rescan_replaces_previous_auth_runtime_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.70', {
                'ip': '192.168.1.70',
                'hostname': 'srv-app2',
                'category': 'linux',
                'type': 'server',
                'os_type': 'linux',
                'open_ports': [22],
                'services': ['SSH'],
                'scan_status': STATUS_COMPLETED,
                'auth_method': 'ssh',
                'auth_methods': ['ssh'],
                'auth_attempts': [
                    {'method': 'ssh', 'user': 'old-root', 'status': 'success', 'error': ''},
                ],
                'user': 'old-root',
                'key_path': 'C:/keys/old',
            })
            storage.flush()

            enricher = StubEnricher(
                storage=storage,
                credentials=[{
                    'protocol': 'ssh',
                    'accounts': [{'user': 'new-root', 'password': 'secret'}],
                }],
                ssh_response={
                    'success': True,
                    'hostname': 'srv-app2',
                    'os': 'Ubuntu 24.04',
                    'auth_method': 'ssh',
                    'user': 'new-root',
                },
            )

            enricher.enrich_host('192.168.1.70', force=True)

            host = storage.get_host_record('192.168.1.70')
            self.assertEqual('new-root', host.user)
            self.assertEqual('', host.key_path)
            self.assertEqual(['ssh'], host.auth_methods)
            self.assertEqual(1, len(host.auth_attempts))
            self.assertEqual('new-root', host.auth_attempts[0]['user'])

    def test_failed_rescan_clears_previous_successful_auth_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.80', {
                'ip': '192.168.1.80',
                'hostname': 'ws-old',
                'category': 'windows',
                'type': 'server',
                'os_type': 'windows',
                'open_ports': [5985],
                'services': ['WinRM'],
                'scan_status': STATUS_COMPLETED,
                'auth_method': 'winrm',
                'auth_methods': ['winrm'],
                'auth_attempts': [
                    {'method': 'winrm', 'user': 'old-admin', 'status': 'success', 'error': ''},
                ],
                'user': 'old-admin',
            })
            storage.flush()

            enricher = StubEnricher(
                storage=storage,
                credentials=[{
                    'protocol': 'winrm',
                    'accounts': [{'user': 'new-admin', 'password': 'bad'}],
                }],
                winrm_response={'auth_failed': True, 'error': 'Access is denied'},
            )

            enricher.enrich_host('192.168.1.80', force=True)

            host = storage.get_host_record('192.168.1.80')
            self.assertEqual(STATUS_AUTH_AVAILABLE_NO_ACCESS, host.scan_status)
            self.assertEqual('', host.auth_method)
            self.assertEqual('', host.user)
            self.assertEqual('', host.key_path)
            self.assertTrue(host.auth_methods)
            self.assertTrue(host.auth_attempts)
            self.assertNotIn('old-admin', [attempt['user'] for attempt in host.auth_attempts])
            self.assertTrue(all(attempt['user'] != 'old-admin' for attempt in host.auth_attempts))

    def test_failed_auth_does_not_downgrade_existing_web_completed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.90', {
                'ip': '192.168.1.90',
                'open_ports': [80, 9100],
                'services': ['HTTP', 'Printer'],
                'category': 'printer',
                'type': 'printer',
                'os_type': 'linux',
                'os': 'Printer',
                'vendor': 'HP',
                'model': 'LaserJet 400 M401dn',
                'scan_status': STATUS_WEB_COMPLETED,
            })
            storage.flush()

            enricher = StubEnricher(
                storage=storage,
                credentials=[{
                    'protocol': 'ssh',
                    'accounts': [{'user': 'root', 'password': 'bad'}],
                }],
                ssh_response=None,
            )

            enricher.enrich_host('192.168.1.90')

            host = storage.get_host_record('192.168.1.90')
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)
            self.assertEqual('HP', host.vendor)
            self.assertEqual('LaserJet 400 M401dn', host.model)


class ReverseDnsDiscoveryTests(unittest.TestCase):
    def test_reverse_dns_name_normalizes_primary_and_aliases(self):
        with patch('src.utils.socket.gethostbyaddr', return_value=('srv-rds1.ag.local', ['srv-rds1'], ['192.168.88.26'])):
            from src.utils import reverse_dns_name
            hostname, hostnames = reverse_dns_name('192.168.88.26')

        self.assertEqual('srv-rds1', hostname)
        self.assertEqual(['srv-rds1.ag.local', 'srv-rds1'], hostnames)


if __name__ == '__main__':
    unittest.main()
