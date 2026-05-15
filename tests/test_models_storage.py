import tempfile
import unittest

from src.models import HostRecord
from src.storage import Storage


class ModelsStorageTests(unittest.TestCase):
    def test_storage_returns_host_record(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.20', {
                'ip': '192.168.1.20',
                'hostname': 'edge-router',
                'open_ports': [22, 80],
                'services': ['SSH', 'HTTP'],
                'category': 'network',
                'type': 'network',
                'scan_status': 'discovered',
            })
            storage.flush()

            record = storage.get_host_record('192.168.1.20')

            self.assertIsInstance(record, HostRecord)
            self.assertEqual('192.168.1.20', record.ip)
            self.assertEqual('edge-router', record.hostname)
            self.assertEqual([22, 80], record.open_ports)
            self.assertEqual('discovered', record.scan_status)

    def test_iter_host_records_returns_sorted_records(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.20', {'ip': '192.168.1.20'})
            storage.update_host('192.168.1.3', {'ip': '192.168.1.3'})
            storage.update_host('192.168.1.11', {'ip': '192.168.1.11'})
            storage.flush()

            ips = [record.ip for record in storage.iter_host_records()]

            self.assertEqual(['192.168.1.3', '192.168.1.11', '192.168.1.20'], ips)

    def test_apply_discovery_keeps_completed_host_intact_without_force(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.10', {
                'ip': '192.168.1.10',
                'hostname': 'srv-app',
                'open_ports': [22],
                'services': ['SSH'],
                'scan_status': 'completed',
                'auth_method': 'ssh',
                'auth_methods': ['ssh'],
                'user': 'root',
            })

            storage.apply_discovery_snapshot([
                HostRecord(
                    ip='192.168.1.10',
                    open_ports=[22, 443],
                    services=['SSH', 'HTTPS'],
                    category='linux',
                    os_type='linux',
                    type='server',
                    scan_status='discovered',
                )
            ])
            storage.flush()

            host = storage.get_host_record('192.168.1.10')
            self.assertEqual([22], host.open_ports)
            self.assertEqual(['SSH'], host.services)
            self.assertEqual('ssh', host.auth_method)
            self.assertEqual('completed', host.scan_status)

    def test_apply_discovery_with_force_replaces_completed_host(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.10', {
                'ip': '192.168.1.10',
                'open_ports': [22],
                'scan_status': 'completed',
                'auth_method': 'ssh',
            })

            storage.apply_discovery_snapshot([
                HostRecord(
                    ip='192.168.1.10',
                    open_ports=[22, 443],
                    services=['SSH', 'HTTPS'],
                    scan_status='discovered',
                )
            ], force=True)
            storage.flush()

            host = storage.get_host_record('192.168.1.10')
            self.assertEqual([22, 443], host.open_ports)
            self.assertEqual('discovered', host.scan_status)
            self.assertEqual('', host.auth_method)

    def test_apply_discovery_keeps_absent_hosts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.99', {
                'ip': '192.168.1.99',
                'hostname': 'offline-host',
                'open_ports': [80],
                'scan_status': 'web_completed',
            })

            storage.apply_discovery_snapshot([
                HostRecord(
                    ip='192.168.1.10',
                    open_ports=[22],
                    services=['SSH'],
                    scan_status='discovered',
                )
            ])
            storage.flush()

            self.assertIsNotNone(storage.get_host_record('192.168.1.99'))
            self.assertEqual('offline-host', storage.get_host_record('192.168.1.99').hostname)
            self.assertIsNotNone(storage.get_host_record('192.168.1.10'))

    def test_apply_discovery_adds_brand_new_host(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)

            storage.apply_discovery_snapshot([
                HostRecord(
                    ip='192.168.1.55',
                    open_ports=[80],
                    services=['HTTP'],
                    scan_status='discovered',
                )
            ])
            storage.flush()

            host = storage.get_host_record('192.168.1.55')
            self.assertIsNotNone(host)
            self.assertEqual([80], host.open_ports)

    def test_storage_preserves_kernel_distribution_and_success_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.30', {
                'ip': '192.168.1.30',
                'kernel_version': '6.8.12-pve',
                'distribution': 'Debian GNU/Linux 12 (bookworm)',
                'success': True,
            })
            storage.flush()

            host = storage.get_host_record('192.168.1.30')

            self.assertEqual('6.8.12-pve', host.kernel_version)
            self.assertEqual('Debian GNU/Linux 12 (bookworm)', host.distribution)
            self.assertTrue(host.success)

    def test_storage_preserves_web_probes_with_numeric_ports(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.35', {
                'ip': '192.168.1.35',
                'web_probes': {
                    443: {
                        'scheme': 'https',
                        'status_code': 200,
                        'title': 'Proxmox Virtual Environment',
                        'tls_subject': 'srv-hv1.ag.local',
                    }
                },
            })
            storage.flush()

            host = storage.get_host_record('192.168.1.35')

            self.assertEqual([443], list(host.web_probes.keys()))
            self.assertEqual('https', host.web_probes[443]['scheme'])
            self.assertEqual('Proxmox Virtual Environment', host.web_probes[443]['title'])

    def test_apply_discovery_replaces_incomplete_host_without_force(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.40', {
                'ip': '192.168.1.40',
                'scan_status': 'auth_available_no_access',
                'kernel_version': '6.8.12-pve',
                'distribution': 'Debian GNU/Linux 12 (bookworm)',
                'success': True,
                'auth_methods': ['ssh'],
                'auth_attempts': [{'method': 'ssh', 'user': 'root', 'status': 'auth_failed', 'error': 'x'}],
            })
            storage.flush()

            storage.apply_discovery_snapshot([
                HostRecord(
                    ip='192.168.1.40',
                    open_ports=[22],
                    services=['SSH'],
                    category='unknown',
                    os_type='',
                    type='unknown',
                    scan_status='discovered',
                )
            ])
            storage.flush()

            host = storage.get_host_record('192.168.1.40')
            self.assertEqual('', host.kernel_version)
            self.assertEqual('', host.distribution)
            self.assertFalse(host.success)
            self.assertEqual([], host.auth_methods)
            self.assertEqual([], host.auth_attempts)

    def test_storage_normalizes_existing_and_incoming_os_values(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.50', {
                'ip': '192.168.1.50',
                'os': 'М\xa0йкрософт Windows 10 Pro',
            })
            storage.update_host('192.168.1.50', {
                'ip': '192.168.1.50',
                'vendor': 'Microsoft',
            })
            storage.flush()

            host = storage.get_host_record('192.168.1.50')
            self.assertEqual('Microsoft Windows 10 Pro', host.os)


if __name__ == '__main__':
    unittest.main()
