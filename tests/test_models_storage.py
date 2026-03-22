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

    def test_replace_discovery_snapshot_removes_absent_hosts_and_preserves_auth(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.10', {
                'ip': '192.168.1.10',
                'hostname': 'old-host',
                'open_ports': [22],
                'services': ['SSH'],
                'scan_status': 'completed',
                'auth_method': 'ssh',
                'auth_methods': ['ssh'],
                'user': 'root',
            })
            storage.update_host('192.168.1.99', {
                'ip': '192.168.1.99',
                'hostname': 'stale-host',
                'open_ports': [80],
                'services': ['HTTP'],
            })

            storage.replace_discovery_snapshot([
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

            self.assertIsNone(storage.get_host_record('192.168.1.99'))
            host = storage.get_host_record('192.168.1.10')
            self.assertEqual([22, 443], host.open_ports)
            self.assertEqual(['SSH', 'HTTPS'], host.services)
            self.assertEqual('ssh', host.auth_method)
            self.assertEqual(['ssh'], host.auth_methods)
            self.assertEqual('root', host.user)


if __name__ == '__main__':
    unittest.main()
