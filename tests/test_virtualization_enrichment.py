import tempfile
import unittest

from src.constants import (
    STATUS_AUTH_AVAILABLE_NO_ACCESS,
    STATUS_COMPLETED,
    STATUS_VIRTUALIZATION_COMPLETED,
)
from src.storage import Storage
from src.virtualization_enrichment import VirtualizationEnricher


class FakeCollector:
    def __init__(self, guests_by_host):
        self.guests_by_host = guests_by_host

    def collect_guests(self, host):
        return list(self.guests_by_host.get(host.ip, []))


class VirtualizationEnrichmentTests(unittest.TestCase):
    def test_virtualization_enrichment_updates_non_completed_host_by_ip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.88.11', {
                'ip': '192.168.88.11',
                'hostname': 'srv-hv1',
                'open_ports': [22, 8006],
                'services': ['SSH', 'Proxmox'],
                'vendor': 'Proxmox',
                'os': 'Debian GNU/Linux 13 (trixie)',
                'kernel_version': '6.17.13-2-pve',
                'category': 'linux',
                'os_type': 'linux',
                'type': 'server',
                'auth_method': 'ssh',
                'user': 'root',
                'key_path': 'C:\\Users\\rsyuzyov\\.ssh\\agent',
                'scan_status': STATUS_COMPLETED,
            })
            storage.update_host('192.168.88.28', {
                'ip': '192.168.88.28',
                'open_ports': [22, 5432],
                'services': ['SSH', 'PostgreSQL'],
                'mac': 'bc:24:11:f4:fd:38',
                'scan_status': STATUS_AUTH_AVAILABLE_NO_ACCESS,
            })
            storage.flush()

            collector = FakeCollector({
                '192.168.88.11': [{
                    'id': '104',
                    'kind': 'ct',
                    'ips': ['192.168.88.28'],
                    'macs': ['bc:24:11:f4:fd:38'],
                    'update': {
                        'hostname': 'srv-db2',
                        'hostnames': ['srv-db2'],
                        'os': 'Debian GNU/Linux 12 (bookworm)',
                        'distribution': 'Debian GNU/Linux 12 (bookworm)',
                        'kernel_version': '6.1.0-33-amd64',
                        'mac': 'bc:24:11:f4:fd:38',
                        'category': 'linux',
                        'os_type': 'linux',
                        'type': 'server',
                    },
                }]
            })

            enricher = VirtualizationEnricher(storage=storage, credentials=[], collector=collector)
            enricher.enrich_all()

            host = storage.get_host_record('192.168.88.28')
            self.assertEqual(STATUS_VIRTUALIZATION_COMPLETED, host.scan_status)
            self.assertEqual('srv-db2', host.hostname)
            self.assertEqual('Debian GNU/Linux 12 (bookworm)', host.os)
            self.assertEqual('linux', host.category)
            self.assertEqual('', host.auth_method)

    def test_virtualization_enrichment_matches_by_unique_mac(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.88.11', {
                'ip': '192.168.88.11',
                'open_ports': [22, 8006],
                'services': ['SSH', 'Proxmox'],
                'vendor': 'Proxmox',
                'kernel_version': '6.17.13-2-pve',
                'auth_method': 'ssh',
                'user': 'root',
                'key_path': 'C:\\Users\\rsyuzyov\\.ssh\\agent',
                'scan_status': STATUS_COMPLETED,
            })
            storage.update_host('192.168.88.50', {
                'ip': '192.168.88.50',
                'mac': '52:54:00:12:34:56',
                'scan_status': STATUS_AUTH_AVAILABLE_NO_ACCESS,
            })
            storage.flush()

            collector = FakeCollector({
                '192.168.88.11': [{
                    'id': '105',
                    'kind': 'ct',
                    'ips': [],
                    'macs': ['52:54:00:12:34:56'],
                    'update': {
                        'hostname': 'srv-cache1',
                        'hostnames': ['srv-cache1'],
                        'os': 'Debian GNU/Linux 12 (bookworm)',
                        'distribution': 'Debian GNU/Linux 12 (bookworm)',
                        'kernel_version': '6.1.0-33-amd64',
                        'mac': '52:54:00:12:34:56',
                        'category': 'linux',
                        'os_type': 'linux',
                        'type': 'server',
                    },
                }]
            })

            enricher = VirtualizationEnricher(storage=storage, credentials=[], collector=collector)
            enricher.enrich_all()

            host = storage.get_host_record('192.168.88.50')
            self.assertEqual(STATUS_VIRTUALIZATION_COMPLETED, host.scan_status)
            self.assertEqual('srv-cache1', host.hostname)

    def test_virtualization_enrichment_skips_completed_targets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.88.11', {
                'ip': '192.168.88.11',
                'open_ports': [22, 8006],
                'services': ['SSH', 'Proxmox'],
                'vendor': 'Proxmox',
                'kernel_version': '6.17.13-2-pve',
                'auth_method': 'ssh',
                'user': 'root',
                'key_path': 'C:\\Users\\rsyuzyov\\.ssh\\agent',
                'scan_status': STATUS_COMPLETED,
            })
            storage.update_host('192.168.88.60', {
                'ip': '192.168.88.60',
                'hostname': 'srv-existing',
                'os': 'Ubuntu 24.04',
                'auth_method': 'ssh',
                'user': 'root',
                'scan_status': STATUS_COMPLETED,
            })
            storage.flush()

            collector = FakeCollector({
                '192.168.88.11': [{
                    'id': '106',
                    'kind': 'ct',
                    'ips': ['192.168.88.60'],
                    'macs': [],
                    'update': {
                        'hostname': 'srv-overwrite',
                        'os': 'Debian GNU/Linux 12 (bookworm)',
                        'distribution': 'Debian GNU/Linux 12 (bookworm)',
                        'kernel_version': '6.1.0-33-amd64',
                        'category': 'linux',
                        'os_type': 'linux',
                        'type': 'server',
                    },
                }]
            })

            enricher = VirtualizationEnricher(storage=storage, credentials=[], collector=collector)
            enricher.enrich_all()

            host = storage.get_host_record('192.168.88.60')
            self.assertEqual(STATUS_COMPLETED, host.scan_status)
            self.assertEqual('srv-existing', host.hostname)

    def test_virtualization_enrichment_supports_vm_guest_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.88.12', {
                'ip': '192.168.88.12',
                'open_ports': [22, 8006],
                'services': ['SSH', 'Proxmox'],
                'vendor': 'Proxmox',
                'auth_method': 'ssh',
                'user': 'root',
                'key_path': 'C:\\Users\\rsyuzyov\\.ssh\\agent',
                'scan_status': STATUS_COMPLETED,
            })
            storage.update_host('192.168.88.180', {
                'ip': '192.168.88.180',
                'scan_status': STATUS_AUTH_AVAILABLE_NO_ACCESS,
            })
            storage.flush()

            collector = FakeCollector({
                '192.168.88.12': [{
                    'id': '102',
                    'kind': 'vm',
                    'ips': ['192.168.88.180'],
                    'macs': ['bc:24:11:56:0d:63'],
                    'update': {
                        'hostname': 'srv-rds2',
                        'hostnames': ['srv-rds2'],
                        'os': 'Windows 10 Pro',
                        'distribution': '',
                        'kernel_version': '19045',
                        'mac': 'bc:24:11:56:0d:63',
                        'category': 'windows',
                        'os_type': 'windows',
                        'type': 'server',
                    },
                }]
            })

            enricher = VirtualizationEnricher(storage=storage, credentials=[], collector=collector)
            enricher.enrich_all()

            host = storage.get_host_record('192.168.88.180')
            self.assertEqual(STATUS_VIRTUALIZATION_COMPLETED, host.scan_status)
            self.assertEqual('srv-rds2', host.hostname)
            self.assertEqual('windows', host.category)
            self.assertEqual('Windows 10 Pro', host.os)

    def test_virtualization_enrichment_skips_ambiguous_duplicate_guest_ips(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.88.11', {
                'ip': '192.168.88.11',
                'open_ports': [22, 8006],
                'services': ['SSH', 'Proxmox'],
                'vendor': 'Proxmox',
                'auth_method': 'ssh',
                'user': 'root',
                'key_path': 'C:\\Users\\rsyuzyov\\.ssh\\agent',
                'scan_status': STATUS_COMPLETED,
            })
            storage.update_host('192.168.88.12', {
                'ip': '192.168.88.12',
                'open_ports': [22, 8006],
                'services': ['SSH', 'Proxmox'],
                'vendor': 'Proxmox',
                'auth_method': 'ssh',
                'user': 'root',
                'key_path': 'C:\\Users\\rsyuzyov\\.ssh\\agent',
                'scan_status': STATUS_COMPLETED,
            })
            storage.update_host('192.168.88.151', {
                'ip': '192.168.88.151',
                'scan_status': STATUS_AUTH_AVAILABLE_NO_ACCESS,
            })
            storage.flush()

            collector = FakeCollector({
                '192.168.88.11': [{
                    'id': '120',
                    'kind': 'ct',
                    'ips': ['192.168.88.151'],
                    'macs': ['bc:24:11:52:fe:ae'],
                    'update': {
                        'hostname': 'test-backup',
                        'hostnames': ['test-backup'],
                        'os': 'Debian GNU/Linux 12 (bookworm)',
                        'distribution': 'Debian GNU/Linux 12 (bookworm)',
                        'kernel_version': '6.1.0-33-amd64',
                        'mac': 'bc:24:11:52:fe:ae',
                        'category': 'linux',
                        'os_type': 'linux',
                        'type': 'server',
                    },
                }],
                '192.168.88.12': [{
                    'id': '124',
                    'kind': 'vm',
                    'ips': ['192.168.88.151'],
                    'macs': ['bc:24:11:84:6d:53'],
                    'update': {
                        'hostname': 'srv-rds-gate',
                        'hostnames': ['srv-rds-gate'],
                        'os': 'Windows 10 Pro',
                        'distribution': '',
                        'kernel_version': '19045',
                        'mac': 'bc:24:11:84:6d:53',
                        'category': 'windows',
                        'os_type': 'windows',
                        'type': 'server',
                    },
                }],
            })

            enricher = VirtualizationEnricher(storage=storage, credentials=[], collector=collector)
            enricher.enrich_all()

            host = storage.get_host_record('192.168.88.151')
            self.assertEqual(STATUS_AUTH_AVAILABLE_NO_ACCESS, host.scan_status)
            self.assertEqual('', host.hostname)

    def test_virtualization_enrichment_overwrites_stale_vendor_and_model(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.88.11', {
                'ip': '192.168.88.11',
                'open_ports': [22, 8006],
                'services': ['SSH', 'Proxmox'],
                'vendor': 'Proxmox',
                'auth_method': 'ssh',
                'user': 'root',
                'key_path': 'C:\\Users\\rsyuzyov\\.ssh\\agent',
                'scan_status': STATUS_COMPLETED,
            })
            storage.update_host('192.168.88.177', {
                'ip': '192.168.88.177',
                'vendor': 'Microsoft',
                'model': 'Windows',
                'category': 'windows',
                'os_type': 'windows',
                'type': 'workstation',
                'scan_status': STATUS_AUTH_AVAILABLE_NO_ACCESS,
            })
            storage.flush()

            collector = FakeCollector({
                '192.168.88.11': [{
                    'id': '131',
                    'kind': 'ct',
                    'ips': ['192.168.88.177'],
                    'macs': ['bc:24:11:25:44:87'],
                    'update': {
                        'hostname': 'aiproxy1',
                        'hostnames': ['aiproxy1'],
                        'os': 'Debian GNU/Linux 13 (trixie)',
                        'distribution': 'Debian GNU/Linux 13 (trixie)',
                        'kernel_version': '6.17.13-2-pve',
                        'mac': 'bc:24:11:25:44:87',
                        'vendor': '',
                        'model': 'Debian GNU/Linux 13 (trixie)',
                        'category': 'linux',
                        'os_type': 'linux',
                        'type': 'server',
                    },
                }]
            })

            enricher = VirtualizationEnricher(storage=storage, credentials=[], collector=collector)
            enricher.enrich_all()

            host = storage.get_host_record('192.168.88.177')
            self.assertEqual(STATUS_VIRTUALIZATION_COMPLETED, host.scan_status)
            self.assertEqual('', host.vendor)
            self.assertEqual('Debian GNU/Linux 13 (trixie)', host.model)
            self.assertEqual('linux', host.category)


if __name__ == '__main__':
    unittest.main()
