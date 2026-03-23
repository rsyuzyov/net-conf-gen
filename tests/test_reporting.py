import json
import tempfile
import unittest
from pathlib import Path

from src.constants import STATUS_COMPLETED, STATUS_VIRTUALIZATION_COMPLETED, STATUS_WEB_COMPLETED
from src.reporting import ReportGenerator
from src.storage import Storage


class ReportingTests(unittest.TestCase):
    def test_reporting_uses_scan_status_and_successful_auth_method(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.10', {
                'ip': '192.168.1.10',
                'hostname': 'srv-app1',
                'type': 'server',
                'category': 'linux',
                'os_type': 'linux',
                'os': 'Ubuntu 24.04',
                'vendor': 'Proxmox',
                'open_ports': [22, 443],
                'services': ['SSH', 'HTTPS'],
                'auth_method': 'ssh',
                'auth_methods': ['ssh'],
                'scan_status': STATUS_COMPLETED,
                'user': 'root',
            })
            storage.flush()

            reporter = ReportGenerator(storage, output_dir=tmpdir, domain='example.local', targets=['192.168.1.0/24'])
            reporter.generate_all()

            inventory = Path(tmpdir, 'inventory.yaml').read_text(encoding='utf-8')
            ssh_config = Path(tmpdir, 'ssh_config').read_text(encoding='utf-8')
            csv_text = Path(tmpdir, 'scan_report.csv').read_text(encoding='utf-8')
            html_report = Path(tmpdir, 'scan_report.html').read_text(encoding='utf-8')
            json_report = json.loads(Path(tmpdir, 'scan_report.json').read_text(encoding='utf-8'))

            self.assertIn('ansible_connection: ssh', inventory)
            self.assertIn('ansible_user: root', inventory)
            self.assertIn('Host srv-app1.example.local srv-app1', ssh_config)
            self.assertIn('scan_status,auth_method,open_ports', csv_text)
            self.assertIn('Scan Status', html_report)
            self.assertIn(STATUS_COMPLETED, html_report)
            self.assertEqual(STATUS_COMPLETED, json_report['192.168.1.10']['scan_status'])

    def test_reporting_highlights_virtualization_completed_like_completed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.29', {
                'ip': '192.168.1.29',
                'hostname': 'docker1',
                'type': 'server',
                'category': 'linux',
                'os_type': 'linux',
                'os': 'Debian GNU/Linux 12 (bookworm)',
                'scan_status': STATUS_VIRTUALIZATION_COMPLETED,
            })
            storage.flush()

            reporter = ReportGenerator(storage, output_dir=tmpdir, domain='example.local', targets=['192.168.1.0/24'])
            reporter.generate_all()

            html_report = Path(tmpdir, 'scan_report.html').read_text(encoding='utf-8')

            self.assertIn('.scan-virtualization-completed', html_report)
            self.assertIn('class="host-linux scan-virtualization-completed"', html_report)

    def test_reporting_highlights_web_completed_like_completed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.31', {
                'ip': '192.168.1.31',
                'hostname': 'KM2F6870',
                'type': 'printer',
                'category': 'printer',
                'os_type': 'linux',
                'os': 'Printer',
                'vendor': 'Kyocera',
                'model': 'ECOSYS M2135dn',
                'scan_status': STATUS_WEB_COMPLETED,
            })
            storage.flush()

            reporter = ReportGenerator(storage, output_dir=tmpdir, domain='example.local', targets=['192.168.1.0/24'])
            reporter.generate_all()

            html_report = Path(tmpdir, 'scan_report.html').read_text(encoding='utf-8')

            self.assertIn('.scan-web-completed', html_report)
            self.assertIn('class="host-linux scan-web-completed"', html_report)


if __name__ == '__main__':
    unittest.main()
