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
                'success': True,
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
            self.assertIn('Подключение выполнено', html_report)
            self.assertEqual(STATUS_COMPLETED, json_report['192.168.1.10']['scan_status'])
            self.assertIn('function copySsh(host, user)', html_report)
            self.assertIn('data-type="ssh"', html_report)

    def test_reporting_renders_winrm_and_psexec_as_copy_actions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.20', {
                'ip': '192.168.1.20',
                'hostname': 'srv-winrm',
                'type': 'server',
                'category': 'windows',
                'os_type': 'windows',
                'os': 'Microsoft Windows Server 2022 Standard',
                'open_ports': [3389, 5985],
                'services': ['RDP', 'WinRM'],
                'auth_method': 'winrm',
                'auth_methods': ['winrm'],
                'scan_status': STATUS_COMPLETED,
                'user': 'domain\\user',
            })
            storage.update_host('192.168.1.21', {
                'ip': '192.168.1.21',
                'hostname': 'ws-01',
                'type': 'workstation',
                'category': 'windows',
                'os_type': 'windows',
                'os': 'Microsoft Windows 10 Pro',
                'open_ports': [3389, 445],
                'services': ['RDP', 'SMB'],
                'auth_method': 'psexec',
                'auth_methods': ['psexec'],
                'scan_status': STATUS_COMPLETED,
                'user': 'domain\\user',
            })
            storage.flush()

            reporter = ReportGenerator(storage, output_dir=tmpdir, domain='example.local')
            reporter.generate_all()

            html_report = Path(tmpdir, 'scan_report.html').read_text(encoding='utf-8')

            self.assertIn('function copyWinRM(host, user)', html_report)
            self.assertIn('function copyPsExec(host, user)', html_report)
            self.assertIn('data-type="winrm"', html_report)
            self.assertIn('data-type="psexec"', html_report)

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
            self.assertIn('Подключение и виртуализация', html_report)

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
            self.assertIn('Только web-проверка', html_report)

    def test_reporting_collapses_duplicate_services_and_warns_on_duplicate_hostnames(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.41', {
                'ip': '192.168.1.41',
                'hostname': 'dup-host',
                'type': 'server',
                'category': 'windows',
                'os_type': 'windows',
                'os': 'Microsoft Windows Server 2022 Standard',
                'open_ports': [3389, 5985, 1540, 1541, 1560, 1561],
                'services': ['RDP', 'WinRM', '1C', '1C', '1C', '1C'],
                'auth_method': 'winrm',
                'auth_methods': ['winrm'],
                'scan_status': STATUS_COMPLETED,
                'success': True,
                'user': 'domain\\user',
            })
            storage.update_host('192.168.1.42', {
                'ip': '192.168.1.42',
                'hostname': 'dup-host',
                'type': 'server',
                'category': 'linux',
                'os_type': 'linux',
                'os': 'Debian GNU/Linux 12 (bookworm)',
                'open_ports': [22],
                'services': ['SSH'],
                'auth_method': 'ssh',
                'auth_methods': ['ssh'],
                'scan_status': STATUS_COMPLETED,
                'success': True,
                'user': 'root',
            })
            storage.flush()

            reporter = ReportGenerator(storage, output_dir=tmpdir, domain='example.local')
            reporter.generate_all()

            html_report = Path(tmpdir, 'scan_report.html').read_text(encoding='utf-8')

            self.assertIn('1C (x4)', html_report)
            self.assertIn('Обнаружены дубликаты hostname/FQDN', html_report)
            self.assertIn('dup-host', html_report)


if __name__ == '__main__':
    unittest.main()
