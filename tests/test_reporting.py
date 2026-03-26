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
                'key_path': '/home/test/.ssh/id_ed25519',
            })
            storage.flush()

            reporter = ReportGenerator(storage, output_dir=tmpdir, domain='example.local', targets=['192.168.1.0/24'])
            reporter.generate_all()

            inventory = Path(tmpdir, 'inventory.yaml').read_text(encoding='utf-8')
            inventory_full = Path(tmpdir, 'inventory_full.yaml').read_text(encoding='utf-8')
            inventory_full = Path(tmpdir, 'inventory_full.yaml').read_text(encoding='utf-8')
            linux_group_vars = Path(tmpdir, 'group_vars', 'linux.yml').read_text(encoding='utf-8')
            linux_servers_group_vars = Path(tmpdir, 'group_vars', 'linux_servers_ssh.yml').read_text(encoding='utf-8')
            ssh_config = Path(tmpdir, 'ssh_config').read_text(encoding='utf-8')
            csv_text = Path(tmpdir, 'scan_report.csv').read_text(encoding='utf-8')
            html_report = Path(tmpdir, 'scan_report.html').read_text(encoding='utf-8')
            json_report = json.loads(Path(tmpdir, 'scan_report.json').read_text(encoding='utf-8'))

            self.assertIn('managed:', inventory)
            self.assertIn('linux_servers_ssh:', inventory)
            self.assertIn('netconf_os: Ubuntu 24.04', inventory)
            self.assertNotIn('netconf_scan_status: completed', inventory)
            self.assertIn('managed:', inventory_full)
            self.assertIn('linux_servers_ssh:', inventory_full)
            self.assertIn('ansible_connection: ssh', linux_group_vars)
            self.assertIn('ansible_user: root', linux_servers_group_vars)
            self.assertIn('ansible_ssh_private_key_file:', linux_servers_group_vars)
            self.assertNotIn('ansible_ssh_private_key_file:', inventory)
            self.assertNotIn('netconf_auth_method:', inventory)
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
            inventory = Path(tmpdir, 'inventory.yaml').read_text(encoding='utf-8')
            inventory_full = Path(tmpdir, 'inventory_full.yaml').read_text(encoding='utf-8')
            inventory_full = Path(tmpdir, 'inventory_full.yaml').read_text(encoding='utf-8')
            inventory_full = Path(tmpdir, 'inventory_full.yaml').read_text(encoding='utf-8')
            inventory_full = Path(tmpdir, 'inventory_full.yaml').read_text(encoding='utf-8')
            winrm_group_vars = Path(tmpdir, 'group_vars', 'windows_winrm.yml').read_text(encoding='utf-8')
            psexec_group_vars = Path(tmpdir, 'group_vars', 'windows_psexec.yml').read_text(encoding='utf-8')

            self.assertIn('function copyWinRM(host, user)', html_report)
            self.assertIn('function copyPsExec(host, user)', html_report)
            self.assertIn('data-type="winrm"', html_report)
            self.assertIn('data-type="psexec"', html_report)
            self.assertIn('windows_winrm:', inventory)
            self.assertIn('windows_psexec:', inventory)
            self.assertNotIn('netconf_vendor: Microsoft', inventory)
            self.assertNotIn('netconf_model: Windows 10 22H2', inventory)
            self.assertIn('ansible_connection: winrm', winrm_group_vars)
            self.assertIn('ansible_connection: psexec', psexec_group_vars)
            self.assertNotIn('ansible_connection: winrm\n', inventory)
            self.assertIn('ansible_user: domain\\user', winrm_group_vars)
            self.assertIn('ansible_user: domain\\user', psexec_group_vars)
            self.assertNotIn('ansible_user: domain\\user', inventory)

    def test_inventory_prefers_ssh_over_winrm_and_psexec(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.22', {
                'ip': '192.168.1.22',
                'hostname': 'win-ssh',
                'type': 'server',
                'category': 'windows',
                'os_type': 'windows',
                'os': 'Microsoft Windows Server 2022 Standard',
                'auth_method': 'psexec',
                'auth_methods': ['winrm', 'psexec', 'ssh'],
                'scan_status': STATUS_COMPLETED,
                'success': True,
                'user': 'administrator',
            })
            storage.flush()

            reporter = ReportGenerator(storage, output_dir=tmpdir, domain='example.local')
            reporter.generate_all()

            inventory = Path(tmpdir, 'inventory.yaml').read_text(encoding='utf-8')
            windows_ssh_group_vars = Path(tmpdir, 'group_vars', 'windows_ssh.yml').read_text(encoding='utf-8')

            self.assertIn('windows_ssh:', inventory)
            self.assertIn('win-ssh:', inventory)
            self.assertIn('ansible_connection: ssh', windows_ssh_group_vars)
            self.assertIn('ansible_user: administrator', windows_ssh_group_vars)
            self.assertNotIn('devices_ssh:\n          hosts:\n            win-ssh:', inventory)
            self.assertNotIn('windows_psexec:\n          hosts:\n            win-ssh:', inventory)
            self.assertNotIn('windows_winrm:\n          hosts:\n            win-ssh:', inventory)

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
            inventory = Path(tmpdir, 'inventory.yaml').read_text(encoding='utf-8')
            inventory_full = Path(tmpdir, 'inventory_full.yaml').read_text(encoding='utf-8')

            self.assertIn('.scan-virtualization-completed', html_report)
            self.assertIn('class="host-linux scan-virtualization-completed"', html_report)
            self.assertIn('Подключение и виртуализация', html_report)
            self.assertNotIn('docker1:', inventory)
            self.assertIn('docker1:', inventory_full)
            self.assertIn('netconf_scan_status: virtualization_completed', inventory_full)

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

    def test_inventory_uses_fallback_aliases_and_separates_discovered_hosts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.50', {
                'ip': '192.168.1.50',
                'hostname': 'host',
                'type': 'server',
                'category': 'windows',
                'os_type': 'windows',
                'os': 'Microsoft Windows Server 2019 Standard',
                'auth_method': 'winrm',
                'scan_status': STATUS_COMPLETED,
                'success': True,
                'user': 'domain\\svc_ansible',
            })
            storage.update_host('192.168.1.60', {
                'ip': '192.168.1.60',
                'type': 'printer',
                'category': 'printer',
                'os_type': 'linux',
                'os': 'Printer',
                'vendor': 'HP',
                'model': 'LaserJet',
                'scan_status': 'discovered',
            })
            storage.flush()

            reporter = ReportGenerator(storage, output_dir=tmpdir, domain='example.local')
            reporter.generate_all()

            inventory = Path(tmpdir, 'inventory.yaml').read_text(encoding='utf-8')
            inventory_full = Path(tmpdir, 'inventory_full.yaml').read_text(encoding='utf-8')
            windows_winrm_group_vars = Path(tmpdir, 'group_vars', 'windows_winrm.yml').read_text(encoding='utf-8')

            self.assertIn('server-192-168-1-50:', inventory)
            self.assertNotIn('\n    discovered:', inventory)
            self.assertIn('discovered:', inventory_full)
            self.assertIn('printers:', inventory_full)
            self.assertIn('printer-192-168-1-60:', inventory_full)
            self.assertIn('managed/windows/windows_winrm', inventory_full)
            self.assertIn('ansible_user: domain\\svc_ansible', windows_winrm_group_vars)


if __name__ == '__main__':
    unittest.main()
