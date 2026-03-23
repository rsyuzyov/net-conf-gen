import unittest

from src.classification import classify_host


class ClassificationTests(unittest.TestCase):
    def test_weak_vendor_signal_stays_unknown(self):
        result = classify_host({
            'ip': '192.168.1.10',
            'vendor': 'Proxmox Server Solutions GmbH',
            'open_ports': [],
            'services': [],
            'service_details': {},
        })

        self.assertEqual('unknown', result['category'])
        self.assertEqual('unknown', result['type'])
        self.assertEqual('', result['os_type'])

    def test_linux_guess_requires_stronger_signal_than_just_ssh_port(self):
        result = classify_host({
            'ip': '192.168.1.11',
            'open_ports': [22],
            'services': ['SSH'],
            'service_details': {22: {'name': '', 'product': 'SSH', 'version': '', 'extrainfo': '', 'tunnel': ''}},
        })

        self.assertEqual('unknown', result['category'])
        self.assertEqual('unknown', result['type'])

    def test_printer_web_signal_beats_generic_service_noise(self):
        result = classify_host({
            'ip': '192.168.1.12',
            'open_ports': [80, 443, 5000],
            'services': ['HTTP', 'HTTPS', 'Synology-QNAP'],
            'service_details': {
                5000: {'name': '', 'product': 'Synology-QNAP', 'version': '', 'extrainfo': '', 'tunnel': ''},
            },
            'web_probes': {
                80: {
                    'title': 'Lexmark MX510de',
                    'server': '',
                    'location': '',
                    'content_type': 'text/html',
                    'auth_scheme': '',
                    'tls_subject': '',
                    'tls_issuer': '',
                    'tls_san': [],
                }
            },
        })

        self.assertEqual('printer', result['category'])
        self.assertEqual('printer', result['type'])
        self.assertEqual('linux', result['os_type'])
        self.assertEqual('Printer', result['os'])

    def test_proxmox_host_with_printer_port_stays_linux(self):
        result = classify_host({
            'ip': '192.168.1.13',
            'open_ports': [22, 8006, 9100],
            'services': ['SSH', 'Proxmox', 'Printer'],
            'service_details': {
                22: {'name': '', 'product': 'SSH', 'version': '', 'extrainfo': '', 'tunnel': ''},
                8006: {'name': '', 'product': 'Proxmox', 'version': '', 'extrainfo': '', 'tunnel': ''},
                9100: {'name': '', 'product': 'Printer', 'version': '', 'extrainfo': '', 'tunnel': ''},
            },
            'os': 'Debian GNU/Linux 13 (trixie)',
            'web_probes': {
                8006: {
                    'title': 'srv-hv1 - Proxmox Virtual Environment',
                    'server': 'pve-api-daemon/3.0',
                    'location': '',
                    'content_type': 'text/html',
                    'auth_scheme': '',
                    'tls_subject': 'srv-hv1.example.local',
                    'tls_issuer': 'Proxmox Virtual Environment',
                    'tls_san': ['srv-hv1.example.local'],
                }
            },
        })

        self.assertEqual('linux', result['category'])
        self.assertEqual('server', result['type'])
        self.assertEqual('linux', result['os_type'])


if __name__ == '__main__':
    unittest.main()
