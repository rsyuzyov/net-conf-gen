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

    def test_camera_with_synology_qnap_service_noise_stays_vendorless(self):
        result = classify_host({
            'ip': '192.168.1.14',
            'open_ports': [23, 554, 5000],
            'services': ['Telnet', 'RTSP', 'Synology-QNAP'],
            'service_details': {
                23: {'name': '', 'product': 'Telnet', 'version': '', 'extrainfo': '', 'tunnel': ''},
                554: {'name': '', 'product': 'RTSP', 'version': '', 'extrainfo': '', 'tunnel': ''},
                5000: {'name': '', 'product': 'Synology-QNAP', 'version': '', 'extrainfo': '', 'tunnel': ''},
            },
            'web_probes': {
                5000: {'reachable': False, 'error': 'connection reset'}
            },
        })

        self.assertEqual('camera', result['category'])
        self.assertEqual('camera', result['type'])
        self.assertEqual('', result['vendor'])

    def test_epson_web_signal_classifies_as_printer(self):
        result = classify_host({
            'ip': '192.168.1.15',
            'open_ports': [80, 443],
            'services': ['HTTP', 'HTTPS'],
            'web_probes': {
                80: {
                    'title': 'L8180 Series',
                    'server': 'EPSON_Linux UPnP/1.0 Epson UPnP SDK/1.0',
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
        self.assertEqual('Epson', result['vendor'])

    def test_printer_signal_beats_mikrotik_winbox_noise(self):
        result = classify_host({
            'ip': '192.168.1.16',
            'open_ports': [80, 8080, 8291, 9100],
            'services': ['HTTP', 'HTTP-Alt', 'MikroTik-Winbox', 'Printer'],
            'os': 'MikroTik RouterOS',
            'service_details': {
                8291: {'name': '', 'product': 'MikroTik-Winbox', 'version': '', 'extrainfo': '', 'tunnel': ''},
                9100: {'name': '', 'product': 'Printer', 'version': '', 'extrainfo': '', 'tunnel': ''},
            },
            'web_probes': {
                80: {
                    'title': 'HP LaserJet 400 MFP M425dn 192.168.1.16',
                    'server': 'Virata-EmWeb/R6_2_1',
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
        self.assertEqual('HP', result['vendor'])
        self.assertEqual('Printer', result['os'])

    def test_netgear_title_beats_synology_service_noise(self):
        result = classify_host({
            'ip': '192.168.1.17',
            'open_ports': [53, 80, 5000],
            'services': ['DNS', 'HTTP', 'Synology-QNAP'],
            'service_details': {
                5000: {'name': '', 'product': 'Synology-QNAP', 'version': '', 'extrainfo': '', 'tunnel': ''},
            },
            'web_probes': {
                80: {
                    'title': 'NETGEAR Router DGN2200v3',
                    'server': '',
                    'location': '',
                    'content_type': 'text/html',
                    'auth_scheme': 'basic',
                    'tls_subject': '',
                    'tls_issuer': '',
                    'tls_san': [],
                }
            },
        })

        self.assertEqual('network', result['category'])
        self.assertEqual('network', result['type'])
        self.assertEqual('Netgear', result['vendor'])
        self.assertEqual('dgn2200v3', result['model'])

    def test_nag_vendor_with_switch_login_page_classifies_as_network(self):
        result = classify_host({
            'ip': '192.168.1.18',
            'vendor': 'NAG',
            'model': 'SNR-S2985G-24TC',
            'open_ports': [22, 23, 80],
            'services': ['SSH', 'Telnet', 'HTTP'],
            'service_details': {
                22: {'name': '', 'product': 'SSH', 'version': '', 'extrainfo': '', 'tunnel': ''},
                23: {'name': '', 'product': 'Telnet', 'version': '', 'extrainfo': '', 'tunnel': ''},
                80: {'name': '', 'product': 'HTTP', 'version': '', 'extrainfo': '', 'tunnel': ''},
            },
            'web_probes': {
                80: {
                    'title': '',
                    'server': 'GoAhead-Webs',
                    'location': 'http://192.168.1.18/default.html',
                    'content_type': 'text/html',
                    'auth_scheme': '',
                    'tls_subject': '',
                    'tls_issuer': '',
                    'tls_san': [],
                    'device_family': 'snr_switch_web',
                    'device_model': 'SNR-S2985G-24TC',
                }
            },
        })

        self.assertEqual('network', result['category'])
        self.assertEqual('network', result['type'])
        self.assertEqual('NAG', result['vendor'])


if __name__ == '__main__':
    unittest.main()
