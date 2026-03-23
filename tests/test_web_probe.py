import tempfile
import unittest

from src.storage import Storage
from src.web_probe import WebProbeEnricher
from src.constants import STATUS_DISCOVERED, STATUS_WEB_COMPLETED


class StubWebProbeEnricher(WebProbeEnricher):
    def __init__(self, storage, probes_by_port, metadata_by_port=None):
        super().__init__(storage=storage, concurrency=1, timeout=1)
        self.probes_by_port = probes_by_port
        self.metadata_by_port = metadata_by_port or {}

    def _probe_port(self, ip, port):
        if port not in self.probes_by_port:
            return {
                'port': port,
                'scheme': 'https' if port == 443 else 'http',
                'reachable': False,
                'error': 'not stubbed',
            }
        probe = dict(self.probes_by_port[port])
        probe.setdefault('port', port)
        return probe

    def _fetch_targeted_probe_metadata(self, ip, probe):
        return dict(self.metadata_by_port.get(probe['port'], {}))


class WebProbeTests(unittest.TestCase):
    def test_web_probe_targets_camera_http_port_8899(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.218', {
                'ip': '192.168.1.218',
                'open_ports': [8899, 34567],
                'services': ['ONVIF', 'XMEye'],
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = WebProbeEnricher(storage=storage, concurrency=1, timeout=1)
            host = storage.get_host_record('192.168.1.218')

            self.assertEqual([8899], enricher._target_ports(host))

    def test_web_probe_updates_structured_web_fields_and_vendor_model(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.10', {
                'ip': '192.168.1.10',
                'open_ports': [443],
                'services': ['HTTPS'],
                'scan_status': 'discovered',
            })
            storage.flush()

            enricher = StubWebProbeEnricher(storage, {
                443: {
                    'scheme': 'https',
                    'reachable': True,
                    'status_code': 200,
                    'title': 'Proxmox Virtual Environment',
                    'server': 'pve-api-daemon/3.0',
                    'content_type': 'text/html',
                    'location': '',
                    'final_url': 'https://192.168.1.10:443/',
                    'www_authenticate': '',
                    'auth_scheme': '',
                    'redirect_to_login': False,
                    'is_login_page': True,
                    'tls_subject': 'srv-hv1.ag.local',
                    'tls_issuer': 'Proxmox VE',
                    'tls_san': ['srv-hv1.ag.local'],
                    'tls_not_before': 'Jan  1 00:00:00 2026 GMT',
                    'tls_not_after': 'Jan  1 00:00:00 2028 GMT',
                }
            })

            enricher.probe_host('192.168.1.10')

            host = storage.get_host_record('192.168.1.10')
            self.assertEqual('Proxmox', host.vendor)
            self.assertEqual('Proxmox VE', host.model)
            self.assertIn(443, host.web_probes)
            self.assertEqual('srv-hv1.ag.local', host.web_probes[443]['tls_subject'])

    def test_web_probe_can_reclassify_mikrotik_from_http_title(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.20', {
                'ip': '192.168.1.20',
                'open_ports': [80],
                'services': ['HTTP'],
                'scan_status': 'discovered',
            })
            storage.flush()

            enricher = StubWebProbeEnricher(storage, {
                80: {
                    'scheme': 'http',
                    'reachable': True,
                    'status_code': 200,
                    'title': 'MikroTik RouterOS',
                    'server': '',
                    'content_type': 'text/html',
                    'location': '',
                    'final_url': 'http://192.168.1.20:80/',
                    'www_authenticate': '',
                    'auth_scheme': '',
                    'redirect_to_login': False,
                    'is_login_page': False,
                }
            })

            enricher.probe_host('192.168.1.20')

            host = storage.get_host_record('192.168.1.20')
            self.assertEqual('mikrotik', host.category)
            self.assertEqual('mikrotik', host.type)
            self.assertEqual('MikroTik', host.vendor)
            self.assertEqual('RouterOS', host.model)

    def test_web_probe_applies_kyocera_targeted_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.31', {
                'ip': '192.168.1.31',
                'open_ports': [80, 443],
                'services': ['HTTP', 'HTTPS'],
                'category': 'printer',
                'type': 'printer',
                'os_type': 'linux',
                'os': 'Printer',
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = StubWebProbeEnricher(
                storage,
                {
                    80: {
                        'scheme': 'http',
                        'reachable': True,
                        'status_code': 200,
                        'title': '',
                        'server': 'KM-MFP-http/V0.0.1',
                        'content_type': 'text/html',
                        'location': '',
                        'final_url': 'http://192.168.1.31:80/',
                        'www_authenticate': '',
                        'auth_scheme': '',
                        'redirect_to_login': False,
                        'is_login_page': False,
                    }
                },
                metadata_by_port={
                    80: {
                        'device_vendor': 'Kyocera',
                        'device_family': 'command_center_rx',
                        'device_model': 'ECOSYS M2135dn',
                        'device_hostname': 'KM2F6870',
                        'device_location': '',
                    }
                },
            )

            enricher.probe_host('192.168.1.31')

            host = storage.get_host_record('192.168.1.31')
            self.assertEqual('Kyocera', host.vendor)
            self.assertEqual('ECOSYS M2135dn', host.model)
            self.assertEqual('KM2F6870', host.hostname)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)
            self.assertEqual('Kyocera', host.web_probes[80]['device_vendor'])
            self.assertEqual('ECOSYS M2135dn', host.web_probes[80]['device_model'])

    def test_web_probe_marks_canon_printer_completed_from_http_and_tls(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.175', {
                'ip': '192.168.1.175',
                'open_ports': [80, 443],
                'services': ['HTTP', 'HTTPS'],
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = StubWebProbeEnricher(storage, {
                80: {
                    'scheme': 'http',
                    'reachable': True,
                    'status_code': 200,
                    'title': 'Удаленный ИП: Вход: MF460 Series: MF460 Series',
                    'server': 'CANON HTTP Server',
                    'content_type': 'text/html;charset=UTF-8',
                    'location': '',
                    'final_url': 'http://192.168.1.175:80/',
                    'www_authenticate': '',
                    'auth_scheme': '',
                    'redirect_to_login': False,
                    'is_login_page': True,
                },
                443: {
                    'scheme': 'https',
                    'reachable': True,
                    'status_code': 404,
                    'title': '',
                    'server': 'CANON HTTP Server',
                    'content_type': 'text/html',
                    'location': '',
                    'final_url': 'https://192.168.1.175:443/',
                    'www_authenticate': '',
                    'auth_scheme': '',
                    'redirect_to_login': False,
                    'is_login_page': False,
                    'tls_subject': 'Canon Imaging Product',
                    'tls_issuer': 'Canon Imaging Product',
                    'tls_san': [],
                    'tls_not_before': 'Jan  1 00:00:00 2012 GMT',
                    'tls_not_after': 'Dec 31 23:59:59 2037 GMT',
                },
            })

            enricher.probe_host('192.168.1.175')

            host = storage.get_host_record('192.168.1.175')
            self.assertEqual('printer', host.category)
            self.assertEqual('printer', host.type)
            self.assertEqual('Canon', host.vendor)
            self.assertEqual('MF460 Series', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)

    def test_web_probe_prefers_lexmark_ui_over_generic_synology_service(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.189', {
                'ip': '192.168.1.189',
                'open_ports': [80, 443, 5000],
                'services': ['HTTP', 'HTTPS', 'Synology-QNAP'],
                'service_details': {
                    5000: {'name': '', 'product': 'Synology-QNAP', 'version': '', 'extrainfo': '', 'tunnel': ''},
                },
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = StubWebProbeEnricher(storage, {
                80: {
                    'scheme': 'http',
                    'reachable': True,
                    'status_code': 200,
                    'title': 'Lexmark MX510de',
                    'server': '',
                    'content_type': 'text/html',
                    'location': '',
                    'final_url': 'http://192.168.1.189:80/',
                    'www_authenticate': '',
                    'auth_scheme': '',
                    'redirect_to_login': False,
                    'is_login_page': False,
                },
                443: {
                    'scheme': 'https',
                    'reachable': False,
                    'error': 'handshake failure',
                },
                5000: {
                    'scheme': 'http',
                    'reachable': False,
                    'error': 'connection reset',
                },
            })

            enricher.probe_host('192.168.1.189')

            host = storage.get_host_record('192.168.1.189')
            self.assertEqual('printer', host.category)
            self.assertEqual('printer', host.type)
            self.assertEqual('Lexmark', host.vendor)
            self.assertEqual('MX510de', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)

    def test_web_probe_extracts_xerox_vendor_and_model_from_phaser_title(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.182', {
                'ip': '192.168.1.182',
                'open_ports': [80, 443],
                'services': ['HTTP', 'HTTPS'],
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = StubWebProbeEnricher(storage, {
                80: {
                    'scheme': 'http',
                    'reachable': True,
                    'status_code': 200,
                    'title': '- Phaser 5550N',
                    'server': 'Allegro-Software-RomPager/4.34',
                    'content_type': 'text/html',
                    'location': '',
                    'final_url': 'http://192.168.1.182:80/',
                    'www_authenticate': '',
                    'auth_scheme': '',
                    'redirect_to_login': False,
                    'is_login_page': False,
                }
            })

            enricher.probe_host('192.168.1.182')

            host = storage.get_host_record('192.168.1.182')
            self.assertEqual('printer', host.category)
            self.assertEqual('printer', host.type)
            self.assertEqual('Xerox', host.vendor)
            self.assertEqual('Phaser 5550N', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)

    def test_web_probe_classifies_pantum_printer_from_tls_vendor(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.183', {
                'ip': '192.168.1.183',
                'open_ports': [80, 443],
                'services': ['HTTP', 'HTTPS'],
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = StubWebProbeEnricher(storage, {
                80: {
                    'scheme': 'http',
                    'reachable': True,
                    'status_code': 200,
                    'title': '',
                    'server': '',
                    'content_type': 'text/html',
                    'location': '',
                    'final_url': 'http://192.168.1.183:80/',
                    'www_authenticate': '',
                    'auth_scheme': '',
                    'redirect_to_login': False,
                    'is_login_page': False,
                },
                443: {
                    'scheme': 'https',
                    'reachable': True,
                    'status_code': 500,
                    'title': '',
                    'server': '',
                    'content_type': 'text/html',
                    'location': '',
                    'final_url': 'https://192.168.1.183:443/',
                    'www_authenticate': '',
                    'auth_scheme': '',
                    'redirect_to_login': False,
                    'is_login_page': False,
                    'tls_subject': 'Pantum Technology Cert',
                    'tls_issuer': 'Pantum Technology Cert',
                    'tls_san': [],
                    'tls_not_before': 'Aug 25 03:48:22 2021 GMT',
                    'tls_not_after': 'Aug 23 03:48:22 2031 GMT',
                },
            })

            enricher.probe_host('192.168.1.183')

            host = storage.get_host_record('192.168.1.183')
            self.assertEqual('printer', host.category)
            self.assertEqual('printer', host.type)
            self.assertEqual('Pantum', host.vendor)
            self.assertEqual('', host.model)
            self.assertEqual('scanned', host.scan_status)

    def test_web_probe_drops_stale_web_completed_when_model_is_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.184', {
                'ip': '192.168.1.184',
                'open_ports': [80, 443],
                'services': ['HTTP', 'HTTPS'],
                'scan_status': STATUS_WEB_COMPLETED,
            })
            storage.flush()

            enricher = StubWebProbeEnricher(storage, {
                80: {
                    'scheme': 'http',
                    'reachable': True,
                    'status_code': 200,
                    'title': '',
                    'server': '',
                    'content_type': 'text/html',
                    'location': '',
                    'final_url': 'http://192.168.1.184:80/',
                    'www_authenticate': '',
                    'auth_scheme': '',
                    'redirect_to_login': False,
                    'is_login_page': False,
                },
                443: {
                    'scheme': 'https',
                    'reachable': True,
                    'status_code': 500,
                    'title': '',
                    'server': '',
                    'content_type': 'text/html',
                    'location': '',
                    'final_url': 'https://192.168.1.184:443/',
                    'www_authenticate': '',
                    'auth_scheme': '',
                    'redirect_to_login': False,
                    'is_login_page': False,
                    'tls_subject': 'Pantum Technology Cert',
                    'tls_issuer': 'Pantum Technology Cert',
                    'tls_san': [],
                    'tls_not_before': 'Aug 25 03:48:22 2021 GMT',
                    'tls_not_after': 'Aug 23 03:48:22 2031 GMT',
                },
            })

            enricher.probe_host('192.168.1.184')

            host = storage.get_host_record('192.168.1.184')
            self.assertEqual('printer', host.category)
            self.assertEqual('Pantum', host.vendor)
            self.assertEqual('', host.model)
            self.assertEqual(STATUS_DISCOVERED, host.scan_status)

    def test_web_probe_identifies_xmeye_camera_family_on_8899(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.218', {
                'ip': '192.168.1.218',
                'open_ports': [8899, 34567],
                'services': ['ONVIF', 'XMEye'],
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = StubWebProbeEnricher(
                storage,
                {
                    8899: {
                        'scheme': 'http',
                        'reachable': True,
                        'status_code': 200,
                        'title': 'Web Viewer',
                        'server': '',
                        'content_type': 'text/html',
                        'location': '',
                        'final_url': 'http://192.168.1.218:8899/',
                        'www_authenticate': '',
                        'auth_scheme': '',
                        'redirect_to_login': False,
                        'is_login_page': False,
                    }
                },
                metadata_by_port={
                    8899: {
                        'device_vendor': 'XMEye',
                        'device_family': 'web_viewer',
                        'device_ui': 'Web Viewer',
                        'device_language': 'Russian',
                        'device_tcp_port': 34567,
                    }
                },
            )

            enricher.probe_host('192.168.1.218')

            host = storage.get_host_record('192.168.1.218')
            self.assertEqual('camera', host.category)
            self.assertEqual('camera', host.type)
            self.assertEqual('XMEye', host.vendor)
            self.assertEqual('', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)
            self.assertEqual('web_viewer', host.web_probes[8899]['device_family'])
            self.assertEqual('Russian', host.web_probes[8899]['device_language'])
            self.assertEqual(34567, host.web_probes[8899]['device_tcp_port'])


if __name__ == '__main__':
    unittest.main()
