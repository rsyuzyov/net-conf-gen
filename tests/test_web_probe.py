import tempfile
import unittest

from src.storage import Storage
from src.web_probe import WebProbeEnricher
from src.constants import STATUS_WEB_COMPLETED


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


if __name__ == '__main__':
    unittest.main()
