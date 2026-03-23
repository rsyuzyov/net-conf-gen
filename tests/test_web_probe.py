import http.client
import tempfile
import unittest
from unittest import mock

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


class TargetedFetchStubWebProbeEnricher(WebProbeEnricher):
    def __init__(self, storage, responses_by_url, probes_by_port=None, post_responses=None):
        super().__init__(storage=storage, concurrency=1, timeout=1)
        self.responses_by_url = responses_by_url
        self.probes_by_port = probes_by_port or {}
        self.post_responses = post_responses or {}

    def _probe_port(self, ip, port):
        if port not in self.probes_by_port:
            return super()._probe_port(ip, port)
        probe = dict(self.probes_by_port[port])
        probe.setdefault('port', port)
        return probe

    def _open_url(self, url):
        response = self.responses_by_url.get(url)
        if response is None:
            return None
        return dict(response)

    def _open_url_with_headers(self, url, headers=None):
        key = (url, (headers or {}).get('Referer', ''))
        response = self.responses_by_url.get(key)
        if response is None:
            response = self.responses_by_url.get(url)
        if response is None:
            return None
        return dict(response)

    def _post_plain_text(self, url, body, headers=None):
        key = (url, body, (headers or {}).get('Referer', ''))
        response = self.post_responses.get(key)
        if response is None:
            response = self.post_responses.get((url, body))
        if response is None:
            return None
        return dict(response)


class RtspStubWebProbeEnricher(StubWebProbeEnricher):
    def __init__(self, storage, probes_by_port, metadata_by_port=None, rtsp_probe=None):
        super().__init__(storage, probes_by_port, metadata_by_port)
        self.rtsp_probe = rtsp_probe

    def _probe_rtsp_port(self, ip, port=554):
        if self.rtsp_probe is None:
            return super()._probe_rtsp_port(ip, port)
        probe = dict(self.rtsp_probe)
        probe.setdefault('port', port)
        probe.setdefault('scheme', 'rtsp')
        return probe


class PjlStubWebProbeEnricher(TargetedFetchStubWebProbeEnricher):
    def __init__(self, storage, responses_by_url, probes_by_port=None, post_responses=None, pjl_metadata=None):
        super().__init__(storage, responses_by_url, probes_by_port, post_responses)
        self.pjl_metadata = pjl_metadata or {}

    def _fetch_pjl_metadata(self, ip, vendor_hint=''):
        metadata = self.pjl_metadata.get(ip)
        if metadata is None:
            return super()._fetch_pjl_metadata(ip, vendor_hint)
        result = dict(metadata)
        if vendor_hint and 'device_vendor' not in result:
            result['device_vendor'] = vendor_hint
        return result


class WebProbeTests(unittest.TestCase):
    def test_probe_port_uses_partial_body_on_incomplete_read(self):
        class FakeResponse:
            def __init__(self):
                self.status = 200
                self.headers = {
                    'Server': 'Virata-EmWeb/R6_2_1',
                    'Content-Type': 'text/html',
                }

            def geturl(self):
                return 'http://192.168.1.85:8080/'

            def read(self, _limit):
                partial = (
                    b'<html><head><title>HP LaserJet 400 M401dn 192.168.1.85</title></head>'
                    b'<body></body></html>'
                )
                raise http.client.IncompleteRead(partial, len(partial) + 100)

            def close(self):
                return None

        class FakeOpener:
            def open(self, request, timeout):
                return FakeResponse()

        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            enricher = WebProbeEnricher(storage=storage, concurrency=1, timeout=1)
            enricher._http_opener = FakeOpener()

            probe = enricher._probe_port('192.168.1.85', 8080)

            self.assertTrue(probe['reachable'])
            self.assertEqual('HP LaserJet 400 M401dn 192.168.1.85', probe['title'])
            self.assertEqual('Virata-EmWeb/R6_2_1', probe['server'])

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

            self.assertEqual([8899, 80, 443], enricher._target_ports(host))

    def test_web_probe_adds_fallback_web_ports_for_printer_and_camera_shapes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.63', {
                'ip': '192.168.1.63',
                'open_ports': [9100],
                'services': ['Printer'],
                'scan_status': 'scanned',
            })
            storage.update_host('192.168.1.109', {
                'ip': '192.168.1.109',
                'open_ports': [34567],
                'services': ['XMEye'],
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = WebProbeEnricher(storage=storage, concurrency=1, timeout=1)
            printer = storage.get_host_record('192.168.1.63')
            camera = storage.get_host_record('192.168.1.109')

            self.assertEqual([80, 443, 8080], enricher._target_ports(printer))
            self.assertEqual([80, 443, 8899], enricher._target_ports(camera))

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

    def test_web_probe_marks_tplink_router_completed_from_preauth_device_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.10', {
                'ip': '192.168.1.10',
                'open_ports': [80],
                'services': ['HTTP'],
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = TargetedFetchStubWebProbeEnricher(
                storage,
                {
                    'http://192.168.1.10:80/': {
                        'status_code': 200,
                        'headers': {},
                        'body': (
                            '<html><head><title>Opening...</title></head><body>'
                            '<script src="js/libs/tpEncrypt.new.js"></script>'
                            '<script src="js/su/language.js"></script>'
                            '<script>$.su.language=new $.su.Language</script>'
                            '</body></html>'
                        ),
                        'final_url': 'http://192.168.1.10:80/',
                    },
                    'http://192.168.1.10:80/config/classes.json': {
                        'status_code': 200,
                        'headers': {},
                        'body': '{"deviceDataProxy":"./modules/main/models.js"}',
                        'final_url': 'http://192.168.1.10:80/config/classes.json',
                    },
                },
                probes_by_port={
                    80: {
                        'scheme': 'http',
                        'reachable': True,
                        'status_code': 200,
                        'title': 'Opening...',
                        'server': '',
                        'content_type': 'text/html;charset=UTF-8',
                        'location': '',
                        'final_url': 'http://192.168.1.10:80/',
                        'www_authenticate': '',
                        'auth_scheme': '',
                        'redirect_to_login': False,
                        'is_login_page': False,
                    }
                },
                post_responses={
                    ('http://192.168.1.10:80/?code=2&asyn=1', '0|1,0,0', 'http://192.168.1.10:80/'): {
                        'status_code': 200,
                        'headers': {},
                        'body': (
                            '00000\r\n'
                            'id 0|1,0,0\r\n'
                            'facturer TP-Link\r\n'
                            'modelName Archer%20C24\r\n'
                            'hardVer Archer%20C24%202.0\r\n'
                            'softVer 1.12.1%20Build%20230308%20Rel.63310n(5255)\r\n'
                        ),
                        'final_url': 'http://192.168.1.10:80/?code=2&asyn=1',
                    }
                },
            )

            enricher.probe_host('192.168.1.10')

            host = storage.get_host_record('192.168.1.10')
            self.assertEqual('network', host.type)
            self.assertEqual('TP-Link', host.vendor)
            self.assertEqual('Archer C24', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)

    def test_web_probe_marks_snr_switch_completed_from_login_page(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.49', {
                'ip': '192.168.1.49',
                'open_ports': [22, 23, 80],
                'services': ['SSH', 'Telnet', 'HTTP'],
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = TargetedFetchStubWebProbeEnricher(
                storage,
                {
                    'http://192.168.1.49:80/': {
                        'status_code': 200,
                        'headers': {},
                        'body': (
                            '<html><head><title>Switch Web Management (1366X768 is recommended)</title></head>'
                            '<body><form action="/goform/WebSetting.html">'
                            '<b>SNR-S2985G-24TC</b>'
                            '<div>Copyright (C) 2018 NAG LLC</div>'
                            '<a href="http://shop.nag.ru">http://shop.nag.ru</a>'
                            '</form></body></html>'
                        ),
                        'final_url': 'http://192.168.1.49:80/',
                    },
                },
                probes_by_port={
                    80: {
                        'scheme': 'http',
                        'reachable': True,
                        'status_code': 200,
                        'title': 'Switch Web Management (1366X768 is recommended)',
                        'server': 'GoAhead-Webs',
                        'content_type': 'text/html',
                        'location': '',
                        'final_url': 'http://192.168.1.49:80/',
                        'www_authenticate': '',
                        'auth_scheme': '',
                        'redirect_to_login': False,
                        'is_login_page': True,
                    }
                },
            )

            enricher.probe_host('192.168.1.49')

            host = storage.get_host_record('192.168.1.49')
            self.assertEqual('network', host.type)
            self.assertEqual('NAG', host.vendor)
            self.assertEqual('SNR-S2985G-24TC', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)

    def test_web_probe_marks_kyocera_completed_from_pjl_when_web_model_unavailable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.55', {
                'ip': '192.168.1.55',
                'open_ports': [80, 443, 9100],
                'services': ['HTTP', 'HTTPS', 'Printer'],
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = PjlStubWebProbeEnricher(
                storage,
                {
                    'http://192.168.1.55:80/': {
                        'status_code': 200,
                        'headers': {},
                        'body': (
                            '<html><head></head><body>'
                            '<script src="../js/jssrc/model/wlmpor/index.model.htm"></script>'
                            '<frame name="wlmframe" src="../startwlm/Start_Wlm.htm" />'
                            '</body></html>'
                        ),
                        'final_url': 'http://192.168.1.55:80/',
                    },
                    'http://192.168.1.55:80/js/jssrc/model/startwlm/Start_Wlm.model.htm?arg1=&arg2=&arg3=&arg4=&arg5=&arg6=&arg8=&arg9=&arg10=0&arg11=': {
                        'status_code': 500,
                        'headers': {},
                        'body': '500 Internal Sever Error',
                        'final_url': 'http://192.168.1.55:80/js/jssrc/model/startwlm/Start_Wlm.model.htm',
                    },
                    'http://192.168.1.55:80/DeepSleep.js': {
                        'status_code': 500,
                        'headers': {},
                        'body': '500 Internal Sever Error',
                        'final_url': 'http://192.168.1.55:80/DeepSleep.js',
                    },
                    'http://192.168.1.55:80/startwlm/Hme_PnlUsg.htm': {
                        'status_code': 500,
                        'headers': {},
                        'body': '500 Internal Sever Error',
                        'final_url': 'http://192.168.1.55:80/startwlm/Hme_PnlUsg.htm',
                    },
                },
                probes_by_port={
                    80: {
                        'scheme': 'http',
                        'reachable': True,
                        'status_code': 200,
                        'title': '',
                        'server': 'KM-MFP-http/V0.0.1',
                        'content_type': 'text/html; charset=UTF-8',
                        'location': '',
                        'final_url': 'http://192.168.1.55:80/',
                        'www_authenticate': '',
                        'auth_scheme': '',
                        'redirect_to_login': False,
                        'is_login_page': False,
                    }
                },
                pjl_metadata={
                    '192.168.1.55': {
                        'device_family': 'pjl_info_id',
                        'device_model': 'ECOSYS M2635dn',
                    }
                },
            )

            enricher.probe_host('192.168.1.55')

            host = storage.get_host_record('192.168.1.55')
            self.assertEqual('printer', host.type)
            self.assertEqual('Kyocera', host.vendor)
            self.assertEqual('ECOSYS M2635dn', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)
            self.assertEqual('pjl_info_id', host.web_probes[80]['device_family'])

    def test_fetch_kyocera_metadata_uses_deepsleep_js_model(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            enricher = TargetedFetchStubWebProbeEnricher(
                storage,
                {
                    'http://192.168.1.31/js/jssrc/model/startwlm/Start_Wlm.model.htm?arg1=&arg2=&arg3=&arg4=&arg5=&arg6=&arg8=&arg9=&arg10=0&arg11=': {
                        'status_code': 200,
                        'headers': {},
                        'body': '<html><frame src="DeepSleep.htm"></frame></html>',
                        'final_url': 'http://192.168.1.31/js/jssrc/model/startwlm/Start_Wlm.model.htm',
                    },
                    'http://192.168.1.31/DeepSleep.js': {
                        'status_code': 200,
                        'headers': {},
                        'body': 'var ModelName = Array("ECOSYS M2035dn");var OEMFlag = 0;var SysLoctn = "";var Hostname = "KYO2035buh";',
                        'final_url': 'http://192.168.1.31/DeepSleep.js',
                    },
                },
            )

            metadata = enricher._fetch_kyocera_metadata('http://192.168.1.31', '')

            self.assertEqual('Kyocera', metadata['device_vendor'])
            self.assertEqual('command_center_rx', metadata['device_family'])
            self.assertEqual('ECOSYS M2035dn', metadata['device_model'])
            self.assertEqual('KYO2035buh', metadata['device_hostname'])

    def test_fetch_kyocera_metadata_uses_startwlm_model_with_referer(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            enricher = TargetedFetchStubWebProbeEnricher(
                storage,
                {
                    ('http://192.168.1.170/', 'http://192.168.1.170/'): {
                        'status_code': 200,
                        'headers': {},
                        'body': '<html></html>',
                        'final_url': 'http://192.168.1.170/',
                    },
                    ('http://192.168.1.170/startwlm/Start_Wlm.htm', 'http://192.168.1.170/'): {
                        'status_code': 200,
                        'headers': {},
                        'body': '<html><script src="../js/jssrc/model/startwlm/Start_Wlm.model.htm"></script></html>',
                        'final_url': 'http://192.168.1.170/startwlm/Start_Wlm.htm',
                    },
                    ('http://192.168.1.170/js/jssrc/model/startwlm/Start_Wlm.model.htm?arg1=&arg2=&arg3=&arg4=&arg5=&arg6=&arg8=&arg9=&arg10=0&arg11=', 'http://192.168.1.170/startwlm/Start_Wlm.htm'): {
                        'status_code': 200,
                        'headers': {},
                        'body': (
                            "_pp.f_getPrinterModel = 'ECOSYS M3145dn';"
                            "_pp.f_getHostName = 'KMC4E578';"
                            "_pp.f_getSNMPSysLocation = '';"
                        ),
                        'final_url': 'http://192.168.1.170/js/jssrc/model/startwlm/Start_Wlm.model.htm',
                    },
                },
            )

            metadata = enricher._fetch_kyocera_metadata('http://192.168.1.170', '<html></html>')

            self.assertEqual('ECOSYS M3145dn', metadata['device_model'])
            self.assertEqual('KMC4E578', metadata['device_hostname'])

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

    def test_web_probe_identifies_netsurveillance_camera_family_on_port_80(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.219', {
                'ip': '192.168.1.219',
                'open_ports': [80, 34567],
                'services': ['HTTP', 'XMEye'],
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
                        'title': 'NETSurveillance WEB',
                        'server': 'uc-httpd 1.0.0',
                        'content_type': 'text/html',
                        'location': '',
                        'final_url': 'http://192.168.1.219:80/',
                        'www_authenticate': '',
                        'auth_scheme': '',
                        'redirect_to_login': False,
                        'is_login_page': False,
                    }
                },
                metadata_by_port={
                    80: {
                        'device_vendor': 'XMEye',
                        'device_family': 'netsurveillance_web',
                        'device_ui': 'NETSurveillance WEB',
                    }
                },
            )

            enricher.probe_host('192.168.1.219')

            host = storage.get_host_record('192.168.1.219')
            self.assertEqual('camera', host.type)
            self.assertEqual('XMEye', host.vendor)
            self.assertEqual('', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)
            self.assertEqual('netsurveillance_web', host.web_probes[80]['device_family'])

    def test_web_probe_uses_onvif_device_info_for_camera_model(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.224', {
                'ip': '192.168.1.224',
                'open_ports': [8899, 34567],
                'services': ['ONVIF', 'XMEye'],
                'service_details': {
                    8899: {'name': '', 'product': 'ONVIF', 'version': '', 'extrainfo': '', 'tunnel': ''},
                    34567: {'name': '', 'product': 'XMEye', 'version': '', 'extrainfo': '', 'tunnel': ''},
                },
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = StubWebProbeEnricher(
                storage,
                {
                    8899: {
                        'scheme': 'http',
                        'reachable': True,
                        'status_code': 405,
                        'title': '',
                        'server': 'gSOAP/2.7',
                        'content_type': 'text/xml; charset=utf-8',
                        'location': '',
                        'final_url': 'http://192.168.1.224:8899/',
                        'www_authenticate': '',
                        'auth_scheme': '',
                        'redirect_to_login': False,
                        'is_login_page': False,
                    }
                },
                metadata_by_port={
                    8899: {
                        'device_family': 'onvif_device_info',
                        'device_model': 'IPC_GK7205V200_50H20AI_S38',
                        'device_manufacturer': 'H264',
                        'device_firmware': 'V5.00.R02.K90659A7.10010.140400..ONVIF 16.12',
                        'device_serial': '0f58f1c047f2f85c',
                    }
                },
            )

            enricher.probe_host('192.168.1.224')

            host = storage.get_host_record('192.168.1.224')
            self.assertEqual('camera', host.category)
            self.assertEqual('camera', host.type)
            self.assertEqual('XMEye', host.vendor)
            self.assertEqual('IPC_GK7205V200_50H20AI_S38', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)
            self.assertEqual('onvif_device_info', host.web_probes[8899]['device_family'])
            self.assertEqual('0f58f1c047f2f85c', host.web_probes[8899]['device_serial'])

    def test_web_probe_marks_camera_completed_from_onvif_model_on_port_80(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.156', {
                'ip': '192.168.1.156',
                'open_ports': [23, 80, 554, 5000],
                'services': ['Telnet', 'HTTP', 'RTSP', 'Synology-QNAP'],
                'service_details': {
                    80: {'name': '', 'product': 'HTTP', 'version': '', 'extrainfo': '', 'tunnel': ''},
                    554: {'name': '', 'product': 'RTSP', 'version': '', 'extrainfo': '', 'tunnel': ''},
                    5000: {'name': '', 'product': 'Synology-QNAP', 'version': '', 'extrainfo': '', 'tunnel': ''},
                },
                'scan_status': 'discovered',
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
                        'server': '',
                        'content_type': 'text/html',
                        'location': '',
                        'final_url': 'http://192.168.1.156:80/',
                        'www_authenticate': '',
                        'auth_scheme': '',
                        'redirect_to_login': False,
                        'is_login_page': True,
                    },
                    5000: {
                        'scheme': 'http',
                        'reachable': False,
                        'error': 'connection reset',
                    },
                },
                metadata_by_port={
                    80: {
                        'device_vendor': 'RVi',
                        'device_family': 'onvif_device_info',
                        'device_model': 'RVi-IPC42DNS',
                        'device_firmware': '2.210.Group 00.0.R, build: 2013-10-24(V4.1.1)',
                        'device_serial': 'TZC3LV001D00477',
                        'device_hardware_id': '1.00',
                    }
                },
            )

            enricher.probe_host('192.168.1.156')

            host = storage.get_host_record('192.168.1.156')
            self.assertEqual('camera', host.category)
            self.assertEqual('camera', host.type)
            self.assertEqual('RVi', host.vendor)
            self.assertEqual('RVi-IPC42DNS', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)

    def test_web_probe_marks_dahua_camera_completed_from_rtsp_preauth(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.250', {
                'ip': '192.168.1.250',
                'open_ports': [23, 554],
                'services': ['Telnet', 'RTSP'],
                'service_details': {
                    23: {'name': '', 'product': 'Telnet', 'version': '', 'extrainfo': '', 'tunnel': ''},
                    554: {'name': '', 'product': 'RTSP', 'version': '', 'extrainfo': '', 'tunnel': ''},
                },
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = RtspStubWebProbeEnricher(
                storage,
                {
                    80: {'scheme': 'http', 'reachable': False, 'error': 'connection refused'},
                    443: {'scheme': 'https', 'reachable': False, 'error': 'connection refused'},
                    8899: {'scheme': 'http', 'reachable': False, 'error': 'connection refused'},
                },
                rtsp_probe={
                    'scheme': 'rtsp',
                    'reachable': True,
                    'status_code': 401,
                    'server': 'Dahua Rtsp Server',
                    'www_authenticate': 'Basic realm="device"',
                    'auth_scheme': 'basic',
                    'device_vendor': 'Dahua',
                    'device_family': 'dahua_rtsp',
                },
            )

            enricher.probe_host('192.168.1.250')

            host = storage.get_host_record('192.168.1.250')
            self.assertEqual('camera', host.category)
            self.assertEqual('camera', host.type)
            self.assertEqual('Dahua', host.vendor)
            self.assertEqual('', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)
            self.assertEqual('dahua_rtsp', host.web_probes[554]['device_family'])

    def test_web_probe_marks_legacy_rvi_camera_completed_when_brand_model_present(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.151', {
                'ip': '192.168.1.151',
                'open_ports': [80, 554],
                'services': ['HTTP', 'RTSP'],
                'service_details': {
                    80: {'name': '', 'product': 'HTTP', 'version': '', 'extrainfo': '', 'tunnel': ''},
                    554: {'name': '', 'product': 'RTSP', 'version': '', 'extrainfo': '', 'tunnel': ''},
                },
                'scan_status': 'discovered',
            })
            storage.flush()

            enricher = StubWebProbeEnricher(
                storage,
                {
                    80: {
                        'scheme': 'http',
                        'reachable': True,
                        'status_code': 200,
                        'title': '"+title+"',
                        'server': '',
                        'content_type': 'text/html',
                        'location': '',
                        'final_url': 'http://192.168.1.151:80/',
                        'www_authenticate': '',
                        'auth_scheme': '',
                        'redirect_to_login': False,
                        'is_login_page': False,
                    }
                },
                metadata_by_port={
                    80: {
                        'device_vendor': 'RVi',
                        'device_family': 'legacy_rvi_ocx',
                        'device_model': 'RVi-IPC12',
                        'device_ui': 'RViCamV_H264',
                        'device_firmware': '6.C.2.11896',
                        'device_sensor': 'imx122',
                    }
                },
            )

            enricher.probe_host('192.168.1.151')

            host = storage.get_host_record('192.168.1.151')
            self.assertEqual('camera', host.category)
            self.assertEqual('camera', host.type)
            self.assertEqual('RVi', host.vendor)
            self.assertEqual('RVi-IPC12', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)
            self.assertEqual('legacy_rvi_ocx', host.web_probes[80]['device_family'])

    def test_web_probe_clears_stale_synology_vendor_on_camera_noise(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.152', {
                'ip': '192.168.1.152',
                'open_ports': [23, 554, 5000],
                'services': ['Telnet', 'RTSP', 'Synology-QNAP'],
                'service_details': {
                    23: {'name': '', 'product': 'Telnet', 'version': '', 'extrainfo': '', 'tunnel': ''},
                    554: {'name': '', 'product': 'RTSP', 'version': '', 'extrainfo': '', 'tunnel': ''},
                    5000: {'name': '', 'product': 'Synology-QNAP', 'version': '', 'extrainfo': '', 'tunnel': ''},
                },
                'vendor': 'Synology',
                'category': 'camera',
                'type': 'camera',
                'os_type': 'linux',
                'os': 'IP Camera',
                'scan_status': 'discovered',
            })
            storage.flush()

            enricher = StubWebProbeEnricher(
                storage,
                {
                    5000: {
                        'scheme': 'http',
                        'reachable': False,
                        'error': 'connection reset',
                    }
                },
            )

            enricher.probe_host('192.168.1.152')

            host = storage.get_host_record('192.168.1.152')
            self.assertEqual('camera', host.category)
            self.assertEqual('camera', host.type)
            self.assertEqual('', host.vendor)
            self.assertEqual('discovered', host.scan_status)

    def test_web_probe_marks_nanokvm_completed_from_title(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.37', {
                'ip': '192.168.1.37',
                'open_ports': [80],
                'services': ['HTTP'],
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
                        'title': 'NanoKVM',
                        'server': '',
                        'content_type': 'text/html',
                        'location': '',
                        'final_url': 'http://192.168.1.37:80/',
                        'www_authenticate': '',
                        'auth_scheme': '',
                        'redirect_to_login': False,
                        'is_login_page': False,
                    }
                },
                metadata_by_port={
                    80: {
                        'device_vendor': 'NanoKVM',
                        'device_family': 'nanokvm',
                        'device_model': 'NanoKVM',
                    }
                },
            )

            enricher.probe_host('192.168.1.37')

            host = storage.get_host_record('192.168.1.37')
            self.assertEqual('ipkvm', host.type)
            self.assertEqual('NanoKVM', host.vendor)
            self.assertEqual('NanoKVM', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)

    def test_web_probe_marks_canon_imagerunner_completed_from_title(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.155', {
                'ip': '192.168.1.155',
                'open_ports': [80],
                'services': ['HTTP'],
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = StubWebProbeEnricher(storage, {
                80: {
                    'scheme': 'http',
                    'reachable': True,
                    'status_code': 200,
                    'title': 'Удаленный ИП: Вход в системуimageRUNNER1133 series:imageRUNNER1133 series',
                    'server': '',
                    'content_type': 'text/html',
                    'location': '',
                    'final_url': 'http://192.168.1.155:80/',
                    'www_authenticate': '',
                    'auth_scheme': '',
                    'redirect_to_login': False,
                    'is_login_page': True,
                }
            })

            enricher.probe_host('192.168.1.155')

            host = storage.get_host_record('192.168.1.155')
            self.assertEqual('printer', host.type)
            self.assertEqual('Canon', host.vendor)
            self.assertEqual('imageRUNNER1133 series', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)

    def test_web_probe_marks_hp_printer_completed_from_title(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.76', {
                'ip': '192.168.1.76',
                'open_ports': [8080, 9100],
                'services': ['HTTP-Alt', 'Printer'],
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = StubWebProbeEnricher(storage, {
                8080: {
                    'scheme': 'http',
                    'reachable': True,
                    'status_code': 200,
                    'title': 'HP LaserJet Professional P1606dn 192.168.1.76',
                    'server': 'Mrvl-R1_0',
                    'content_type': 'text/html',
                    'location': '',
                    'final_url': 'http://192.168.1.76:8080/',
                    'www_authenticate': '',
                    'auth_scheme': '',
                    'redirect_to_login': False,
                    'is_login_page': False,
                }
            })

            enricher.probe_host('192.168.1.76')

            host = storage.get_host_record('192.168.1.76')
            self.assertEqual('printer', host.type)
            self.assertEqual('HP', host.vendor)
            self.assertEqual('LaserJet Professional P1606dn', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)

    def test_web_probe_marks_hp_printer_completed_from_partial_response_body(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.85', {
                'ip': '192.168.1.85',
                'open_ports': [8080, 9100],
                'services': ['HTTP-Alt', 'Printer'],
                'scan_status': 'scanned',
            })
            storage.flush()

            partial_body = (
                '<html><head><title>HP LaserJet 400 M401dn 192.168.1.85</title></head>'
                '<body></body></html>'
            ).encode('utf-8')

            class FakeResponse:
                def __init__(self):
                    self.status = 200
                    self.headers = {
                        'Server': 'Virata-EmWeb/R6_2_1',
                        'Content-Type': 'text/html',
                    }

                def geturl(self):
                    return 'http://192.168.1.85:8080/'

                def read(self, _limit):
                    raise http.client.IncompleteRead(partial_body, len(partial_body) + 500)

                def close(self):
                    return None

            class FakeOpener:
                def open(self, request, timeout):
                    return FakeResponse()

            enricher = WebProbeEnricher(storage=storage, concurrency=1, timeout=1)
            enricher._http_opener = FakeOpener()

            with mock.patch('src.web_probe._fetch_tls_info', return_value={}):
                enricher.probe_host('192.168.1.85')

            host = storage.get_host_record('192.168.1.85')
            self.assertEqual('printer', host.type)
            self.assertEqual('HP', host.vendor)
            self.assertEqual('LaserJet 400 M401dn', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)

    def test_web_probe_marks_brother_printer_completed_from_title(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.181', {
                'ip': '192.168.1.181',
                'open_ports': [80],
                'services': ['HTTP'],
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
                        'title': 'Brother DCP-L2540DN series',
                        'server': 'debut/1.30',
                        'content_type': 'text/html',
                        'location': '',
                        'final_url': 'http://192.168.1.181:80/',
                        'www_authenticate': '',
                        'auth_scheme': '',
                        'redirect_to_login': False,
                        'is_login_page': True,
                    }
                },
                metadata_by_port={
                    80: {
                        'device_vendor': 'Brother',
                        'device_family': 'brother_ews',
                        'device_model': 'DCP-L2540DN series',
                    }
                },
            )

            enricher.probe_host('192.168.1.181')

            host = storage.get_host_record('192.168.1.181')
            self.assertEqual('printer', host.type)
            self.assertEqual('Brother', host.vendor)
            self.assertEqual('DCP-L2540DN series', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)

    def test_web_probe_marks_network_appliance_completed_when_vendor_model_known(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.9', {
                'ip': '192.168.1.9',
                'open_ports': [4081],
                'services': ['Kerio-Admin'],
                'category': 'network',
                'type': 'network',
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = StubWebProbeEnricher(storage, {
                4081: {
                    'scheme': 'https',
                    'reachable': True,
                    'status_code': 302,
                    'title': '',
                    'server': 'Kerio Control Embedded Web Server',
                    'content_type': 'text/html',
                    'location': '/login/',
                    'final_url': 'https://192.168.1.9:4081/',
                    'www_authenticate': '',
                    'auth_scheme': '',
                    'redirect_to_login': True,
                    'is_login_page': True,
                }
            })

            enricher.probe_host('192.168.1.9')

            host = storage.get_host_record('192.168.1.9')
            self.assertEqual('network', host.type)
            self.assertEqual('Kerio', host.vendor)
            self.assertEqual('Kerio Control', host.model)
            self.assertEqual(STATUS_WEB_COMPLETED, host.scan_status)

    def test_web_probe_downgrades_empty_scanned_host_without_ports_to_discovered(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Storage(output_dir=tmpdir)
            storage.update_host('192.168.1.252', {
                'ip': '192.168.1.252',
                'open_ports': [],
                'services': [],
                'scan_status': 'scanned',
            })
            storage.flush()

            enricher = StubWebProbeEnricher(storage, {})
            enricher.probe_host('192.168.1.252')

            host = storage.get_host_record('192.168.1.252')
            self.assertEqual(STATUS_DISCOVERED, host.scan_status)


if __name__ == '__main__':
    unittest.main()
