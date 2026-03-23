import html
import http.client
import http.cookiejar
import logging
import re
import socket
import ssl
import tempfile
import os
import urllib.error
import urllib.parse
import urllib.request
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.classification import classify_host
from src.constants import (
    STATUS_COMPLETED,
    STATUS_DISCOVERED,
    STATUS_SCANNED,
    STATUS_VIRTUALIZATION_COMPLETED,
    STATUS_WEB_COMPLETED,
)
from src.vendor_db import determine_vendor_model, extract_model_from_web_text


logger = logging.getLogger(__name__)

WEB_PORT_SCHEMES = {
    80: 'http',
    443: 'https',
    8080: 'http',
    8443: 'https',
    8006: 'https',
    4081: 'https',
    5000: 'http',
    5001: 'https',
    9090: 'http',
    3000: 'http',
    4040: 'http',
    10000: 'https',
    8291: 'http',
    8728: 'http',
    8899: 'http',
}

TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)
LOGIN_RE = re.compile(
    r'(login|log in|sign in|password|username|user name|authentication|auth)',
    re.IGNORECASE,
)
AUTH_SCHEME_RE = re.compile(r'^\s*([A-Za-z]+)')
RTSP_STATUS_RE = re.compile(r'^RTSP/\d+\.\d+\s+(\d+)', re.IGNORECASE)
KYOCERA_ASSIGNMENT_RE = re.compile(r"_pp\.(f_getPrinterModel|f_getHostName|f_getSNMPSysLocation)\s*=\s*'([^']*)';")
KYOCERA_DEEPSLEEP_MODEL_RE = re.compile(r'var\s+ModelName\s*=\s*Array\("([^"]+)"\)', re.IGNORECASE)
KYOCERA_DEEPSLEEP_HOST_RE = re.compile(r'var\s+Hostname\s*=\s*"([^"]*)"', re.IGNORECASE)
KYOCERA_DEEPSLEEP_LOCATION_RE = re.compile(r'var\s+SysLoctn\s*=\s*"([^"]*)"', re.IGNORECASE)
XML_TAG_RE_TEMPLATE = r'<(?:\w+:)?{tag}>(.*?)</(?:\w+:)?{tag}>'
GENERIC_CAMERA_MANUFACTURERS = {'', 'h264', 'ipcamera', 'ipc', 'onvif'}
RVI_VAR_RE = re.compile(r'var\s+(fw_version|sensor|sensor_type|activex_id)\s*=\s*"([^"]*)";', re.IGNORECASE)
RVI_BRAND_VAR_RE = re.compile(r'var\s+(brand_prodnbr|brand_prodname|brand_prodtype)\s*=\s*"([^"]*)";', re.IGNORECASE)
XIAOMI_HARDWARE_RE = re.compile(r"hardware\s*=\s*'([^']+)'", re.IGNORECASE)
CANON_DEV_RE = re.compile(r'DEV=([A-Z0-9-]+)', re.IGNORECASE)
HP_TITLE_RE = re.compile(r'\bHP\s+(LaserJet(?:\s+Professional)?(?:\s+(?!\d{1,3}(?:\.\d{1,3}){3}\b)[A-Z0-9-]+){1,3})\b', re.IGNORECASE)
BROTHER_TITLE_RE = re.compile(r'\bBrother\s+((?:DCP|MFC|HL|ADS|PT|QL)-[A-Z0-9]+(?:\s+series)?)\b', re.IGNORECASE)
TP_LINK_MODEL_RE = re.compile(r'\b(Archer\s+[A-Z0-9-]+|TL-[A-Z0-9-]+|Deco\s+[A-Z0-9-]+)\b', re.IGNORECASE)
PJL_QUOTED_MODEL_RE = re.compile(r'"([^"\r\n]+)"')
SNR_SWITCH_MODEL_RE = re.compile(r'\b(SNR-[A-Z0-9-]+)\b', re.IGNORECASE)


def _https_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _normalize_header(value):
    if not value:
        return ''
    return str(value).strip()


def _extract_title(body):
    if not body:
        return ''
    match = TITLE_RE.search(body)
    if not match:
        return ''
    title = html.unescape(match.group(1))
    title = re.sub(r'\s+', ' ', title).strip()
    return title[:200]


def _is_login_page(title, body, location, auth_scheme):
    if auth_scheme:
        return True
    combined = ' '.join(part for part in (title, body[:2000], location) if part)
    return bool(LOGIN_RE.search(combined))


def _extract_auth_scheme(www_authenticate):
    if not www_authenticate:
        return ''
    match = AUTH_SCHEME_RE.match(www_authenticate)
    if not match:
        return ''
    return match.group(1).lower()


def _extract_xml_tag(body, tag):
    if not body:
        return ''
    match = re.search(XML_TAG_RE_TEMPLATE.format(tag=re.escape(tag)), body, re.IGNORECASE | re.DOTALL)
    if not match:
        return ''
    return html.unescape(match.group(1)).strip()


def _read_response_body(response, limit):
    try:
        body = response.read(limit)
    except http.client.IncompleteRead as exc:
        body = exc.partial
    return body.decode('utf-8', errors='ignore')


def _read_error_body(exc, limit):
    try:
        body = exc.read(limit)
    except http.client.IncompleteRead as read_exc:
        body = read_exc.partial
    except Exception:
        body = b''
    return body.decode('utf-8', errors='ignore')


def _has_strong_nas_web_signal(probes):
    signals = []
    for probe in probes:
        if not isinstance(probe, dict):
            continue
        signals.extend([
            str(probe.get('title', '') or ''),
            str(probe.get('server', '') or ''),
            str(probe.get('location', '') or ''),
            str(probe.get('content_type', '') or ''),
        ])
    text = ' '.join(signals).lower()
    return any(
        signal in text
        for signal in (
            'diskstation',
            'disk station',
            'synology dsm',
            'web station',
            'qnap',
            'qts',
            'qumagie',
        )
    )


def _parse_tls_name(entries):
    values = []
    if not isinstance(entries, (list, tuple)):
        return ''
    for item in entries:
        if not isinstance(item, tuple):
            continue
        for key, value in item:
            if key.lower() == 'commonname' and value:
                values.append(str(value).strip())
    return ', '.join(values)


def _parse_tls_san(entries):
    values = []
    if not isinstance(entries, (list, tuple)):
        return values
    for item in entries:
        if not isinstance(item, tuple) or len(item) != 2:
            continue
        kind, value = item
        if str(kind).lower() != 'dns':
            continue
        value = str(value).strip()
        if value and value not in values:
            values.append(value)
    return values


def _fetch_tls_info(ip, port, timeout):
    try:
        pem_cert = ssl.get_server_certificate((ip, port), timeout=timeout)
    except Exception as exc:
        logger.debug("TLS probe failed for %s:%s: %s", ip, port, exc)
        return {}

    try:
        with tempfile.NamedTemporaryFile('w+', encoding='utf-8', delete=False) as tmp:
            tmp.write(pem_cert)
            tmp.flush()
            tmp_path = tmp.name
        cert = ssl._ssl._test_decode_cert(tmp_path)
    except Exception as exc:
        logger.debug("TLS decode failed for %s:%s: %s", ip, port, exc)
        return {}
    finally:
        try:
            if 'tmp_path' in locals() and tmp_path:
                os.unlink(tmp_path)
        except OSError:
            pass

    if not isinstance(cert, dict):
        return {}

    return {
        'tls_subject': _parse_tls_name(cert.get('subject')),
        'tls_issuer': _parse_tls_name(cert.get('issuer')),
        'tls_san': _parse_tls_san(cert.get('subjectAltName')),
        'tls_not_before': _normalize_header(cert.get('notBefore')),
        'tls_not_after': _normalize_header(cert.get('notAfter')),
    }


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class WebProbeEnricher:
    def __init__(self, storage, concurrency=10, timeout=4):
        self.storage = storage
        self.concurrency = concurrency
        self.timeout = timeout
        self._cookiejar = http.cookiejar.CookieJar()
        self._http_opener = urllib.request.build_opener(
            _NoRedirectHandler(),
            urllib.request.HTTPCookieProcessor(self._cookiejar),
        )
        self._https_opener = urllib.request.build_opener(
            _NoRedirectHandler(),
            urllib.request.HTTPCookieProcessor(self._cookiejar),
            urllib.request.HTTPSHandler(context=_https_context()),
        )

    def _target_ports(self, host):
        ports = list(dict.fromkeys(port for port in host.open_ports if port in WEB_PORT_SCHEMES))
        open_ports = set(host.open_ports or [])
        host_type = str(getattr(host, 'type', '') or '').lower()
        category = str(getattr(host, 'category', '') or '').lower()

        if host_type == 'printer' or category == 'printer' or 9100 in open_ports:
            for port in (80, 443, 8080):
                if port not in ports and port in WEB_PORT_SCHEMES:
                    ports.append(port)

        if host_type == 'camera' or category == 'camera' or 34567 in open_ports or 554 in open_ports:
            for port in (80, 443, 8899):
                if port not in ports and port in WEB_PORT_SCHEMES:
                    ports.append(port)

        return ports

    def _build_url(self, ip, port):
        return f"{WEB_PORT_SCHEMES[port]}://{ip}:{port}/"

    def _is_camera_like_host(self, host):
        open_ports = set((host.open_ports if host else []) or [])
        host_type = str(getattr(host, 'type', '') or '').lower()
        category = str(getattr(host, 'category', '') or '').lower()
        services = [str(service).lower() for service in ((host.services if host else []) or [])]
        return (
            host_type == 'camera'
            or category == 'camera'
            or 554 in open_ports
            or 34567 in open_ports
            or any(service in ('onvif', 'xmeye', 'rtsp') for service in services)
        )

    def _probe_rtsp_port(self, ip, port=554):
        request = (
            f"OPTIONS rtsp://{ip}/ RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"User-Agent: net-conf-gen/1.0\r\n\r\n"
        ).encode('ascii')
        raw = b''
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                sock.sendall(request)
                raw = sock.recv(4096)
        except Exception as exc:
            logger.debug("RTSP probe failed for %s:%s: %s", ip, port, exc)
            return {
                'port': port,
                'scheme': 'rtsp',
                'reachable': False,
                'error': str(exc),
            }

        text = raw.decode('utf-8', errors='ignore')
        lines = [line.strip() for line in text.replace('\r', '').split('\n') if line.strip()]
        status_code = 0
        headers = {}
        if lines:
            match = RTSP_STATUS_RE.match(lines[0])
            if match:
                status_code = int(match.group(1))
            for line in lines[1:]:
                if ':' not in line:
                    continue
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()

        probe = {
            'port': port,
            'scheme': 'rtsp',
            'reachable': True,
            'status_code': status_code,
            'server': headers.get('server', ''),
            'www_authenticate': headers.get('www-authenticate', ''),
            'auth_scheme': _extract_auth_scheme(headers.get('www-authenticate', '')),
            'rtsp_response': text[:1000],
        }
        header_text = ' '.join([
            probe.get('server', ''),
            probe.get('www_authenticate', ''),
        ]).lower()
        if 'dahua' in header_text:
            probe['device_vendor'] = 'Dahua'
            probe['device_family'] = 'dahua_rtsp'
        return probe

    def _fetch_pjl_metadata(self, ip, vendor_hint=''):
        commands = [
            b'\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X',
            b'\x1b%-12345X@PJL INFO PRODINFO\r\n\x1b%-12345X',
        ]
        text = ''
        for command in commands:
            try:
                with socket.create_connection((ip, 9100), timeout=self.timeout) as sock:
                    sock.settimeout(self.timeout)
                    sock.sendall(command)
                    chunks = []
                    while True:
                        try:
                            data = sock.recv(4096)
                        except socket.timeout:
                            break
                        if not data:
                            break
                        chunks.append(data)
            except Exception as exc:
                logger.debug("PJL probe failed for %s: %s", ip, exc)
                continue

            text = b''.join(chunks).decode('utf-8', errors='ignore')
            if '"' in text or 'INFO ID' in text or 'PRODINFO' in text:
                break

        if not text:
            return {}

        model = ''
        match = PJL_QUOTED_MODEL_RE.search(text)
        if match:
            model = match.group(1).strip()

        if not model:
            return {}

        vendor = vendor_hint.strip()
        model_lower = model.lower()
        if not vendor:
            if 'ecosys' in model_lower or 'taskalfa' in model_lower or 'kyocera' in model_lower:
                vendor = 'Kyocera'
            elif 'laserjet' in model_lower or model_lower.startswith('hp '):
                vendor = 'HP'
            elif 'brother' in model_lower:
                vendor = 'Brother'
            elif 'imagerunner' in model_lower or re.match(r'^(mf\d|lbp\d)', model_lower):
                vendor = 'Canon'
            elif 'pantum' in model_lower:
                vendor = 'Pantum'
            elif 'xerox' in model_lower or 'phaser' in model_lower:
                vendor = 'Xerox'

        metadata = {
            'device_model': model,
            'device_family': 'pjl_info_id',
        }
        if vendor:
            metadata['device_vendor'] = vendor
        return metadata

    def _probe_port(self, ip, port):
        url = self._build_url(ip, port)
        request = urllib.request.Request(url, headers={'User-Agent': 'net-conf-gen/1.0'})
        response = None
        body = ''
        status_code = 0
        headers = None
        final_url = url

        try:
            opener = self._https_opener if WEB_PORT_SCHEMES[port] == 'https' else self._http_opener
            response = opener.open(request, timeout=self.timeout)
            status_code = getattr(response, 'status', 200)
            headers = response.headers
            final_url = response.geturl() or url
            body = _read_response_body(response, 16384)
        except urllib.error.HTTPError as exc:
            status_code = exc.code
            headers = exc.headers
            final_url = exc.geturl() or url
            body = _read_error_body(exc, 16384)
        except Exception as exc:
            logger.debug("HTTP probe failed for %s:%s: %s", ip, port, exc)
            return {
                'port': port,
                'scheme': WEB_PORT_SCHEMES[port],
                'reachable': False,
                'error': str(exc),
            }
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass

        server = _normalize_header(headers.get('Server') if headers else '')
        location = _normalize_header(headers.get('Location') if headers else '')
        www_authenticate = _normalize_header(headers.get('WWW-Authenticate') if headers else '')
        auth_scheme = _extract_auth_scheme(www_authenticate)
        title = _extract_title(body)
        content_type = _normalize_header(headers.get('Content-Type') if headers else '')
        probe = {
            'port': port,
            'scheme': WEB_PORT_SCHEMES[port],
            'reachable': True,
            'status_code': status_code,
            'server': server,
            'title': title,
            'content_type': content_type,
            'location': location,
            'final_url': final_url,
            'www_authenticate': www_authenticate,
            'auth_scheme': auth_scheme,
            'redirect_to_login': 'login' in location.lower() or 'signin' in location.lower(),
            'is_login_page': _is_login_page(title, body, location, auth_scheme),
        }
        if WEB_PORT_SCHEMES[port] == 'https':
            probe.update(_fetch_tls_info(ip, port, self.timeout))
        return probe

    def _open_url(self, url):
        return self._open_url_with_headers(url)

    def _open_url_with_headers(self, url, headers=None):
        request_headers = {'User-Agent': 'net-conf-gen/1.0'}
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(url, headers=request_headers)
        response = None
        try:
            opener = self._https_opener if url.startswith('https://') else self._http_opener
            response = opener.open(request, timeout=self.timeout)
            body = _read_response_body(response, 20000)
            return {
                'status_code': getattr(response, 'status', 200),
                'headers': response.headers,
                'body': body,
                'final_url': response.geturl() or url,
            }
        except urllib.error.HTTPError as exc:
            body = _read_error_body(exc, 20000)
            return {
                'status_code': exc.code,
                'headers': exc.headers,
                'body': body,
                'final_url': exc.geturl() or url,
            }
        except Exception as exc:
            logger.debug("Targeted web fetch failed for %s: %s", url, exc)
            return None
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass

    def _post_json(self, url, payload):
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'User-Agent': 'net-conf-gen/1.0',
                'Content-Type': 'text/plain',
            },
            method='POST',
        )
        response = None
        try:
            opener = self._https_opener if url.startswith('https://') else self._http_opener
            response = opener.open(request, timeout=self.timeout)
            body = _read_response_body(response, 20000)
            return {
                'status_code': getattr(response, 'status', 200),
                'headers': response.headers,
                'body': body,
                'final_url': response.geturl() or url,
            }
        except urllib.error.HTTPError as exc:
            body = _read_error_body(exc, 20000)
            return {
                'status_code': exc.code,
                'headers': exc.headers,
                'body': body,
                'final_url': exc.geturl() or url,
            }
        except Exception as exc:
            logger.debug("Targeted web POST failed for %s: %s", url, exc)
            return None
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass

    def _post_plain_text(self, url, body, headers=None):
        request_headers = {
            'User-Agent': 'net-conf-gen/1.0',
            'Content-Type': 'text/plain;charset=UTF-8',
        }
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(
            url,
            data=body.encode('utf-8'),
            headers=request_headers,
            method='POST',
        )
        response = None
        try:
            opener = self._https_opener if url.startswith('https://') else self._http_opener
            response = opener.open(request, timeout=self.timeout)
            return {
                'status_code': getattr(response, 'status', 200),
                'headers': response.headers,
                'body': _read_response_body(response, 20000),
                'final_url': response.geturl() or url,
            }
        except urllib.error.HTTPError as exc:
            body = _read_error_body(exc, 20000)
            return {
                'status_code': exc.code,
                'headers': exc.headers,
                'body': body,
                'final_url': exc.geturl() or url,
            }
        except Exception as exc:
            logger.debug("Targeted web text POST failed for %s: %s", url, exc)
            return None
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass

    def _post_soap(self, url, body):
        request = urllib.request.Request(
            url,
            data=body.encode('utf-8'),
            headers={
                'User-Agent': 'net-conf-gen/1.0',
                'Content-Type': 'application/soap+xml; charset=utf-8',
            },
            method='POST',
        )
        response = None
        try:
            opener = self._https_opener if url.startswith('https://') else self._http_opener
            response = opener.open(request, timeout=self.timeout)
            return {
                'status_code': getattr(response, 'status', 200),
                'headers': response.headers,
                'body': _read_response_body(response, 20000),
                'final_url': response.geturl() or url,
            }
        except urllib.error.HTTPError as exc:
            body = _read_error_body(exc, 20000)
            return {
                'status_code': exc.code,
                'headers': exc.headers,
                'body': body,
                'final_url': exc.geturl() or url,
            }
        except Exception as exc:
            logger.debug("Targeted web SOAP failed for %s: %s", url, exc)
            return None
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass

    def _fetch_onvif_device_info(self, base_url):
        soap_body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
            '<s:Body><tds:GetDeviceInformation/></s:Body>'
            '</s:Envelope>'
        )
        for path in ('/', '/onvif/device_service'):
            response = self._post_soap(f"{base_url}{path}", soap_body)
            if not response:
                continue
            body = response.get('body', '')
            model = _extract_xml_tag(body, 'Model')
            if not model:
                continue
            manufacturer = _extract_xml_tag(body, 'Manufacturer')
            metadata = {
                'device_family': 'onvif_device_info',
                'device_model': model,
            }
            firmware = _extract_xml_tag(body, 'FirmwareVersion')
            serial = _extract_xml_tag(body, 'SerialNumber')
            hardware = _extract_xml_tag(body, 'HardwareId')
            if firmware:
                metadata['device_firmware'] = firmware
            if serial:
                metadata['device_serial'] = serial
            if hardware:
                metadata['device_hardware_id'] = hardware
            if manufacturer and manufacturer.strip().lower() not in GENERIC_CAMERA_MANUFACTURERS:
                metadata['device_vendor'] = manufacturer.strip()
            else:
                metadata['device_manufacturer'] = manufacturer.strip()
            return metadata
        return {}

    def _fetch_rvi_legacy_metadata(self, base_url):
        response = self._open_url(f"{base_url}/asp/view.asp")
        if not response:
            return {}
        body = response.get('body', '')
        values = {}
        for key, value in RVI_VAR_RE.findall(body):
            values[key.lower()] = value.strip()
        brand_values = {}
        for key, value in RVI_BRAND_VAR_RE.findall(body):
            brand_values[key.lower()] = value.strip()

        activex_id = values.get('activex_id', '')
        fw_version = values.get('fw_version', '')
        sensor = values.get('sensor', '')
        sensor_type = values.get('sensor_type', '')
        body_lower = body.lower()
        if 'rvicamv_' not in activex_id.lower() and 'rvi' not in body_lower:
            return {}

        metadata = {
            'device_vendor': 'RVi',
            'device_family': 'legacy_rvi_ocx',
        }
        if fw_version:
            metadata['device_firmware'] = fw_version
        if sensor:
            metadata['device_sensor'] = sensor
        if sensor_type:
            metadata['device_sensor_type'] = sensor_type
        if activex_id:
            metadata['device_ui'] = activex_id
        if brand_values.get('brand_prodnbr'):
            metadata['device_model'] = brand_values['brand_prodnbr']
        elif brand_values.get('brand_prodname'):
            metadata['device_model'] = brand_values['brand_prodname']
        if brand_values.get('brand_prodtype'):
            metadata['device_product_type'] = brand_values['brand_prodtype']
        return metadata

    def _fetch_xiaomi_router_metadata(self, base_url, root_body):
        response = self._open_url(f"{base_url}/cgi-bin/luci/web")
        body = (response or {}).get('body', '') or root_body
        if '小米路由器' not in body and 'miwifi' not in body.lower() and 'xiaomi' not in body.lower():
            return {}

        metadata = {
            'device_vendor': 'Xiaomi',
            'device_family': 'miwifi_router',
            'device_ui': 'MiWiFi',
            'device_model': 'Mi Router',
        }
        hardware = XIAOMI_HARDWARE_RE.search(body)
        if hardware:
            metadata['device_model'] = hardware.group(1).strip().upper()
        return metadata

    def _fetch_epson_metadata(self, base_url, root_body):
        response = self._open_url(f"{base_url}/PRESENTATION/HTML/TOP/INDEX.HTML")
        body = (response or {}).get('body', '') or root_body
        title = _extract_title(body)
        if 'epson' not in body.lower() and 'epson' not in title.lower():
            return {}

        metadata = {
            'device_vendor': 'Epson',
            'device_family': 'epson_web_config',
        }
        if title:
            metadata['device_model'] = title
        return metadata

    def _fetch_brother_metadata(self, base_url, root_body):
        response = self._open_url(f"{base_url}/general/status.html")
        body = (response or {}).get('body', '') or root_body
        title = _extract_title(body)
        match = BROTHER_TITLE_RE.search(title or body)
        if not match:
            return {}
        return {
            'device_vendor': 'Brother',
            'device_family': 'brother_ews',
            'device_model': match.group(1).strip(),
        }

    def _fetch_hp_metadata(self, base_url, root_body):
        body = root_body
        if not body:
            response = self._open_url(f"{base_url}/SSI/index.htm")
            body = (response or {}).get('body', '')
        match = HP_TITLE_RE.search(body)
        if not match:
            return {}
        return {
            'device_vendor': 'HP',
            'device_family': 'hp_embedded_web_server',
            'device_model': match.group(1).strip(),
        }

    def _fetch_tplink_metadata(self, base_url, root_body):
        body_lower = (root_body or '').lower()
        if (
            'tpencrypt.new.js' not in body_lower
            and '$.su.language' not in body_lower
            and 'js/su/language.js' not in body_lower
        ):
            return {}

        metadata = {
            'device_vendor': 'TP-Link',
            'device_family': 'tplink_smart_ui',
        }
        title_model = TP_LINK_MODEL_RE.search(root_body or '')
        if title_model:
            metadata['device_model'] = title_model.group(1).strip()

        response = self._post_plain_text(
            f"{base_url}/?code=2&asyn=1",
            '0|1,0,0',
            headers={'Referer': f"{base_url}/"},
        )
        response_body = (response or {}).get('body', '')
        if not response_body:
            return metadata if metadata.get('device_model') else {}

        fields = {}
        for line in response_body.splitlines():
            line = line.strip()
            if not line or re.fullmatch(r'\d{5}', line):
                continue
            if ' ' not in line:
                continue
            key, value = line.split(' ', 1)
            fields[key] = urllib.parse.unquote(value.strip())

        manufacturer = str(fields.get('facturer', '') or '').strip()
        if manufacturer:
            metadata['device_vendor'] = manufacturer
        model = str(fields.get('modelName', '') or '').strip()
        if model:
            metadata['device_model'] = model
        hardware = str(fields.get('hardVer', '') or '').strip()
        software = str(fields.get('softVer', '') or '').strip()
        special_id = str(fields.get('specialId', '') or '').strip()
        if hardware:
            metadata['device_hardware'] = hardware
        if software:
            metadata['device_firmware'] = software
        if special_id:
            metadata['device_special_id'] = special_id
        return metadata if metadata.get('device_model') else {}

    def _fetch_snr_switch_metadata(self, base_url, root_body, probe=None):
        body = root_body or ''
        location = str((probe or {}).get('location', '') or '')
        if location and not SNR_SWITCH_MODEL_RE.search(body):
            parsed = urllib.parse.urlparse(location)
            if parsed.path:
                response = self._open_url(f"{base_url}{parsed.path}")
                location_body = (response or {}).get('body', '')
                if location_body:
                    body = location_body
        body_lower = body.lower()
        if 'switch web management' not in body_lower and 'goahead-webs' not in body_lower:
            return {}

        match = SNR_SWITCH_MODEL_RE.search(body)
        if not match:
            return {}

        metadata = {
            'device_vendor': 'NAG',
            'device_family': 'snr_switch_web',
            'device_model': match.group(1).strip(),
        }
        if 'nag llc' in body_lower or 'shop.nag.ru' in body_lower or 'nag.ru' in body_lower:
            metadata['device_vendor'] = 'NAG'
        return metadata

    def _fetch_canon_metadata(self, base_url, root_body):
        bodies = [root_body]
        for path in ('/index.html', '/login.html', '/t_noacc.html'):
            response = self._open_url(f"{base_url}{path}")
            if response:
                bodies.append(response.get('body', ''))
        model_js = self._open_url(f"{base_url}/JS_MDL/model.js")
        if model_js:
            bodies.append(model_js.get('body', ''))

        best_metadata = {}
        for body in bodies:
            title = _extract_title(body)
            title_lower = title.lower()
            if (
                'canon' not in body.lower()
                and 'imagerunner' not in title_lower
                and 'mf' not in title_lower
                and 'lbp' not in title_lower
                and 'dev=' not in body.lower()
            ):
                continue

            metadata = best_metadata or {
                'device_vendor': 'Canon',
                'device_family': 'canon_remote_ui',
            }
            title_model = extract_model_from_web_text('Canon', {'title': title})
            if title_model:
                metadata['device_model'] = title_model
            dev_match = CANON_DEV_RE.search(body)
            if dev_match:
                metadata['device_model'] = dev_match.group(1).strip()
            best_metadata = metadata
            if best_metadata.get('device_model'):
                break
        return best_metadata

    def _fetch_kyocera_metadata(self, base_url, root_body):
        metadata = {
            'device_vendor': 'Kyocera',
            'device_family': 'command_center_rx',
        }

        def apply_assignment_values(body):
            values = {}
            for key, value in KYOCERA_ASSIGNMENT_RE.findall(body or ''):
                values[key] = value.strip()
            if values.get('f_getPrinterModel'):
                metadata['device_model'] = values['f_getPrinterModel']
            if values.get('f_getHostName'):
                metadata['device_hostname'] = values['f_getHostName']
            if values.get('f_getSNMPSysLocation'):
                metadata['device_location'] = values['f_getSNMPSysLocation']

        def apply_deepsleep_values(body):
            if not body:
                return
            match = KYOCERA_DEEPSLEEP_MODEL_RE.search(body)
            if match:
                metadata['device_model'] = match.group(1).strip()
            match = KYOCERA_DEEPSLEEP_HOST_RE.search(body)
            if match and match.group(1).strip():
                metadata['device_hostname'] = match.group(1).strip()
            match = KYOCERA_DEEPSLEEP_LOCATION_RE.search(body)
            if match and match.group(1).strip():
                metadata['device_location'] = match.group(1).strip()

        apply_assignment_values(root_body)
        self._open_url_with_headers(f"{base_url}/", headers={'Referer': f"{base_url}/"})
        self._open_url_with_headers(f"{base_url}/startwlm/Start_Wlm.htm", headers={'Referer': f"{base_url}/"})
        model_url = (
            f"{base_url}/js/jssrc/model/startwlm/Start_Wlm.model.htm"
            "?arg1=&arg2=&arg3=&arg4=&arg5=&arg6=&arg8=&arg9=&arg10=0&arg11="
        )
        model_response = self._open_url_with_headers(
            model_url,
            headers={'Referer': f"{base_url}/startwlm/Start_Wlm.htm"},
        )
        apply_assignment_values((model_response or {}).get('body', ''))

        if metadata.get('device_model'):
            return metadata

        for path in (
            '/DeepSleep.js',
            '/startwlm/Hme_PnlUsg.htm',
        ):
            response = self._open_url_with_headers(
                f"{base_url}{path}",
                headers={'Referer': f"{base_url}/startwlm/Start_Wlm.htm"},
            )
            body = (response or {}).get('body', '')
            apply_deepsleep_values(body)
            apply_assignment_values(body)
            if metadata.get('device_model'):
                break
        return metadata

    def _fetch_targeted_probe_metadata(self, ip, probe):
        if not probe.get('reachable'):
            return {}

        host = self.storage.get_host_record(ip)
        ports = set((host.open_ports if host else []) or [])
        services = [str(service).lower() for service in ((host.services if host else []) or [])]
        base_url = f"{probe.get('scheme', 'http')}://{ip}:{probe.get('port')}"
        root = self._open_url(f"{base_url}/")
        root_body = (root or {}).get('body', '')
        root_text = ' '.join([
            root_body[:4000],
            str(probe.get('server', '')),
            str(probe.get('title', '')),
        ]).lower()

        hp_metadata = self._fetch_hp_metadata(base_url, root_body)
        if hp_metadata:
            return hp_metadata

        tplink_metadata = self._fetch_tplink_metadata(base_url, root_body)
        if tplink_metadata:
            return tplink_metadata

        snr_switch_metadata = self._fetch_snr_switch_metadata(base_url, root_body, probe)
        if snr_switch_metadata:
            return snr_switch_metadata

        if 'nanokvm' in root_text:
            return {
                'device_vendor': 'NanoKVM',
                'device_family': 'nanokvm',
                'device_model': 'NanoKVM',
            }

        if 'xiaomi' in root_text or 'miwifi' in root_text or '小米路由器' in root_text:
            xiaomi_metadata = self._fetch_xiaomi_router_metadata(base_url, root_body)
            if xiaomi_metadata:
                return xiaomi_metadata

        if 'epson' in root_text:
            epson_metadata = self._fetch_epson_metadata(base_url, root_body)
            if epson_metadata:
                return epson_metadata

        brother_metadata = self._fetch_brother_metadata(base_url, root_body)
        if brother_metadata:
            return brother_metadata

        canon_metadata = self._fetch_canon_metadata(base_url, root_body)
        if canon_metadata:
            return canon_metadata

        if 'kyocera' not in root_text and 'command center rx' not in root_text and 'km-mfp-http' not in root_text:
            onvif_metadata = {}
            camera_like = (
                554 in ports
                or 34567 in ports
                or any(service in ('onvif', 'xmeye', 'rtsp') for service in services)
            )
            if probe.get('port') in (80, 8899, 5000) and camera_like:
                onvif_metadata = self._fetch_onvif_device_info(base_url)

            plugin_response = None
            if probe.get('port') == 8899 or 'web viewer' in root_text:
                plugin_response = self._open_url(f"{base_url}/pluginVersion.js")
            plugin_text = (plugin_response or {}).get('body', '').lower()
            if onvif_metadata:
                if 'web viewer' in root_text or 'xmsecu.com' in plugin_text or 'version_web' in plugin_text:
                    onvif_metadata.setdefault('device_vendor', 'XMEye')
                    onvif_metadata.setdefault('device_ui', 'Web Viewer')
                return onvif_metadata

            if probe.get('port') == 80 and camera_like:
                rvi_metadata = self._fetch_rvi_legacy_metadata(base_url)
                if rvi_metadata:
                    return rvi_metadata

            if (
                'web viewer' not in root_text
                and 'xmsecu.com' not in plugin_text
                and 'version_web' not in plugin_text
                and 'netsurveillance web' not in root_text
            ):
                return {}

            metadata = {
                'device_vendor': 'XMEye',
                'device_family': 'web_viewer' if 'web viewer' in root_text or 'xmsecu.com' in plugin_text or 'version_web' in plugin_text else 'netsurveillance_web',
                'device_ui': 'Web Viewer' if 'web viewer' in root_text or 'xmsecu.com' in plugin_text or 'version_web' in plugin_text else 'NETSurveillance WEB',
            }
            prelogin = self._post_json(
                f"{base_url}/cgi-bin/login.cgi",
                {'Name': 'GetPreLoginInfo'},
            )
            if prelogin:
                try:
                    prelogin_data = json.loads(prelogin.get('body', '') or '{}')
                except json.JSONDecodeError:
                    prelogin_data = {}
                if prelogin_data.get('Language'):
                    metadata['device_language'] = str(prelogin_data['Language']).strip()
                if prelogin_data.get('TCPPort'):
                    metadata['device_tcp_port'] = prelogin_data['TCPPort']
            return metadata

        kyocera_metadata = self._fetch_kyocera_metadata(base_url, root_body)
        if kyocera_metadata.get('device_model') or 9100 not in ports:
            return kyocera_metadata

        pjl_metadata = self._fetch_pjl_metadata(ip, kyocera_metadata.get('device_vendor', 'Kyocera'))
        if pjl_metadata:
            merged = dict(kyocera_metadata)
            merged.update(pjl_metadata)
            return merged
        return kyocera_metadata

    def _apply_probe_results(self, host, probes):
        status = host.scan_status or ''
        for probe in probes:
            if probe.get('scheme') == 'rtsp':
                continue
            probe.update(self._fetch_targeted_probe_metadata(host.ip, probe))

        update = {
            'web_probes': {probe['port']: probe for probe in probes},
        }

        for probe in probes:
            if probe.get('device_vendor'):
                update['vendor'] = probe['device_vendor']
            if probe.get('device_model'):
                update['model'] = probe['device_model']
            if (
                status not in (STATUS_COMPLETED, STATUS_VIRTUALIZATION_COMPLETED)
                and probe.get('device_hostname')
            ):
                update['hostname'] = probe['device_hostname']
                update['hostnames'] = [probe['device_hostname']]

        merged = host.to_dict()
        merged.update(update)

        classified = classify_host(merged)
        update.update({
            'category': classified.get('category', ''),
            'type': classified.get('type', ''),
            'os_type': classified.get('os_type', ''),
            'os': classified.get('os', ''),
        })

        determine_vendor_model(update, merged | classified)
        final_type = update.get('type') or merged.get('type', '')
        final_vendor = update.get('vendor') or merged.get('vendor', '')
        final_model = update.get('model') or merged.get('model', '')
        camera_family = ''
        for probe in probes:
            family = str(probe.get('device_family', '')).strip()
            if family:
                camera_family = family
                break
        if (
            final_type == 'camera'
            and final_vendor in ('Synology', 'QNAP')
            and not any(probe.get('device_vendor') for probe in probes if isinstance(probe, dict))
            and not _has_strong_nas_web_signal(probes)
        ):
            update['vendor'] = ''
            final_vendor = ''
        if (
            status not in (STATUS_COMPLETED, STATUS_VIRTUALIZATION_COMPLETED)
            and final_type in ('printer', 'ipkvm', 'network', 'mikrotik')
            and final_vendor
            and final_model
        ):
            update['scan_status'] = STATUS_WEB_COMPLETED
        elif (
            status not in (STATUS_COMPLETED, STATUS_VIRTUALIZATION_COMPLETED)
            and final_type == 'camera'
            and final_vendor
            and (camera_family in ('web_viewer', 'netsurveillance_web', 'onvif_device_info', 'dahua_rtsp') or final_model)
        ):
            update['scan_status'] = STATUS_WEB_COMPLETED
        elif status == STATUS_WEB_COMPLETED:
            # Drop stale web-only completion when reclassification no longer has enough confidence.
            has_auth_context = bool(host.auth_methods or host.auth_attempts or host.auth_method)
            update['scan_status'] = STATUS_SCANNED if has_auth_context else STATUS_DISCOVERED
        self.storage.update_host(host.ip, update, overwrite_protected=True)

    def probe_host(self, ip):
        host = self.storage.get_host_record(ip)
        if not host:
            return

        target_ports = self._target_ports(host)
        if not target_ports:
            if host.web_probes:
                self.storage.update_host(ip, {'web_probes': {}}, overwrite_protected=True)
            elif (
                host.scan_status == STATUS_SCANNED
                and not host.open_ports
                and not host.auth_methods
                and not host.auth_attempts
                and not host.auth_method
            ):
                self.storage.update_host(ip, {'scan_status': STATUS_DISCOVERED}, overwrite_protected=True)
            return

        probes = []
        for port in target_ports:
            probe = self._probe_port(ip, port)
            if probe:
                probes.append(probe)

        if self._is_camera_like_host(host) and 554 in set(host.open_ports or []):
            rtsp_probe = self._probe_rtsp_port(ip, 554)
            if rtsp_probe:
                probes.append(rtsp_probe)

        self._apply_probe_results(host, probes)

    def enrich_all(self, target_ips=None):
        hosts = list(self.storage.iter_host_records())
        if target_ips is not None:
            target_set = set(target_ips)
            hosts = [host for host in hosts if host.ip in target_set]

        ips = [
            host.ip
            for host in hosts
            if self._target_ports(host)
            or host.web_probes
            or (
                host.scan_status == STATUS_SCANNED
                and not host.open_ports
                and not host.web_probes
                and not host.auth_methods
                and not host.auth_attempts
                and not host.auth_method
            )
        ]
        if not ips:
            return

        with ThreadPoolExecutor(max_workers=min(self.concurrency, len(ips))) as executor:
            futures = {executor.submit(self.probe_host, ip): ip for ip in ips}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    logger.error("Web probe failed for %s: %s", ip, exc)

        self.storage.flush()
