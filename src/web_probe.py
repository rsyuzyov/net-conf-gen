import html
import logging
import re
import socket
import ssl
import tempfile
import os
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.classification import classify_host
from src.constants import STATUS_COMPLETED, STATUS_VIRTUALIZATION_COMPLETED, STATUS_WEB_COMPLETED
from src.vendor_db import determine_vendor_model


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
}

TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)
LOGIN_RE = re.compile(
    r'(login|log in|sign in|password|username|user name|authentication|auth)',
    re.IGNORECASE,
)
AUTH_SCHEME_RE = re.compile(r'^\s*([A-Za-z]+)')
KYOCERA_ASSIGNMENT_RE = re.compile(r"_pp\.(f_getPrinterModel|f_getHostName|f_getSNMPSysLocation)\s*=\s*'([^']*)';")


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
        self._http_opener = urllib.request.build_opener(_NoRedirectHandler())
        self._https_opener = urllib.request.build_opener(
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=_https_context()),
        )

    def _target_ports(self, host):
        return [port for port in host.open_ports if port in WEB_PORT_SCHEMES]

    def _build_url(self, ip, port):
        return f"{WEB_PORT_SCHEMES[port]}://{ip}:{port}/"

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
            body = response.read(16384).decode('utf-8', errors='ignore')
        except urllib.error.HTTPError as exc:
            status_code = exc.code
            headers = exc.headers
            final_url = exc.geturl() or url
            try:
                body = exc.read(16384).decode('utf-8', errors='ignore')
            except Exception:
                body = ''
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
        request = urllib.request.Request(url, headers={'User-Agent': 'net-conf-gen/1.0'})
        response = None
        try:
            opener = self._https_opener if url.startswith('https://') else self._http_opener
            response = opener.open(request, timeout=self.timeout)
            body = response.read(20000).decode('utf-8', errors='ignore')
            return {
                'status_code': getattr(response, 'status', 200),
                'headers': response.headers,
                'body': body,
                'final_url': response.geturl() or url,
            }
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(20000).decode('utf-8', errors='ignore')
            except Exception:
                body = ''
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

    def _fetch_targeted_probe_metadata(self, ip, probe):
        if not probe.get('reachable'):
            return {}

        base_url = f"{probe.get('scheme', 'http')}://{ip}:{probe.get('port')}"
        root = self._open_url(f"{base_url}/")
        if not root:
            return {}

        root_body = root.get('body', '')
        root_text = ' '.join([
            root_body[:4000],
            str(probe.get('server', '')),
            str(probe.get('title', '')),
        ]).lower()

        if 'kyocera' not in root_text and 'command center rx' not in root_text and 'km-mfp-http' not in root_text:
            return {}

        model_url = (
            f"{base_url}/js/jssrc/model/startwlm/Start_Wlm.model.htm"
            "?arg1=&arg2=&arg3=&arg4=&arg5=&arg6=&arg8=&arg9=&arg10=0&arg11="
        )
        model_response = self._open_url(model_url)
        if not model_response:
            return {'device_vendor': 'Kyocera', 'device_family': 'command_center_rx'}

        values = {}
        for key, value in KYOCERA_ASSIGNMENT_RE.findall(model_response.get('body', '')):
            values[key] = value.strip()

        metadata = {
            'device_vendor': 'Kyocera',
            'device_family': 'command_center_rx',
        }
        if values.get('f_getPrinterModel'):
            metadata['device_model'] = values['f_getPrinterModel']
        if values.get('f_getHostName'):
            metadata['device_hostname'] = values['f_getHostName']
        if values.get('f_getSNMPSysLocation'):
            metadata['device_location'] = values['f_getSNMPSysLocation']
        return metadata

    def _apply_probe_results(self, host, probes):
        status = host.scan_status or ''
        for probe in probes:
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
        if (
            status not in (STATUS_COMPLETED, STATUS_VIRTUALIZATION_COMPLETED)
            and final_type in ('printer', 'ipkvm')
            and final_vendor
            and final_model
        ):
            update['scan_status'] = STATUS_WEB_COMPLETED
        self.storage.update_host(host.ip, update, overwrite_protected=True)

    def probe_host(self, ip):
        host = self.storage.get_host_record(ip)
        if not host:
            return

        target_ports = self._target_ports(host)
        if not target_ports:
            if host.web_probes:
                self.storage.update_host(ip, {'web_probes': {}}, overwrite_protected=True)
            return

        probes = []
        for port in target_ports:
            probe = self._probe_port(ip, port)
            if probe:
                probes.append(probe)

        self._apply_probe_results(host, probes)

    def enrich_all(self, target_ips=None):
        hosts = list(self.storage.iter_host_records())
        if target_ips is not None:
            target_set = set(target_ips)
            hosts = [host for host in hosts if host.ip in target_set]

        ips = [host.ip for host in hosts if self._target_ports(host) or host.web_probes]
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
