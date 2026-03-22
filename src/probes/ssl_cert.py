"""SSL certificate probe — получение CN и issuer из SSL-сертификата."""
import ssl
import socket
import re
import logging

logger = logging.getLogger(__name__)

# Порты для SSL-проверки
SSL_PORTS = {443, 4081, 5001, 8006, 8443, 10000}


def get_ssl_cert_info(ip, port=443, timeout=3):
    """Получить информацию из SSL/TLS-сертификата.

    Returns:
        dict: {'cn': str, 'issuer_cn': str} или пустой dict.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                cert = s.getpeercert(True)
                if not cert:
                    return {}

                pem = ssl.DER_cert_to_PEM_cert(cert)
                text = _cert_to_text(pem)
                result = {}

                cn_match = re.search(r'subject.*?CN\s*=\s*([^\r\n,/]+)', text)
                if cn_match:
                    result['cn'] = cn_match.group(1).strip()

                issuer_match = re.search(r'issuer.*?CN\s*=\s*([^\r\n,/]+)', text)
                if issuer_match:
                    result['issuer_cn'] = issuer_match.group(1).strip()

                return result
    except Exception as e:
        logger.debug(f"SSL cert scrape failed for {ip}:{port}: {e}")
        return {}


def scan_ssl_ports(ip, open_ports):
    """Собрать SSL cert info со всех HTTPS-подобных портов.

    Returns:
        dict: {port: {'cn': ..., 'issuer_cn': ...}}
    """
    ports = set(open_ports) & SSL_PORTS
    certs = {}
    for port in sorted(ports):
        cert = get_ssl_cert_info(ip, port=port)
        if cert:
            certs[port] = cert
            logger.info(f"  SSL cert {ip}:{port} = CN={cert.get('cn')}, Issuer={cert.get('issuer_cn')}")
    return certs


def _cert_to_text(pem_cert):
    """Получить текстовое представление сертификата.

    Сначала пробует openssl, fallback — пустая строка.
    """
    import subprocess
    try:
        r = subprocess.run(
            ['openssl', 'x509', '-noout', '-subject', '-issuer'],
            input=pem_cert, capture_output=True, text=True, timeout=5
        )
        return r.stdout
    except Exception:
        return ''
