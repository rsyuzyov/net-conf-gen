import socket
import ssl
import logging
import subprocess
import platform
import re

from src.connectors import snmp as snmp_connector
from src.connectors import http as http_connector

logger = logging.getLogger(__name__)

# Попытка импорта mac-vendor-lookup
try:
    from mac_vendor_lookup import MacLookup
    HAS_MAC_LOOKUP = True
except ImportError:
    HAS_MAC_LOOKUP = False
    logger.debug("mac-vendor-lookup not installed. Vendor detection will be limited.")

class Fingerprinter:
    """
    Класс для fingerprinting хостов.
    Определяет ОС и тип устройства через TTL, баннеры и MAC-адрес.
    Может работать как отдельный шаг для обработки хостов из storage.
    """
    
    def __init__(self, storage=None):
        """
        Args:
            storage: Storage объект (опционально, для работы в режиме шага)
        """
        self.storage = storage
        
        # Загрузка базы дефолтных учётных данных
        self._default_creds_db = http_connector.load_default_credentials()
        
        # Инициализация MAC lookup
        if HAS_MAC_LOOKUP:
            try:
                self.mac_lookup = MacLookup()
                # Обновить базу при первом запуске (требует интернет)
                try:
                    self.mac_lookup.update_vendors()
                except Exception:
                    pass  # Если нет интернета, используем существующую базу
            except Exception as e:
                logger.debug(f"Failed to initialize MAC lookup: {e}")
                self.mac_lookup = None
        else:
            self.mac_lookup = None

    # ===== Vendor Detection =====
    def get_vendor_from_mac(self, mac):
        """Получить производителя по MAC адресу."""
        if not mac or not self.mac_lookup:
            return ''

        try:
            vendor = self.mac_lookup.lookup(mac)
            return vendor
        except Exception as e:
            logger.debug(f"MAC lookup failed for {mac}: {e}")
            return ''

    def _detect_device_type_by_vendor(self, vendor):
        """Определение типа устройства по производителю."""
        if not vendor:
            return None

        vendor_lower = vendor.lower()

        # MikroTik devices (check first for specific type)
        mikrotik_vendors = ['mikrotik', 'routerboard']

        # Android devices
        android_vendors = [
            'xiaomi', 'samsung', 'huawei', 'oppo', 'vivo', 'oneplus',
            'realme', 'zte', 'lenovo', 'asus', 'lg electronics',
            'motorola mobility', 'google', 'htc', 'sony mobile',
            'meizu', 'tcl', 'honor', 'nothing technology'
        ]

        # iOS devices
        ios_vendors = ['apple']

        # IoT/Smart home
        iot_vendors = [
            'espressif', 'tuya', 'shelly', 'sonoff', 'tp-link',
            'yeelight', 'philips lighting', 'lifx', 'xiaomi communications'
        ]

        # Network equipment (generic)
        network_vendors = [
            'cisco', 'ubiquiti', 'huawei device',
            'd-link', 'netgear', 'juniper', 'aruba', 'hp'
        ]

        # Printers
        printer_vendors = [
            'hewlett packard', 'canon', 'epson', 'brother', 'xerox', 'ricoh'
        ]

        # Check MikroTik first (before generic network)
        for v in mikrotik_vendors:
            if v in vendor_lower:
                return 'mikrotik'

        for v in android_vendors:
            if v in vendor_lower:
                return 'mobile'

        for v in ios_vendors:
            if v in vendor_lower:
                return 'mobile'

        for v in iot_vendors:
            if v in vendor_lower:
                return 'iot'

        for v in network_vendors:
            if v in vendor_lower:
                return 'network'

        for v in printer_vendors:
            if v in vendor_lower:
                return 'printer'

        return None

    # ===== Vendor / Model =====
    # Маппинг MAC-vendor → нормализованный vendor
    _MAC_VENDOR_MAP = {
        'hewlett packard': 'HP',
        'hp inc': 'HP',
        'routerboard': 'MikroTik',
        'mikrotik': 'MikroTik',
        'tp-link': 'TP-Link',
        'cisco': 'Cisco',
        'ubiquiti': 'Ubiquiti',
        'd-link': 'D-Link',
        'netgear': 'Netgear',
        'juniper': 'Juniper',
        'aruba': 'Aruba',
        'apple': 'Apple',
        'samsung': 'Samsung',
        'xiaomi': 'Xiaomi',
        'huawei': 'Huawei',
        'canon': 'Canon',
        'epson': 'Epson',
        'brother': 'Brother',
        'xerox': 'Xerox',
        'ricoh': 'Ricoh',
        'konica minolta': 'Konica Minolta',
        'intel': 'Intel',
        'dell': 'Dell',
        'lenovo': 'Lenovo',
        'asus': 'ASUS',
        'espressif': 'Espressif',
        'tuya': 'Tuya',
        'hikvision': 'Hikvision',
        'dahua': 'Dahua',
    }

    def _determine_vendor_model(self, update_data, host_info):
        """
        Определяет vendor (бренд) и model (продукт/модель) по всем источникам.

        Приоритет:
          1. SSL cert issuer
          2. SNMP sysDescr
          3. HTTP title
          4. OS / port-based detection
          5. MAC vendor (fallback)

        Записывает 'vendor' и 'model' в update_data.
        """
        vendor = ''
        model = ''
        mac_vendor = host_info.get('vendor', '')  # сырой MAC-vendor

        os_name = update_data.get('os', '')
        http_title = update_data.get('http_title', '')
        ssl_cert = update_data.get('ssl_cert', {})
        snmp_info = update_data.get('snmp_info', {})
        host_type = update_data.get('type', '')

        # --- 1. SSL cert issuer ---
        ssl_issuer = ''
        if isinstance(ssl_cert, dict):
            ssl_issuer = ssl_cert.get('issuer_cn', '').lower()
        if 'kerio' in ssl_issuer:
            vendor = vendor or 'Kerio'
            model = model or 'Kerio Control'
        elif 'proxmox' in ssl_issuer:
            vendor = vendor or 'Proxmox'
            model = model or 'Proxmox VE'

        # --- 2. SNMP sysDescr ---
        sys_descr = ''
        if isinstance(snmp_info, dict):
            sys_descr = snmp_info.get('sysDescr', '')
        if sys_descr:
            sd_lower = sys_descr.lower()
            if 'routeros' in sd_lower or 'mikrotik' in sd_lower:
                vendor = vendor or 'MikroTik'
                model = model or sys_descr.strip()[:80]
            elif 'cisco' in sd_lower:
                vendor = vendor or 'Cisco'
                model = model or sys_descr.strip()[:80]
            elif 'linux' in sd_lower:
                model = model or sys_descr.strip()[:80]
            elif 'windows' in sd_lower:
                vendor = vendor or 'Microsoft'
                model = model or sys_descr.strip()[:80]

        # --- 3. HTTP title ---
        if http_title:
            title_lower = http_title.lower()
            title_vendor_map = {
                'laserjet': ('HP', http_title),
                'hp ': ('HP', http_title),
                'canon': ('Canon', http_title),
                'epson': ('Epson', http_title),
                'brother': ('Brother', http_title),
                'xerox': ('Xerox', http_title),
                'ricoh': ('Ricoh', http_title),
                'konica': ('Konica Minolta', http_title),
                'pi-hole': ('Pi-hole', 'Pi-hole'),
                'proxmox': ('Proxmox', http_title),
                'synology': ('Synology', http_title),
                'qnap': ('QNAP', http_title),
                'mikrotik': ('MikroTik', http_title),
                'hikvision': ('Hikvision', http_title),
                'dahua': ('Dahua', http_title),
                'ubiquiti': ('Ubiquiti', http_title),
                'unifi': ('Ubiquiti', http_title),
                'kerio': ('Kerio', http_title),
            }
            for kw, (v, m) in title_vendor_map.items():
                if kw in title_lower:
                    vendor = vendor or v
                    model = model or m
                    break

        # --- 4. OS / port-based ---
        if os_name:
            os_lower = os_name.lower()
            if 'mikrotik' in os_lower:
                vendor = vendor or 'MikroTik'
                model = model or 'RouterOS'
            elif 'kerio' in os_lower:
                vendor = vendor or 'Kerio'
                model = model or 'Kerio Control'
            elif 'proxmox' in os_lower:
                vendor = vendor or 'Proxmox'
                model = model or 'Proxmox VE'
            elif 'windows' in os_lower:
                vendor = vendor or 'Microsoft'
            elif host_type == 'printer' and 'printer' in os_lower:
                pass  # vendor уже определён из title/mac

        # --- 5. MAC vendor (fallback + нормализация) ---
        if mac_vendor:
            mac_lower = mac_vendor.lower()
            for pattern, normalized in self._MAC_VENDOR_MAP.items():
                if pattern in mac_lower:
                    vendor = vendor or normalized
                    break
            if not vendor:
                # Используем MAC vendor как есть, если не нашли в маппинге
                vendor = mac_vendor

        # Записываем
        if vendor:
            update_data['vendor'] = vendor
        if model:
            update_data['model'] = model

    # ===== Reverse DNS =====
    def _reverse_dns(self, ip):
        """Получить hostname через reverse DNS."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            short = hostname.split('.')[0]
            return short
        except socket.herror:
            return ""
        except Exception as e:
            logger.debug(f"Reverse DNS failed for {ip}: {e}")
            return ""

    # ===== HTTP Title =====
    def _get_http_title(self, ip, port=80, timeout=3):
        """Получить <title> с HTTP-страницы."""
        try:
            import urllib.request
            import urllib.error
            scheme = 'https' if port in (443, 4081, 5001, 8006, 8443, 10000) else 'http'
            url = f"{scheme}://{ip}:{port}/"
            req = urllib.request.Request(url, headers={'User-Agent': 'net-conf-gen/1.0'})
            ctx = None
            if scheme == 'https':
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                body = response.read(4096).decode('utf-8', errors='ignore')
                match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
                if match:
                    return match.group(1).strip()
        except Exception:
            pass
        return ""

    # ===== SSL Certificate =====
    def _get_ssl_cert_info(self, ip, port=443, timeout=3):
        """Получить информацию из SSL/TLS-сертификата.

        Returns:
            dict: {'cn': str, 'issuer_cn': str, 'not_after': str} или пустой dict
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as s:
                    cert_bin = s.getpeercert(True)
                    if not cert_bin:
                        return {}

                    # Парсим через openssl (если доступен) или DER → PEM → subprocess
                    pem = ssl.DER_cert_to_PEM_cert(cert_bin)
                    result = {}

                    # Subject CN
                    cn_match = re.search(r'subject.*?CN\s*=\s*([^\r\n,/]+)',
                                         self._openssl_x509_text(pem))
                    if cn_match:
                        result['cn'] = cn_match.group(1).strip()

                    # Issuer CN
                    issuer_match = re.search(r'issuer.*?CN\s*=\s*([^\r\n,/]+)',
                                             self._openssl_x509_text(pem))
                    if issuer_match:
                        result['issuer_cn'] = issuer_match.group(1).strip()

                    return result
        except Exception as e:
            logger.debug(f"SSL cert scrape failed for {ip}:{port}: {e}")
            return {}

    def _openssl_x509_text(self, pem_cert):
        """Получить текстовое представление сертификата через openssl."""
        try:
            r = subprocess.run(
                ['openssl', 'x509', '-noout', '-subject', '-issuer'],
                input=pem_cert, capture_output=True, text=True, timeout=5
            )
            return r.stdout
        except Exception:
            # Fallback: парсим PEM вручную через ssl модуль
            try:
                cert = ssl.PEM_cert_to_DER_cert(pem_cert)
                # Простой regex по base64 — не даст CN, вернём пустую строку
                return ""
            except Exception:
                return ""

    # ===== Port-based Detection =====
    def _detect_by_ports(self, open_ports):
        """Определение типа устройства по характерным комбинациям портов."""
        if not open_ports:
            return None
        ports = set(open_ports)

        # MikroTik: API (8728/8729) — надёжный маркер
        if ports & {8728, 8729}:
            return {'os': 'MikroTik RouterOS', 'os_type': 'linux', 'type': 'mikrotik'}

        # Winbox (8291) — может быть и у HP-принтеров
        # Если 9100 (JetDirect) тоже открыт — скорее принтер, пропускаем  
        if 8291 in ports and 9100 not in ports:
            return {'os': 'MikroTik RouterOS', 'os_type': 'linux', 'type': 'mikrotik'}

        # WinRM (5985) = 100% Windows
        if 5985 in ports:
            return {'os': 'Windows', 'os_type': 'windows', 'type': 'workstation'}

        # Kerio Control: порт 4081 (админка) или 4040
        if ports & {4081, 4040}:
            return {'os': 'Kerio Control', 'os_type': 'linux', 'type': 'network'}

        return None

    # ===== Deep Port Analysis =====
    # Порты, на которых стоит собирать HTTP title
    HTTP_PORTS = {80, 443, 3000, 4040, 4081, 5000, 5001, 8006, 8080, 8443, 10000}
    # Порты, на которых стоит собирать SSL cert
    SSL_PORTS = {443, 4081, 5001, 8006, 8443, 10000}
    # Порты для расширенного banner grabbing (в дополнение к стандартным)
    EXTRA_BANNER_PORTS = {23, 554, 1433, 1521, 3306, 5432, 5900, 8291}

    def _deep_port_analysis(self, ip, open_ports, update_data):
        """
        Расширенный анализ всех найденных портов для неполностью определённых хостов.
        Собирает HTTP title, SSL cert и баннеры с нестандартных портов.
        """
        ports = set(open_ports)

        # HTTP title со всех HTTP-подобных портов
        http_titles = {}
        for port in sorted(ports & self.HTTP_PORTS):
            title = self._get_http_title(ip, port=port, timeout=3)
            if title:
                http_titles[port] = title
                logger.info(f"  HTTP title {ip}:{port} = {title[:60]}")
        
        if http_titles:
            update_data['http_titles'] = http_titles
            # Основной http_title — с первого найденного порта (80 приоритет)
            if not update_data.get('http_title'):
                primary_port = 80 if 80 in http_titles else min(http_titles.keys())
                update_data['http_title'] = http_titles[primary_port]

        # SSL cert со всех HTTPS-подобных портов
        ssl_certs = {}
        for port in sorted(ports & self.SSL_PORTS):
            cert = self._get_ssl_cert_info(ip, port=port)
            if cert:
                ssl_certs[port] = cert
                logger.info(f"  SSL cert {ip}:{port} = CN={cert.get('cn')}, Issuer={cert.get('issuer_cn')}")
        
        if ssl_certs:
            update_data['ssl_certs'] = ssl_certs
            # Основной ssl_cert — с 443 или первого найденного
            if not update_data.get('ssl_cert'):
                primary_port = 443 if 443 in ssl_certs else min(ssl_certs.keys())
                update_data['ssl_cert'] = ssl_certs[primary_port]

        # Расширенный banner grabbing
        extra_banners = {}
        for port in sorted(ports & self.EXTRA_BANNER_PORTS):
            banner = self._grab_banner(ip, port, timeout=1)
            if banner:
                extra_banners[port] = banner[:200]
                logger.info(f"  Banner {ip}:{port} = {banner[:60]}")

        if extra_banners:
            update_data['extra_banners'] = extra_banners

        # Дополнительная классификация на основе собранных данных
        self._classify_from_deep_analysis(update_data, http_titles, ssl_certs, extra_banners)

    def _classify_from_deep_analysis(self, update_data, http_titles, ssl_certs, extra_banners):
        """
        Дополнительная классификация хоста на основе данных глубокого анализа портов.
        Используется когда стандартные методы не дали высокой уверенности.
        """
        current_type = update_data.get('type', 'unknown')
        current_os = update_data.get('os', 'Unknown')
        
        # Если тип уже определён с высокой уверенностью, не трогаем
        if current_type not in ('unknown', 'server', 'workstation') and \
           update_data.get('fingerprint_confidence') == 'high':
            return
        
        # Анализируем HTTP title со всех портов
        all_titles = ' '.join(http_titles.values()).lower() if http_titles else ''
        
        # Grafana
        if 'grafana' in all_titles:
            if current_type == 'unknown':
                update_data['type'] = 'server'
            update_data.setdefault('model', 'Grafana')
            logger.info(f"  Classified via deep analysis: Grafana")
        
        # Proxmox
        if 'proxmox' in all_titles:
            update_data['type'] = 'server'
            if 'proxmox' not in current_os.lower():
                update_data['os'] = 'Proxmox VE'
            update_data.setdefault('vendor', 'Proxmox')
            logger.info(f"  Classified via deep analysis: Proxmox VE")
        
        # Kibana
        if 'kibana' in all_titles:
            if current_type == 'unknown':
                update_data['type'] = 'server'
            update_data.setdefault('model', 'Kibana')
            logger.info(f"  Classified via deep analysis: Kibana")
        
        # Synology / QNAP NAS
        if 'synology' in all_titles:
            update_data['type'] = 'server'
            update_data.setdefault('vendor', 'Synology')
            update_data.setdefault('model', 'DiskStation')
            logger.info(f"  Classified via deep analysis: Synology NAS")
        
        if 'qnap' in all_titles:
            update_data['type'] = 'server'
            update_data.setdefault('vendor', 'QNAP')
            logger.info(f"  Classified via deep analysis: QNAP NAS")
        
        # UniFi
        if 'unifi' in all_titles or 'ubiquiti' in all_titles:
            update_data.setdefault('vendor', 'Ubiquiti')
            if current_type == 'unknown':
                update_data['type'] = 'network'
            logger.info(f"  Classified via deep analysis: Ubiquiti/UniFi")
        
        # Webmin
        if 'webmin' in all_titles:
            if current_type == 'unknown':
                update_data['type'] = 'server'
            update_data.setdefault('model', 'Webmin')
            logger.info(f"  Classified via deep analysis: Webmin")
        
        # Zabbix
        if 'zabbix' in all_titles:
            if current_type == 'unknown':
                update_data['type'] = 'server'
            update_data.setdefault('model', 'Zabbix')
            logger.info(f"  Classified via deep analysis: Zabbix")
        
        # NanoKVM
        if 'nanokvm' in all_titles:
            update_data['type'] = 'server'
            update_data['os'] = 'Linux/Unix'
            update_data.setdefault('vendor', 'Sipeed')
            update_data['model'] = 'NanoKVM'
            logger.info(f"  Classified via deep analysis: NanoKVM")
        
        # Камеры по HTTP title → vendor/model
        if 'netsurveillance' in all_titles:
            update_data['type'] = 'camera'
            update_data['os'] = 'IP Camera'
            update_data.setdefault('vendor', 'XMEye')
            update_data.setdefault('model', 'NETSurveillance DVR/NVR')
            logger.info(f"  Classified via deep analysis: XMEye NETSurveillance")
        
        if 'webpackspa' in all_titles:
            update_data['type'] = 'camera'
            update_data['os'] = 'IP Camera'
            update_data.setdefault('vendor', 'Hikvision')
            update_data.setdefault('model', 'IP Camera')
            logger.info(f"  Classified via deep analysis: Hikvision (webpackSPA)")
        
        if 'web viewer' in all_titles:
            update_data['type'] = 'camera'
            update_data['os'] = 'IP Camera'
            update_data.setdefault('vendor', 'Samsung/Hanwha')
            update_data.setdefault('model', 'IP Camera')
            logger.info(f"  Classified via deep analysis: Samsung/Hanwha (Web Viewer)")
        
        # Анализируем SSL certs
        for port, cert in ssl_certs.items():
            issuer = cert.get('issuer_cn', '').lower()
            cn = cert.get('cn', '').lower()
            
            if 'kerio' in issuer or 'kerio' in cn:
                update_data['type'] = 'network'
                update_data['os'] = 'Kerio Control'
                update_data.setdefault('vendor', 'Kerio')
                logger.info(f"  Classified via deep SSL analysis ({port}): Kerio Control")
            elif 'proxmox' in issuer or 'proxmox' in cn:
                update_data['type'] = 'server'
                update_data['os'] = 'Proxmox VE'
                update_data.setdefault('vendor', 'Proxmox')
                logger.info(f"  Classified via deep SSL analysis ({port}): Proxmox VE")
        
        # Анализируем extra banners
        for port, banner in extra_banners.items():
            banner_lower = banner.lower()
            
            # Telnet (23) — часто роутеры или управляемые свитчи
            if port == 23 and current_type == 'unknown':
                update_data['type'] = 'network'
                logger.info(f"  Telnet banner detected, classified as network")
            
            # RTSP (554) — камеры
            if port == 554 and ('rtsp' in banner_lower or 'server' in banner_lower):
                if current_type not in ('camera', 'printer'):
                    update_data['type'] = 'camera'
                    update_data['os'] = 'IP Camera'
                    logger.info(f"  RTSP banner detected, classified as camera")

    # ===== Windows Classification =====
    def _classify_windows_type(self, hostname, open_ports):
        """Уточнение типа Windows: server vs workstation."""
        if hostname and hostname.lower().startswith('srv-'):
            return 'server'

        server_indicators = {88, 389, 636, 1540, 1541, 1560, 1561, 2049, 5985}
        if server_indicators & set(open_ports or []):
            return 'server'

        return 'workstation'

    # ===== TTL Analysis =====
    def _ping_ttl(self, ip, timeout=2):
        """Получить TTL через ping."""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            result = subprocess.run(
                ['ping', param, '1', ip],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            output = result.stdout

            # Парсинг TTL
            ttl_match = re.search(r'TTL[=:]?\s*(\d+)', output, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                return ttl
        except Exception as e:
            logger.debug(f"Ping failed for {ip}: {e}")

        return None

    def _analyze_ttl(self, ttl):
        """Определение ОС по TTL значению."""
        if not ttl:
            return {}

        # Windows: 128
        if 110 <= ttl <= 128:
            return {'os': 'Windows', 'os_type': 'windows', 'type': 'workstation'}
        # Linux/Unix: 64
        elif 50 <= ttl <= 64:
            return {'os': 'Linux/Unix', 'os_type': 'linux', 'type': 'server'}
        # Network device: 255
        elif ttl > 200:
            return {'os': 'Network Device', 'os_type': 'linux', 'type': 'network'}

        return {}

    # ===== Banner Grabbing =====
    def _grab_banner(self, ip, port, timeout=1):
        """Получить баннер сервиса."""
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)

                # Для HTTP отправляем запрос
                if port in [80, 8080, 8000]:
                    sock.send(b'HEAD / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                # HTTPS (443) пропускаем - требует SSL handshake
                elif port == 443:
                    return None

                # Читаем ответ
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner
        except Exception as e:
            logger.debug(f"Banner grab failed {ip}:{port} - {e}")
            return None

    def _analyze_banners(self, ip):
        """Анализ баннеров с нескольких портов."""
        banners = {}
        result = {}

        # Порты для banner grabbing
        BANNER_PORTS = [22, 80, 8080, 21, 25]

        for port in BANNER_PORTS:
            banner = self._grab_banner(ip, port, timeout=1)
            if banner:
                banners[port] = banner
                logger.debug(f"Banner {ip}:{port} - {banner[:50]}")

        # Анализ SSH (22)
        if 22 in banners:
            ssh_banner = banners[22]
            if 'OpenSSH' in ssh_banner:
                result['os'] = 'Linux/Unix (OpenSSH)'
                result['os_type'] = 'linux'
                result['type'] = 'server'
                return result
            elif 'dropbear' in ssh_banner.lower():
                result['os'] = 'Embedded Linux (Dropbear)'
                result['os_type'] = 'linux'
                result['type'] = 'iot'
                return result

        # Анализ HTTP (80, 8080)
        for port in [80, 8080]:
            if port in banners:
                http_banner = banners[port]
                
                # Ищем Server header
                server_match = re.search(r'Server:\s*([^\r\n]+)', http_banner, re.IGNORECASE)
                if server_match:
                    server = server_match.group(1)
                    server_lower = server.lower()

                    if 'nginx' in server_lower or 'apache' in server_lower:
                        if 'win64' in server_lower or 'win32' in server_lower:
                            result['os'] = f'Windows ({server})'
                            result['os_type'] = 'windows'
                        else:
                            result['os'] = f'Linux ({server})'
                            result['os_type'] = 'linux'
                        result['type'] = 'server'
                        return result
                    elif 'iis' in server_lower or 'microsoft' in server_lower:
                        result['os'] = f'Windows ({server})'
                        result['os_type'] = 'windows'
                        result['type'] = 'server'
                        return result
                    elif 'printer' in server_lower or 'cups' in server_lower:
                        result['os'] = 'Printer'
                        result['os_type'] = 'linux'
                        result['type'] = 'printer'
                        return result

        # Анализ FTP (21)
        if 21 in banners:
            ftp_banner = banners[21]
            if 'Microsoft FTP' in ftp_banner or 'Windows' in ftp_banner:
                result['os'] = 'Windows (FTP)'
                result['os_type'] = 'windows'
                result['type'] = 'server'
                return result
            elif 'vsFTPd' in ftp_banner or 'ProFTPD' in ftp_banner:
                result['os'] = 'Linux (FTP)'
                result['os_type'] = 'linux'
                result['type'] = 'server'
                return result

        return result

    # ===== Main Fingerprinting Method =====
    def lightweight_fingerprint(self, ip, vendor=None, mac=None, open_ports=None):
        """
        Легковесный fingerprinting без nmap.

        Args:
            ip: IP адрес
            vendor: MAC vendor (опционально, для fallback)
            mac: MAC адрес (для lookup vendor если не передан)

        Returns:
            dict: {
                'os': str,
                'kernel_version': str,
                'type': str,
                'confidence': str (high/medium/low),
                'method': str (ttl/banner/vendor/none),
                'details': dict
            }
        """
        result = {
            'os': 'Unknown',
            'kernel_version': '',
            'os_type': 'linux',
            'type': 'unknown',
            'hostname': '',
            'confidence': 'low',
            'method': 'none',
            'details': {}
        }

        # 0. Обновить vendor через MAC lookup если нужно
        if not vendor and mac:
            vendor = self.get_vendor_from_mac(mac)
        
        if vendor:
            result['vendor'] = vendor

        # 1. Port-based pre-detection (высокая достоверность)
        if open_ports:
            port_info = self._detect_by_ports(open_ports)
            if port_info:
                result.update(port_info)
                result['confidence'] = 'high'
                result['method'] = 'port'
                logger.info(f"Fingerprint {ip} via ports: {port_info}")
                return result

        # 2. TTL Analysis (быстрый, надежный)
        ttl = self._ping_ttl(ip, timeout=2)
        if ttl:
            result['details']['ttl'] = ttl
            ttl_info = self._analyze_ttl(ttl)
            
            if ttl_info.get('os_type'):
                result['os'] = ttl_info['os']
                result['os_type'] = ttl_info['os_type']
                result['type'] = ttl_info.get('type', 'unknown')
                result['confidence'] = 'medium'
                result['method'] = 'ttl'
                # Уточняем тип Windows (server vs workstation)
                if result['os_type'] == 'windows' and open_ports:
                    result['type'] = self._classify_windows_type(
                        result.get('hostname', ''), open_ports)
                logger.debug(f"Fingerprint {ip} via TTL: {ttl_info}")
                return result

        # 3. Banner Grabbing (более точный)
        banner_info = self._analyze_banners(ip)
        if banner_info.get('os_type'):
            result['os'] = banner_info['os']
            result['os_type'] = banner_info['os_type']
            result['type'] = banner_info.get('type', 'unknown')
            result['confidence'] = 'high'
            result['method'] = 'banner' if not ttl else 'ttl+banner'
            # Уточняем тип Windows
            if result['os_type'] == 'windows' and open_ports:
                result['type'] = self._classify_windows_type(
                    result.get('hostname', ''), open_ports)
            logger.info(f"Fingerprint {ip} via banner: {banner_info}")
            return result

        # 4. Vendor-based Detection (fallback)
        if vendor:
            device_type = self._detect_device_type_by_vendor(vendor)
            if device_type:
                # TP-Link с DNS-портом → network (роутер), а не IoT
                if device_type == 'iot' and open_ports and 53 in open_ports:
                    device_type = 'network'
                # Маппинг типов устройств на os_type
                os_type_map = {
                    'mobile': 'android',
                    'iot': 'linux',
                    'network': 'linux',
                    'printer': 'linux',
                    'mikrotik': 'linux'
                }
                result['os_type'] = os_type_map.get(device_type, 'linux')
                result['type'] = device_type
                result['os'] = {
                    'mobile': 'Android/iOS',
                    'iot': 'IoT Device',
                    'network': 'Network Equipment',
                    'printer': 'Printer',
                    'mikrotik': 'MikroTik RouterOS'
                }.get(device_type, 'Unknown')
                result['confidence'] = 'low'
                result['method'] = 'vendor'
                logger.info(f"Fingerprint {ip} via vendor: {vendor} -> {device_type}")
                return result

        # Если ничего не сработало
        logger.debug(f"Fingerprint {ip} failed - no methods succeeded")
        return result

    # ===== Backward Compatibility =====
    def fingerprint(self, ip, vendor=None, open_ports=None):
        """
        Обратная совместимость со старым API.
        
        Формат:
            {'os': str, 'hostname': str, 'os_type': str, 'type': str}
        """
        # Вызываем новый метод
        fp_result = self.lightweight_fingerprint(ip, vendor=vendor, mac=None, open_ports=open_ports)
        
        # Возвращаем в формате
        return {
            'os': fp_result['os'],
            'hostname': fp_result.get('hostname', ''),
            'os_type': fp_result['os_type'],
            'type': fp_result['type']
        }

    # ===== Step Mode Methods =====
    def run(self, host_ip=None, force=False):
        """
        Запускает fingerprinting для хостов из storage.
        
        Args:
            host_ip: IP конкретного хоста (опционально)
            force: Принудительно запустить для всех хостов
        """
        if not self.storage:
            raise ValueError("Storage не инициализирован. Создайте объект с storage для использования run()")
        
        if host_ip:
            # Fingerprint для конкретного хоста
            self._fingerprint_host(host_ip, force)
        else:
            # Fingerprint для всех подходящих хостов
            self._fingerprint_all_hosts(force)
    
    def _fingerprint_host(self, ip, force=False):
        """Fingerprint для одного хоста."""
        host_info = self.storage.get_host(ip)
        
        if not host_info:
            logger.error(f"Хост {ip} не найден в storage")
            return
        
        # Проверяем, нужно ли делать fingerprint
        deep_scan_status = host_info.get('deep_scan_status', '')
        
        if not force and deep_scan_status == 'completed':
            logger.info(f"Хост {ip} уже имеет deep_scan_status=completed, пропускаем")
            return
        
        logger.info(f"Fingerprinting хоста: {ip}")
        
        # Выполняем fingerprinting
        open_ports = host_info.get('open_ports', [])
        fp_result = self.lightweight_fingerprint(
            ip,
            vendor=host_info.get('vendor'),
            mac=host_info.get('mac'),
            open_ports=open_ports
        )
        
        # Обновляем информацию в storage
        update_data = {
            'os': fp_result.get('os', 'Unknown'),
            'os_type': fp_result.get('os_type', 'linux'),
            'type': fp_result.get('type', 'unknown'),
            'fingerprint_method': fp_result.get('method', 'none'),
            'fingerprint_confidence': fp_result.get('confidence', 'low')
        }
        
        # Hostname: reverse DNS если не определён ранее
        current_hostname = host_info.get('hostname', '')
        fp_hostname = fp_result.get('hostname', '')
        if not current_hostname and not fp_hostname:
            dns_hostname = self._reverse_dns(ip)
            if dns_hostname:
                update_data['hostname'] = dns_hostname
                logger.info(f"  Hostname via reverse DNS: {dns_hostname}")
        elif fp_hostname:
            update_data['hostname'] = fp_hostname
        
        # Расширенный анализ портов: HTTP title, SSL cert, баннеры
        # с ВСЕХ HTTP/HTTPS-подобных портов (не только 80/443)
        self._deep_port_analysis(ip, open_ports, update_data)

        # SSL cert → hostname и уточнение ОС
        ssl_cert = update_data.get('ssl_cert', {})
        if ssl_cert:
            ssl_cn = ssl_cert.get('cn', '')
            ssl_issuer = ssl_cert.get('issuer_cn', '')

            # CN → hostname (если ещё не определён и CN похож на hostname)
            if ssl_cn and not update_data.get('hostname') and not current_hostname:
                # Фильтруем IP-адреса и wildcard-сертификаты
                if not ssl_cn.startswith('*') and not re.match(r'^\d+\.\d+\.\d+\.\d+$', ssl_cn):
                    update_data['hostname'] = ssl_cn.split('.')[0]
                    logger.info(f"  Hostname via SSL CN: {update_data['hostname']}")

            # Issuer → уточнение ОС
            issuer_lower = ssl_issuer.lower()
            if 'kerio' in issuer_lower and update_data.get('os', 'Unknown') in ('Unknown', 'Linux/Unix'):
                update_data['os'] = 'Kerio Control'
                update_data['type'] = 'network'
                logger.info(f"  OS via SSL issuer: Kerio Control")
            elif 'proxmox' in issuer_lower and update_data.get('os', 'Unknown') in ('Unknown', 'Linux/Unix'):
                update_data['os'] = 'Proxmox VE'
                update_data['type'] = 'server'
                logger.info(f"  OS via SSL issuer: Proxmox VE")

        # Определение принтеров по hostname и http_title
        final_hostname = update_data.get('hostname') or current_hostname or ''
        http_title = update_data.get('http_title', '')
        hostname_lower = final_hostname.lower()
        title_lower = http_title.lower()
        
        printer_hostname = hostname_lower.startswith('npi') or hostname_lower.startswith('km')
        printer_title = any(kw in title_lower for kw in ['laserjet', 'canon', 'epson', 'brother', 'xerox', 'ricoh', 'konica', 'lbp'])
        
        if printer_hostname or printer_title:
            update_data['type'] = 'printer'
            update_data['os'] = 'Printer'
            update_data['os_type'] = 'linux'
            logger.info(f"  Classified as printer (hostname={final_hostname}, title={http_title[:40]})")
        
        # Определение IP-камер по http_title и портам
        camera_title_keywords = {
            'netsurveillance': ('XMEye', 'NETSurveillance DVR/NVR'),
            'webpackspa': ('Hikvision', 'IP Camera'),
            'web viewer': ('Samsung/Hanwha', 'IP Camera'),
            'hikvision': ('Hikvision', 'IP Camera'),
            'dahua': ('Dahua', 'IP Camera'),
            'ipcamera': (None, 'IP Camera'),
            'ip camera': (None, 'IP Camera'),
            'dvr': (None, 'DVR'),
            'nvr': (None, 'NVR'),
            'xmeye': ('XMEye', 'DVR/NVR'),
            'surveillance': (None, None),
            'onvif': (None, None),
        }
        camera_title = False
        camera_vendor_from_title = None
        camera_model_from_title = None
        for kw, (v, m) in camera_title_keywords.items():
            if kw in title_lower:
                camera_title = True
                if v and not camera_vendor_from_title:
                    camera_vendor_from_title = v
                if m and not camera_model_from_title:
                    camera_model_from_title = m
        
        camera_ports = bool({554, 8899, 34567} & set(open_ports))
        
        if (camera_title or camera_ports) and update_data.get('type') != 'printer':
            update_data['type'] = 'camera'
            update_data['os'] = 'IP Camera'
            update_data['os_type'] = 'linux'
            if camera_vendor_from_title:
                update_data.setdefault('vendor', camera_vendor_from_title)
            if camera_model_from_title:
                update_data.setdefault('model', camera_model_from_title)
            logger.info(f"  Classified as camera (title={http_title[:40]}, camera_ports={camera_ports})")
        
        # Vendor-based type refinement (для случаев когда TTL ставит generic type)
        vendor = host_info.get('vendor', '')
        if vendor and update_data.get('type') not in ('printer', 'mikrotik', 'camera'):
            vendor_lower = vendor.lower()
            # TP-Link с DNS-портом → сетевое оборудование (роутер)
            if 'tp-link' in vendor_lower and 53 in open_ports:
                update_data['type'] = 'network'
                update_data['os'] = 'Network Equipment'
                logger.info(f"  Classified as network (vendor={vendor}, DNS port open)")
        
        # SNMP-опрос для хостов с портом 161 или type='network'
        if 161 in open_ports or update_data.get('type') in ('network', 'mikrotik'):
            snmp_info = snmp_connector.snmp_get_info(ip)
            if snmp_info:
                update_data['snmp_info'] = snmp_info
                # sysName → hostname (если не определён)
                sys_name = snmp_info.get('sysName', '')
                if sys_name and not update_data.get('hostname') and not current_hostname:
                    update_data['hostname'] = sys_name.split('.')[0]
                    logger.info(f"  Hostname via SNMP: {update_data['hostname']}")
                # sysLocation → location
                sys_location = snmp_info.get('sysLocation', '')
                if sys_location:
                    update_data['location'] = sys_location
                # Уточнение os/type по sysDescr
                snmp_os = snmp_connector.parse_snmp_os(snmp_info)
                if snmp_os and update_data.get('os', 'Unknown') in ('Unknown', 'Network Device', 'Network Equipment'):
                    update_data.update(snmp_os)
                    logger.info(f"  OS via SNMP: {snmp_os.get('os')}")
        
        # Уточняем Windows type если hostname стал известен
        if update_data.get('os_type') == 'windows':
            hostname = update_data.get('hostname') or current_hostname or ''
            update_data['type'] = self._classify_windows_type(hostname, open_ports)
        
        # Определяем vendor (бренд) и model (продукт/модель)
        self._determine_vendor_model(update_data, host_info)
        
        # Проверка дефолтных учётных данных через HTTP
        http_ports = {80, 443, 3000, 4040, 4081, 5000, 5001, 8006, 8080, 8443, 10000}
        if http_ports & set(open_ports):
            # Собираем актуальную информацию для маппинга
            merged_info = dict(host_info)
            merged_info.update(update_data)
            
            web_auth = http_connector.check_default_credentials(
                ip, merged_info, self._default_creds_db
            )
            if web_auth:
                update_data['web_auth_check'] = web_auth
                if web_auth.get('default_creds_found'):
                    user = web_auth.get('user', '')
                    pwd = web_auth.get('password', '')
                    port = web_auth.get('port', 80)
                    auth_type = web_auth.get('auth_type', 'http')
                    # Формируем поле account: протокол://user:password@ip:port
                    proto = 'https' if port in (443, 4081, 5001, 8006, 8443, 10000) else 'http'
                    pwd_display = pwd if pwd else '(пустой)'
                    update_data['account'] = f"{proto}://{user}:{pwd}@{ip}:{port}"
                    logger.warning(
                        f"  [!] ДЕФОЛТНЫЕ УЧЁТКИ: {ip}:{port} "
                        f"({web_auth.get('vendor_matched')}) - "
                        f"{user}:{pwd_display}"
                    )
        
        # Формируем account из SSH/WinRM если нет web_auth account
        if 'account' not in update_data:
            auth_method = update_data.get('auth_method') or host_info.get('auth_method', '')
            if auth_method == 'ssh':
                update_data['account'] = f"ssh://{ip}:22"
            elif auth_method == 'winrm':
                update_data['account'] = f"winrm://{ip}:5985"
        
        self.storage.update_host(ip, update_data)
        
        logger.info(f"  OS: {update_data.get('os')}, Type: {update_data.get('type')}, "
                   f"Method: {update_data.get('fingerprint_method')}, "
                   f"Confidence: {update_data.get('fingerprint_confidence')}")
    
    def _fingerprint_all_hosts(self, force=False):
        """Fingerprint для всех хостов с deep_scan_status != 'completed'."""
        if not self.storage.data:
            logger.warning("Нет хостов в storage")
            return
        
        # Фильтруем хосты
        hosts_to_scan = []
        for ip, host_info in self.storage.data.items():
            deep_scan_status = host_info.get('deep_scan_status', '')
            
            if force or deep_scan_status != 'completed':
                hosts_to_scan.append(ip)
        
        if not hosts_to_scan:
            logger.info("Нет хостов для fingerprinting (все имеют deep_scan_status=completed)")
            return
        
        logger.info(f"Найдено хостов для fingerprinting: {len(hosts_to_scan)}")
        
        # Выполняем fingerprinting для каждого хоста
        for ip in hosts_to_scan:
            self._fingerprint_host(ip, force=True)  # force=True т.к. уже отфильтровали
        
        logger.info(f"Fingerprinting завершен для {len(hosts_to_scan)} хостов")
