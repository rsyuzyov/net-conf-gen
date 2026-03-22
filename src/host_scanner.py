"""Сканер хостов — единый модуль для сбора данных.

Заменяет fingerprint.py + connection_check.py.
Выполняет стратегию сканирования для каждого хоста
в зависимости от его категории.
"""
import socket
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.credentials import CredentialManager
from src.scan_strategies import get_strategy
from src.vendor_db import (
    determine_vendor_model, classify_windows_type,
    detect_camera_from_title, is_printer_by_hostname,
    is_printer_by_title, CAMERA_PORTS, NETWORK_VENDORS,
    normalize_mac_vendor,
)
from src.utils import normalize_os_name
from src.probes.http import scan_http_ports
from src.probes.ssl_cert import scan_ssl_ports
from src.probes.banner import scan_banners
from src.connectors import snmp as snmp_connector

logger = logging.getLogger(__name__)

# MAC vendor lookup (опционально)
try:
    from mac_vendor_lookup import MacLookup
    _mac_lookup = MacLookup()
    try:
        _mac_lookup.update_vendors()
    except Exception:
        pass
except ImportError:
    _mac_lookup = None


def _get_vendor_from_mac(mac):
    """Получить vendor по MAC."""
    if not mac or not _mac_lookup:
        return ''
    try:
        return _mac_lookup.lookup(mac)
    except Exception:
        return ''


def _reverse_dns(ip):
    """Reverse DNS lookup."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname.split('.')[0]
    except socket.herror:
        return ''
    except Exception as e:
        logger.debug(f"Reverse DNS failed for {ip}: {e}")
        return ''


class HostScanner:
    """Сканер хостов. Выполняет стратегию сканирования по категории."""

    def __init__(self, storage, credentials, concurrency=20):
        self.storage = storage
        self.credential_manager = CredentialManager(credentials)
        self.concurrency = concurrency
        # Lazy-init коннекторов
        self._ssh = None
        self._winrm = None
        self._psexec = None

    @property
    def ssh_connector(self):
        if self._ssh is None:
            from src.connectors.ssh import SSHConnector
            self._ssh = SSHConnector()
        return self._ssh

    @property
    def winrm_connector(self):
        if self._winrm is None:
            from src.connectors.winrm import WinRMConnector
            self._winrm = WinRMConnector()
        return self._winrm

    @property
    def psexec_connector(self):
        if self._psexec is None:
            from src.connectors.psexec import PsExecConnector
            self._psexec = PsExecConnector()
        return self._psexec

    # ========== Основной метод ==========

    def scan_host(self, ip, category, force=False):
        """Сканировать один хост по стратегии для его категории.

        Args:
            ip: IP адрес
            category: категория из classifier (windows, linux, printer, etc.)
            force: принудительное сканирование
        """
        host_info = self.storage.get_host(ip)
        if not host_info:
            logger.error(f"Хост {ip} не найден в storage")
            return

        if not force and host_info.get('scan_status') == 'completed':
            logger.debug(f"{ip}: уже просканирован, пропускаем")
            return

        logger.info(f"Сканирование {ip} (категория: {category})")

        open_ports = host_info.get('open_ports', [])
        strategy = get_strategy(category)

        update_data = {
            'category': category,
            'auth_methods': [],
            'auth_attempts': [],
        }

        # Обновляем vendor через MAC если ещё не определён
        if not host_info.get('vendor') and host_info.get('mac'):
            mac_vendor = _get_vendor_from_mac(host_info['mac'])
            if mac_vendor:
                update_data['vendor'] = normalize_mac_vendor(mac_vendor)

        # Выполняем шаги стратегии
        for step in strategy:
            success = self._execute_step(step, ip, host_info, open_ports, update_data)
            if success and step.stop_on_success:
                logger.info(f"  {ip}: {step.action} успешен, остальные шаги пропускаем")
                break

        # ===== Post-processing =====
        self._post_process(ip, host_info, open_ports, update_data, category)

        self.storage.update_host(ip, update_data)
        logger.info(f"  {ip}: OS={update_data.get('os')}, type={update_data.get('type')}, "
                    f"scan_status={update_data.get('scan_status', 'scanned')}")

    # ========== Выполнение шагов ==========

    def _execute_step(self, step, ip, host_info, open_ports, update_data):
        """Выполнить один шаг стратегии. Возвращает True при успехе."""
        action = step.action
        try:
            if action == 'reverse_dns':
                return self._step_reverse_dns(ip, host_info, update_data)
            elif action == 'connect_ssh':
                return self._step_connect(ip, 'ssh', open_ports, update_data)
            elif action == 'connect_winrm':
                return self._step_connect(ip, 'winrm', open_ports, update_data)
            elif action == 'connect_psexec':
                return self._step_connect(ip, 'psexec', open_ports, update_data)
            elif action == 'snmp':
                return self._step_snmp(ip, update_data)
            elif action == 'http_title':
                return self._step_http(ip, open_ports, update_data, deep=False)
            elif action == 'http_deep':
                return self._step_http(ip, open_ports, update_data, deep=True)
            elif action == 'ssl_cert':
                return self._step_ssl(ip, open_ports, update_data)
            elif action == 'banner':
                return self._step_banner(ip, open_ports, update_data)
            else:
                logger.warning(f"Неизвестный шаг: {action}")
                return False
        except Exception as e:
            logger.error(f"Ошибка при выполнении {action} для {ip}: {e}")
            return False

    def _step_reverse_dns(self, ip, host_info, update_data):
        """Reverse DNS."""
        if host_info.get('hostname') or update_data.get('hostname'):
            return False
        hostname = _reverse_dns(ip)
        if hostname:
            update_data['hostname'] = hostname
            logger.info(f"  Hostname via DNS: {hostname}")
            return True
        return False

    def _step_connect(self, ip, protocol, open_ports, update_data):
        """Попытка подключения через протокол (SSH/WinRM/PsExec).

        Единая логика вместо 4 copy-paste блоков.
        """
        # Проверяем, открыт ли нужный порт
        required_port = {'ssh': 22, 'winrm': 5985, 'psexec': 445}
        port = required_port.get(protocol)
        if port and port not in (open_ports or []):
            return False

        connector = self._get_connector(protocol)
        if not connector:
            return False

        # Определяем type credentials для поиска
        cred_type = {'ssh': 'ssh', 'winrm': 'winrm', 'psexec': 'winrm'}[protocol]

        success = False

        # WinRM: сначала SSO
        if protocol == 'winrm':
            success = self._try_single_connect(
                connector, ip, protocol, user=None, password=None,
                update_data=update_data, is_sso=True
            )
            if success:
                return True

        # Перебор credentials
        for cred in self.credential_manager:
            if cred.get('type') != cred_type:
                continue

            user = cred.get('user')

            if protocol == 'ssh':
                # SSH: сначала ключи, потом пароли
                for key_path in cred.get('key_paths', []):
                    if self._try_single_connect(
                        connector, ip, 'ssh_key', user=user,
                        key_path=key_path, update_data=update_data
                    ):
                        success = True
                        break

                if not success:
                    for password in cred.get('passwords', []):
                        if self._try_single_connect(
                            connector, ip, protocol, user=user,
                            password=password, update_data=update_data
                        ):
                            success = True
                            break
            else:
                # WinRM / PsExec: только пароли
                for password in cred.get('passwords', []):
                    if self._try_single_connect(
                        connector, ip, protocol, user=user,
                        password=password, update_data=update_data
                    ):
                        success = True
                        break

            if success:
                break

        return success

    def _try_single_connect(self, connector, ip, method, user=None,
                            password=None, key_path=None,
                            update_data=None, is_sso=False):
        """Одна попытка подключения. Возвращает True при успехе."""
        try:
            info = connector.connect(ip, user, password=password, key_path=key_path)
        except Exception as e:
            logger.debug(f"{ip}: {method} ошибка: {e}")
            update_data.setdefault('auth_attempts', []).append({
                'method': method,
                'user': user or '',
                'status': 'error',
                'error': str(e)
            })
            return False

        if not info:
            update_data.setdefault('auth_attempts', []).append({
                'method': method,
                'user': user or '',
                'status': 'failed',
                'error': 'No response'
            })
            return False

        # Протокол работает, но auth не прошёл
        if info.get('auth_failed'):
            base_method = method.replace('_key', '')
            if base_method not in update_data.get('auth_methods', []):
                update_data.setdefault('auth_methods', []).append(base_method)
            update_data.setdefault('auth_attempts', []).append({
                'method': method,
                'user': user or info.get('user', ''),
                'status': 'auth_failed',
                'error': info.get('error', '')
            })
            return False

        # Успешное подключение
        if info.get('success') or info.get('hostname'):
            # Нормализация OS
            if 'os' in info:
                info['os'] = normalize_os_name(info['os'])

            update_data.update(info)
            update_data['scan_status'] = 'completed'

            base_method = method.replace('_key', '')
            if base_method not in update_data.get('auth_methods', []):
                update_data.setdefault('auth_methods', []).append(base_method)
            if user:
                update_data['user'] = user
            update_data.setdefault('auth_attempts', []).append({
                'method': method,
                'user': user or info.get('user', ''),
                'status': 'success'
            })
            logger.info(f"  {ip}: Подключение через {method} — OK")
            return True

        return False

    def _step_snmp(self, ip, update_data):
        """SNMP опрос."""
        snmp_info = snmp_connector.snmp_get_info(ip, timeout=1)
        if not snmp_info:
            return False

        update_data['snmp_info'] = snmp_info

        if snmp_info.get('sysDescr'):
            update_data['snmp_sys_descr'] = snmp_info['sysDescr']

        # sysName → hostname
        sys_name = snmp_info.get('sysName', '')
        if sys_name and not update_data.get('hostname'):
            update_data['hostname'] = sys_name.split('.')[0]
            logger.info(f"  Hostname via SNMP: {update_data['hostname']}")

        # sysLocation → location
        if snmp_info.get('sysLocation'):
            update_data['location'] = snmp_info['sysLocation']

        # Парсинг ОС/vendor/model из sysDescr
        snmp_os = snmp_connector.parse_snmp_os(snmp_info)
        if snmp_os:
            if snmp_os.get('vendor'):
                update_data.setdefault('vendor', snmp_os['vendor'])
            if snmp_os.get('model'):
                update_data.setdefault('model', snmp_os['model'])
            if snmp_os.get('firmware'):
                update_data['firmware'] = snmp_os['firmware']
            if snmp_os.get('snmp_enterprise_vendor'):
                update_data['snmp_enterprise_vendor'] = snmp_os['snmp_enterprise_vendor']

            # OS/type — обновляем если текущее значение generic
            current_os = update_data.get('os', '')
            generic = ('', 'Unknown', 'Linux/Unix', 'IP Camera', 'Printer',
                       'Network Device', 'Network Equipment', 'SNMP Device')
            if current_os in generic and snmp_os.get('os'):
                update_data['os'] = snmp_os['os']
                if snmp_os.get('os_type'):
                    update_data['os_type'] = snmp_os['os_type']
                if snmp_os.get('type'):
                    update_data['type'] = snmp_os['type']
                logger.info(f"  OS via SNMP: {snmp_os['os']}")

        return True

    def _step_http(self, ip, open_ports, update_data, deep=False):
        """HTTP title/body сканирование."""
        result = scan_http_ports(ip, open_ports, deep=deep)

        if not result['titles']:
            return False

        update_data['http_titles'] = result['titles']
        if result['primary_title']:
            update_data['http_title'] = result['primary_title']

        # Классификация по body (deep analysis)
        if deep and result['bodies']:
            self._classify_from_http(update_data, result['titles'], result['bodies'])

        return True

    def _step_ssl(self, ip, open_ports, update_data):
        """SSL cert сканирование."""
        certs = scan_ssl_ports(ip, open_ports)
        if not certs:
            return False

        update_data['ssl_certs'] = certs
        primary_port = 443 if 443 in certs else min(certs.keys())
        update_data['ssl_cert'] = certs[primary_port]

        # Hostname из CN
        cert = certs[primary_port]
        cn = cert.get('cn', '')
        if cn and not update_data.get('hostname'):
            if not cn.startswith('*') and not re.match(r'^\d+\.\d+\.\d+\.\d+$', cn):
                update_data['hostname'] = cn.split('.')[0]
                logger.info(f"  Hostname via SSL CN: {update_data['hostname']}")

        return True

    def _step_banner(self, ip, open_ports, update_data):
        """Banner grabbing."""
        banners = scan_banners(ip, open_ports, extra=True)
        if not banners:
            return False

        update_data['extra_banners'] = banners

        # SSH banner → Linux
        if 22 in banners and 'OpenSSH' in banners[22]:
            update_data.setdefault('os', 'Linux/Unix')
            update_data.setdefault('os_type', 'linux')

        # RTSP → camera
        if 554 in banners:
            update_data.setdefault('type', 'camera')
            update_data.setdefault('os', 'IP Camera')

        # Telnet → network
        if 23 in banners and not update_data.get('type'):
            update_data['type'] = 'network'

        return True

    # ========== HTTP deep classification ==========

    def _classify_from_http(self, update_data, titles, bodies):
        """Классификация устройства по HTTP body (для unknown/network)."""
        all_titles = ' '.join(titles.values()).lower()
        all_bodies = ' '.join(bodies.values()).lower()

        # TP-Link
        is_tplink = (
            'tp-link' in all_bodies or 'tplinkwifi' in all_bodies or
            'tpencrypt' in all_bodies or
            ('$.su.app' in all_bodies and '$.su.language' in all_bodies)
        )
        if is_tplink:
            update_data['type'] = 'network'
            update_data['os'] = 'Network Equipment'
            update_data.setdefault('vendor', 'TP-Link')
            model_match = re.search(
                r'(TL-[A-Z]{1,3}\d{2,5}[A-Z]?|Archer\s*[A-Z]\d{1,4}|Deco\s*[A-Z]\d{1,4})',
                ' '.join(bodies.values()), re.IGNORECASE)
            update_data.setdefault('model', model_match.group(1) if model_match else 'TP-Link Router')
            return

        # D-Link
        if 'd-link' in all_bodies or 'd-link' in all_titles:
            update_data['type'] = 'network'
            update_data['os'] = 'Network Equipment'
            update_data.setdefault('vendor', 'D-Link')
            return

        # ASUS
        if 'main_login.asp' in all_bodies:
            update_data['type'] = 'network'
            update_data['os'] = 'Network Equipment'
            update_data.setdefault('vendor', 'ASUS')
            model_match = re.search(
                r'(RT-[A-Z]{1,4}\d{2,5}[A-Z]?|GT-[A-Z]{1,4}\d{2,5})',
                ' '.join(bodies.values()), re.IGNORECASE)
            update_data.setdefault('model', model_match.group(1) if model_match else 'ASUS Router')
            return

        # Kyocera
        if 'kyocera' in all_bodies:
            update_data['type'] = 'printer'
            update_data['os'] = 'Printer'
            update_data.setdefault('vendor', 'Kyocera')
            return

        # Canon
        canon_match = re.search(r'(LBP\d{3,4}\w*|MF\d{3,4}\w*|iR-ADV\s*\w+)', all_titles, re.IGNORECASE)
        if canon_match:
            update_data['type'] = 'printer'
            update_data['os'] = 'Printer'
            update_data.setdefault('vendor', 'Canon')
            update_data.setdefault('model', canon_match.group(1).upper())
            return

        # NanoKVM
        if 'nanokvm' in all_titles:
            update_data['type'] = 'ipkvm'
            update_data['os'] = 'NanoKVM'
            update_data.setdefault('vendor', 'Sipeed')
            update_data['model'] = 'NanoKVM'
            return

        # Proxmox
        if 'proxmox' in all_titles:
            update_data['type'] = 'server'
            update_data['os'] = 'Proxmox VE'
            update_data.setdefault('vendor', 'Proxmox')
            return

        # Камеры
        if 'rsvideoocx' in all_bodies:
            update_data['type'] = 'camera'
            update_data['os'] = 'IP Camera'
            return
        for kw, vendor in [('netsurveillance', 'XMEye'), ('webpackspa', 'Hikvision'),
                           ('web viewer', 'Samsung/Hanwha')]:
            if kw in all_titles:
                update_data['type'] = 'camera'
                update_data['os'] = 'IP Camera'
                update_data.setdefault('vendor', vendor)
                return

        # SSL-based (Kerio, Proxmox)
        ssl_certs = update_data.get('ssl_certs', {})
        for port, cert in ssl_certs.items():
            issuer = cert.get('issuer_cn', '').lower()
            cn = cert.get('cn', '').lower()
            if 'kerio' in issuer or 'kerio' in cn:
                update_data['type'] = 'network'
                update_data['os'] = 'Kerio Control'
                update_data.setdefault('vendor', 'Kerio')
                return

        # Серверные приложения
        for kw, model_name in [('grafana', 'Grafana'), ('kibana', 'Kibana'),
                                ('zabbix', 'Zabbix'), ('webmin', 'Webmin')]:
            if kw in all_titles:
                update_data.setdefault('type', 'server')
                update_data.setdefault('model', model_name)
                return

        # NAS
        if 'synology' in all_titles:
            update_data['type'] = 'server'
            update_data.setdefault('vendor', 'Synology')
            update_data.setdefault('model', 'DiskStation')
            return
        if 'qnap' in all_titles:
            update_data['type'] = 'server'
            update_data.setdefault('vendor', 'QNAP')
            return

        # UniFi
        if 'unifi' in all_titles or 'ubiquiti' in all_titles:
            update_data.setdefault('vendor', 'Ubiquiti')
            update_data.setdefault('type', 'network')
            return

    # ========== Post-processing ==========

    def _post_process(self, ip, host_info, open_ports, update_data, category):
        """Пост-обработка: нормализация, уточнение type, vendor/model."""

        # Нормализация OS
        if 'os' in update_data:
            update_data['os'] = normalize_os_name(update_data['os'])

        # Если нет scan_status — определяем по auth
        if 'scan_status' not in update_data:
            if update_data.get('auth_methods'):
                update_data['scan_status'] = 'auth_available_no_access'
            elif category in ('printer', 'camera', 'network', 'mikrotik'):
                update_data['scan_status'] = 'scanned'
            else:
                update_data['scan_status'] = 'scanned_no_access'

        # HTTP title → printer/camera уточнение
        http_title = update_data.get('http_title', '')
        hostname = update_data.get('hostname', '') or host_info.get('hostname', '')

        if is_printer_by_hostname(hostname) or is_printer_by_title(http_title):
            update_data['type'] = 'printer'
            update_data['os'] = 'Printer'
            update_data.setdefault('os_type', 'linux')

        is_cam, cam_vendor, cam_model = detect_camera_from_title(http_title)
        if (is_cam or (CAMERA_PORTS & set(open_ports))) and update_data.get('type') != 'printer':
            update_data['type'] = 'camera'
            update_data['os'] = 'IP Camera'
            update_data.setdefault('os_type', 'linux')
            if cam_vendor:
                update_data.setdefault('vendor', cam_vendor)
            if cam_model:
                update_data.setdefault('model', cam_model)

        # Windows: уточнение server vs workstation
        os_str = update_data.get('os', '')
        is_windows = (
            update_data.get('os_type') == 'windows'
            or ('windows' in os_str.lower() and {135, 445} & set(open_ports))
        )
        if is_windows:
            update_data['os_type'] = 'windows'
            update_data['type'] = classify_windows_type(
                hostname, open_ports, os_str
            )

        # Network equipment fallback
        vendor = update_data.get('vendor', '') or host_info.get('vendor', '')
        if update_data.get('type') in ('unknown', None) and vendor in NETWORK_VENDORS:
            update_data['type'] = 'network'
            if not update_data.get('os') or update_data.get('os') in ('Linux/Unix', 'Unknown', ''):
                update_data['os'] = 'Network Equipment'

        # Заполняем os_type/type по умолчанию из категории
        if not update_data.get('os_type'):
            type_map = {
                'windows': 'windows',
                'linux': 'linux',
                'mikrotik': 'linux',
                'printer': 'linux',
                'camera': 'linux',
                'network': 'linux',
            }
            update_data['os_type'] = type_map.get(category, 'linux')

        if not update_data.get('type') or update_data['type'] == 'unknown':
            type_map = {
                'windows': 'workstation',
                'linux': 'server',
                'mikrotik': 'mikrotik',
                'printer': 'printer',
                'camera': 'camera',
                'network': 'network',
            }
            if category in type_map:
                update_data['type'] = type_map[category]

        # Vendor/model (единый вызов)
        determine_vendor_model(update_data, host_info)

    # ========== Коннектор helpers ==========

    def _get_connector(self, protocol):
        """Получить коннектор по протоколу."""
        if protocol in ('ssh', 'ssh_key'):
            return self.ssh_connector
        elif protocol == 'winrm':
            return self.winrm_connector
        elif protocol == 'psexec':
            return self.psexec_connector
        return None

    # ========== Массовое сканирование ==========

    def scan_all(self, classifications, force=False):
        """Сканировать все хосты параллельно.

        Args:
            classifications: dict {ip: category}
            force: принудительное сканирование
        """
        if not classifications:
            logger.warning("Нет хостов для сканирования")
            return

        total = len(classifications)
        logger.info(f"Сканирование {total} хостов...")

        completed = 0
        max_workers = min(self.concurrency, total)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.scan_host, ip, category, force): ip
                for ip, category in classifications.items()
            }
            for future in as_completed(futures):
                ip = futures[future]
                completed += 1
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Ошибка сканирования {ip}: {e}")
                if completed % 10 == 0 or completed == total:
                    logger.info(f"Прогресс: {completed}/{total}")

        self.storage.flush()
        logger.info(f"Сканирование завершено: {total} хостов")
