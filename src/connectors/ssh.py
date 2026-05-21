import getpass
import os
import re
import paramiko
import logging
from . import BaseConnector

logger = logging.getLogger(__name__)

# Подавляем traceback'и из внутреннего потока paramiko.transport
logging.getLogger('paramiko.transport').setLevel(logging.CRITICAL)


_HOSTNAME_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?$')

_SSH_CONFIG_CACHE = {'mtime': None, 'config': None}


def _load_ssh_config():
    """Кэшированная загрузка ~/.ssh/config. Возвращает None если файла нет/битый."""
    path = os.path.expanduser('~/.ssh/config')
    if not os.path.exists(path):
        return None
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None
    if _SSH_CONFIG_CACHE['mtime'] == mtime and _SSH_CONFIG_CACHE['config']:
        return _SSH_CONFIG_CACHE['config']
    try:
        cfg = paramiko.SSHConfig()
        with open(path, 'r', encoding='utf-8') as f:
            cfg.parse(f)
    except Exception as e:
        logger.debug(f"Failed to parse ~/.ssh/config: {e}")
        return None
    _SSH_CONFIG_CACHE['mtime'] = mtime
    _SSH_CONFIG_CACHE['config'] = cfg
    return cfg


def _resolve_ssh_config_target(ip, hostname=None):
    """Ищет настройки в ~/.ssh/config для ip → hostname.

    Возвращает dict с ключами {host, port, user, key_filenames, sock} или None,
    если ни один target не даёт значимого match (есть только глобальные defaults).
    """
    cfg = _load_ssh_config()
    if cfg is None:
        return None
    for candidate in (ip, hostname):
        if not candidate:
            continue
        try:
            opts = cfg.lookup(candidate)
        except Exception:
            continue
        # Match считается значимым, если есть user/identityfile/proxy — иначе это просто defaults
        has_signal = any(k in opts for k in ('user', 'identityfile', 'proxycommand', 'proxyjump'))
        if not has_signal:
            continue
        resolved = {
            'host': opts.get('hostname', candidate),
            'port': int(opts.get('port', 22)),
            'user': opts.get('user') or getpass.getuser(),
            'key_filenames': opts.get('identityfile') or None,
        }
        proxy_cmd = opts.get('proxycommand')
        if proxy_cmd:
            try:
                resolved['sock'] = paramiko.ProxyCommand(proxy_cmd)
            except Exception as e:
                logger.debug(f"Failed to init ProxyCommand for {candidate}: {e}")
        return resolved
    return None


def _sanitize_hostname(raw):
    if not raw:
        return ''
    value = raw.strip()
    if not value or len(value) > 253:
        return ''
    if any(ch in value for ch in '\n\r\t :;,<>"\'()[]{}=|/\\?'):
        return ''
    if '---' in value:
        return ''
    if not _HOSTNAME_RE.match(value):
        return ''
    return value


def _sanitize_single_line(raw, max_len=200):
    if not raw:
        return ''
    value = raw.strip()
    if not value:
        return ''
    if any(ch in value for ch in '\n\r\t'):
        return ''
    if len(value) > max_len:
        return ''
    return value


class SSHConnector(BaseConnector):
    def connect(self, ip, user, password=None, key_path=None, use_ssh_config=False, hostname=None):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if use_ssh_config:
                resolved = _resolve_ssh_config_target(ip, hostname)
                if not resolved:
                    return None
                connect_kwargs = {
                    'hostname': resolved['host'],
                    'port': resolved['port'],
                    'username': resolved['user'],
                    'timeout': 5,
                    'allow_agent': True,
                    'look_for_keys': True,
                }
                if resolved.get('key_filenames'):
                    connect_kwargs['key_filename'] = resolved['key_filenames']
                if resolved.get('sock') is not None:
                    connect_kwargs['sock'] = resolved['sock']
                client.connect(**connect_kwargs)
                user = resolved['user']
            elif key_path:
                client.connect(ip, username=user, key_filename=key_path, timeout=5)
            elif password:
                client.connect(ip, username=user, password=password, timeout=5)
            else:
                return None
            
            # Collect detailed OS information
            os_info = {}
            
            try:
                # Получаем тип ОС
                stdin, stdout, stderr = client.exec_command('uname -s', timeout=5)
                os_type = _sanitize_single_line(stdout.read().decode(), max_len=64)
                if os_type:
                    os_info['os'] = os_type

                # Получаем версию ядра
                stdin, stdout, stderr = client.exec_command('uname -r', timeout=5)
                kernel_version = _sanitize_single_line(stdout.read().decode(), max_len=128)
                if kernel_version:
                    os_info['kernel_version'] = kernel_version

                # Получаем hostname
                stdin, stdout, stderr = client.exec_command('hostname', timeout=5)
                hostname = _sanitize_hostname(stdout.read().decode())
                if hostname:
                    os_info['hostname'] = hostname

                # Получаем дистрибутив (может не сработать на всех системах)
                stdin, stdout, stderr = client.exec_command('cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d \'"\'', timeout=5)
                distribution = _sanitize_single_line(stdout.read().decode(), max_len=200)
                if distribution:
                    os_info['distribution'] = distribution
                
                # Получаем первый MAC адрес (не loopback)
                stdin, stdout, stderr = client.exec_command(
                    "cat /sys/class/net/*/address 2>/dev/null | grep -v '00:00:00:00:00:00' | head -n1",
                    timeout=5
                )
                mac = stdout.read().decode().strip()
                if not mac:
                    # Fallback через ip link
                    stdin, stdout, stderr = client.exec_command(
                        "ip link show 2>/dev/null | grep 'link/ether' | head -n1 | cut -d' ' -f6",
                        timeout=5
                    )
                    mac = stdout.read().decode().strip()
                # Валидация MAC
                import re
                if mac and re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac):
                    os_info['mac'] = mac.lower()
                    
                logger.debug(f"SSH OS info collected for {ip}: {os_info}")
                
            except Exception as e:
                logger.debug(f"Failed to collect OS info via SSH for {ip}: {e}")
                # Продолжаем без детальной информации
            
            client.close()
            
            # Формируем результат
            # ВАЖНО: НЕ сохраняем key_path для безопасности
            os_value = os_info.get('distribution') or os_info.get('os') or ''
            # Если ни один из идентификаторов Linux не прочитан корректно — не маркируем как linux,
            # это может быть embedded-устройство с собственным CLI (см. защиту от мусорных ответов выше).
            looks_like_linux = bool(
                os_info.get('os')
                or os_info.get('distribution')
                or os_info.get('kernel_version')
            )
            result = {
                'success': True,
                'auth_method': 'ssh',
                'hostname': os_info.get('hostname', ''),
                'os': os_value,
                'os_type': 'linux' if looks_like_linux else '',
                # type НЕ устанавливаем — его определяет fingerprint, коннектор не должен перезаписывать
                'user': user,
                'mac': os_info.get('mac', ''),
                'kernel_version': os_info.get('kernel_version', ''),
                'distribution': os_info.get('distribution', '')
            }

            return result
        except paramiko.AuthenticationException as e:
            # Ошибка аутентификации - протокол работает, но учетные данные неверные
            logger.debug(f"SSH authentication failed for {ip}: {e}")
            return {'auth_failed': True, 'error': 'Authentication failed'}
        except paramiko.ssh_exception.IncompatiblePeer as e:
            logger.warning(f"SSH {ip}: несовместимый SSH-сервер (старые алгоритмы ключей)")
            return None
        except paramiko.SSHException as e:
            logger.warning(f"SSH {ip}: ошибка протокола SSH: {e}")
            return None
        except (OSError, TimeoutError) as e:
            logger.debug(f"SSH {ip}: сетевая ошибка: {e}")
            return None
        except Exception as e:
            logger.warning(f"SSH {ip}: неожиданная ошибка: {type(e).__name__} - {e}")
            return None
