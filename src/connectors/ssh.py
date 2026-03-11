import paramiko
import logging
from . import BaseConnector

logger = logging.getLogger(__name__)

# Подавляем traceback'и из внутреннего потока paramiko.transport
logging.getLogger('paramiko.transport').setLevel(logging.CRITICAL)

class SSHConnector(BaseConnector):
    def connect(self, ip, user, password=None, key_path=None):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            # Connect with password or key
            if key_path:
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
                os_type = stdout.read().decode().strip()
                if os_type:
                    os_info['os'] = os_type
                
                # Получаем версию ядра
                stdin, stdout, stderr = client.exec_command('uname -r', timeout=5)
                kernel_version = stdout.read().decode().strip()
                if kernel_version:
                    os_info['kernel_version'] = kernel_version
                
                # Получаем hostname
                stdin, stdout, stderr = client.exec_command('hostname', timeout=5)
                hostname = stdout.read().decode().strip()
                if hostname:
                    os_info['hostname'] = hostname
                
                # Получаем дистрибутив (может не сработать на всех системах)
                stdin, stdout, stderr = client.exec_command('cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d \'"\'', timeout=5)
                distribution = stdout.read().decode().strip()
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
            result = {
                'success': True,
                'auth_method': 'ssh',
                'hostname': os_info.get('hostname', ''),
                'os': os_info.get('distribution', os_info.get('os', 'Linux')),
                'os_type': 'linux',
                'type': 'server',
                'user': user,
                'mac': os_info.get('mac', ''),
                'kernel_version': os_info.get('kernel_version', '')
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
