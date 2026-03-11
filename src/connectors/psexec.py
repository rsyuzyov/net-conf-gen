import logging
from pypsexec.client import Client
from smbprotocol.exceptions import SMBAuthenticationError, LogonFailure, SMBConnectionClosed
from . import BaseConnector

logger = logging.getLogger(__name__)

def _decode_output(data: bytes) -> str:
    """Декодирует вывод cmd.exe: utf-8 → cp866 → cp1251 → latin-1."""
    for enc in ('utf-8', 'cp866', 'cp1251', 'latin-1'):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode('utf-8', errors='replace')

class PsExecConnector(BaseConnector):
    def connect(self, ip, user, password=None, key_path=None):
        """Try connecting via PsExec (pypsexec) with credentials.
        
        Returns:
            dict | None: Result dict on success, None on failure.
        """
        if not user or not password:
            logger.debug(f"PsExec: User and password are required")
            return None

        # pypsexec works on Linux/Windows/Mac via Python
        # Logic: 
        # 1. Connect
        # 2. Authenticate
        # 3. Run command (hostname, os_info)
        
        c = None
        service_created = False
        try:
            logger.debug(f"PsExec: Connecting to {ip} as {user} (password length: {len(password) if password else 0})...")
            c = Client(ip, username=user, password=password, port=445)
            c.connect(timeout=5)
            
            try:
                # Создаем сервис один раз; удаляем в finally ниже
                c.create_service()
                service_created = True

                # Get Hostname
                stdout, stderr, rc = c.run_executable("cmd.exe", arguments="/c hostname")
                hostname = _decode_output(stdout).strip()

                if not hostname:
                    logger.debug("PsExec: Empty hostname returned")
                    return None

                logger.debug(f"PsExec: Got hostname: {hostname}")

                # Get OS Info
                stdout_os, stderr_os, rc_os = c.run_executable(
                    "cmd.exe",
                    arguments="/c wmic os get Caption /value",
                )
                os_output = _decode_output(stdout_os).strip()

                os_name = "Windows"
                for line in os_output.split('\n'):
                    if 'caption=' in line.lower():
                        os_name = line.split('=', 1)[1].strip()
                        break

                # Get kernel version
                stdout_ver, stderr_ver, rc_ver = c.run_executable(
                    "cmd.exe",
                    arguments="/c wmic os get Version /value",
                )
                version_output = _decode_output(stdout_ver).strip()
                
                kernel_version = ""
                for line in version_output.split('\n'):
                    if 'version=' in line.lower():
                        kernel_version = line.split('=', 1)[1].strip()
                        break
                # Get MAC address
                mac = ""
                try:
                    stdout_mac, stderr_mac, rc_mac = c.run_executable(
                        "cmd.exe",
                        arguments='/c getmac /fo csv /nh | findstr /V "disconnected"',
                    )
                    mac_output = _decode_output(stdout_mac).strip()
                    if mac_output:
                        import re
                        mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', mac_output)
                        if mac_match:
                            mac = mac_match.group(0).replace('-', ':').lower()
                except Exception as mac_err:
                    logger.debug(f"PsExec: Failed to get MAC for {ip}: {mac_err}")

                return {
                    'hostname': hostname,
                    'os': os_name,
                    'os_type': 'windows',
                    'type': 'workstation',
                    'user': user,
                    'auth_method': 'psexec',
                    'kernel_version': kernel_version,
                    'mac': mac
                }
            finally:
                if service_created:
                    try:
                        c.remove_service()
                    except Exception as cleanup_err:
                        logger.debug(f"PsExec: remove_service cleanup error for {ip}: {cleanup_err}")
                
                # Закрываем соединение
                if c:
                    try:
                        c.disconnect()
                    except Exception as disconnect_err:
                        logger.debug(f"PsExec: disconnect error for {ip}: {disconnect_err}")
        except (SMBAuthenticationError, LogonFailure) as e:
            logger.debug(f"PsExec: Authentication failed for {user}@{ip}: {type(e).__name__} - {e}")
            return {'auth_failed': True, 'error': 'Authentication failed'}
        except SMBConnectionClosed as e:
            logger.debug(f"PsExec: SMB connection closed for {ip}: {e}")
            return None
        except Exception as e:
            error_str = str(e)
            error_type = type(e).__name__
            # Проверяем, является ли это ошибкой аутентификации
            if any(keyword in error_str.lower() for keyword in ['authentication', 'credentials', 'logon', 'access denied', 'permission denied']):
                logger.debug(f"PsExec: Authentication error for {user}@{ip}: {e}")
                return {'auth_failed': True, 'error': 'Authentication failed'}
            # Известные инфраструктурные ошибки — понятные сообщения
            if 'Connection timeout' in error_str:
                logger.warning(f"PsExec {ip}: таймаут SMB-подключения (хост не отвечает на SMB)")
            elif 'encryption is required' in error_str:
                logger.warning(f"PsExec {ip}: хост требует SMB-шифрование (не поддерживается клиентом)")
            elif 'PIPE_BROKEN' in error_str or 'pipe' in error_str.lower():
                logger.warning(f"PsExec {ip}: соединение разорвано хостом (нет прав или политика)")
            else:
                logger.warning(f"PsExec {ip}: ошибка подключения: {error_type} - {error_str}")
                import traceback
                logger.debug(f"PsExec traceback: {traceback.format_exc()}")
            return None

