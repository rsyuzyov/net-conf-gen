import json
import winrm
import warnings
import logging
import getpass
import os
import sys
import ctypes
import time
from . import BaseConnector
from src.utils import decode_windows_output as _decode_output

logger = logging.getLogger(__name__)

# Suppress noisy errors from the library
logging.getLogger('winrm').setLevel(logging.CRITICAL)
logging.getLogger('requests_kerberos').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)

class WinRMConnector(BaseConnector):
    # Подменяем kerberos-авторизацию на GSSAPI (wheels для 3.13)
    _kerberos_patched = False
    _winkerberos_encoding_patched = False

    @classmethod
    def _patch_winkerberos_encoding(cls):
        """Патчим winkerberos для правильной кодировки ошибок SSPI"""
        if cls._winkerberos_encoding_patched:
            return
        try:
            import winkerberos
            original_step = winkerberos.authGSSClientStep
            
            def patched_step(state, challenge):
                try:
                    return original_step(state, challenge)
                except Exception as e:
                    error_msg = str(e)
                    if '�' in error_msg and 'SSPI:' in error_msg:
                        import re
                        match = re.search(r'0x[0-9A-Fa-f]+', error_msg)
                        error_code = int(match.group(), 16) if match else 0x80090308
                        
                        buffer = ctypes.create_unicode_buffer(512)
                        result = ctypes.windll.kernel32.FormatMessageW(
                            0x00001000, None, error_code, 0, buffer, 512, None
                        )
                        if result:
                            fixed_msg = f"authGSSClientStep() failed: ('SSPI: InitializeSecurityContext: {buffer.value.strip()}',)"
                            raise type(e)(fixed_msg) from e
                    raise
            
            winkerberos.authGSSClientStep = patched_step
            cls._winkerberos_encoding_patched = True
        except Exception as e:
            logger.debug(f"winkerberos encoding patch skipped: {e}")

    @classmethod
    def _ensure_gssapi_auth(cls):
        if cls._kerberos_patched:
            return
        
        # Патчим winkerberos для правильной кодировки
        cls._patch_winkerberos_encoding()
        try:
            from requests.auth import AuthBase
            from requests_gssapi import HTTPSPNEGOAuth
            import winrm.transport as wt
            # Повторно используем константу REQUIRED из vendored requests_kerberos
            REQUIRED = getattr(wt, "REQUIRED", 1)

            class GSSAPIKerberosAuth(AuthBase):
                # Шифрование WinRM через SPNEGO не поддерживаем, поэтому False
                winrm_encryption_available = False

                def __init__(self, mutual_authentication=REQUIRED, service="HTTP", delegate=False,
                             force_preemptive=False, principal=None, hostname_override=None,
                             sanitize_mutual_error_response=True, send_cbt=True):
                    # HTTPSPNEGOAuth ожидает host/service, делегирование и principal
                    self._auth = HTTPSPNEGOAuth(
                        principal=principal,
                        hostname_override=hostname_override,
                        delegate=delegate,
                        opportunistic_auth=force_preemptive,
                        service=service,
                        mutual_authentication=True if mutual_authentication == REQUIRED else False,
                    )

                def __call__(self, r):
                    return self._auth(r)

            wt.HTTPKerberosAuth = GSSAPIKerberosAuth
            wt.HAVE_KERBEROS = True
            cls._kerberos_patched = True
        except Exception:
            # Оставляем поведение по умолчанию, если gssapi не установлена
            pass

    def _is_permanent_auth_error(self, detail):
        detail = (detail or '').lower()
        return any(token in detail for token in (
            'specified credentials were rejected',
            'logon failure',
            'unknown user name or bad password',
            'unauthorized',
            '401',
        ))

    def _test_connection(self, session):
        """Проверяет работоспособность подключения простой командой."""
        try:
            result = session.run_cmd('echo test')
            if result.status_code == 0:
                return True, ''

            stderr = _decode_output(result.std_err).strip()
            stdout = _decode_output(result.std_out).strip()
            detail = stderr or stdout or f'Command returned status {result.status_code}'
            return False, detail
        except Exception as e:
            return False, str(e)

    def connect(self, ip, user=None, password=None, key_path=None):
        self._ensure_gssapi_auth()
        
        if user and password:
            # NTLM аутентификация
            last_error = ''
            for attempt in range(2):
                try:
                    session = winrm.Session(f'http://{ip}:5985/wsman', auth=(user, password), transport='ntlm')

                    ok, detail = self._test_connection(session)
                    if not ok:
                        last_error = detail or 'Connection test failed'
                        if self._is_permanent_auth_error(last_error) or attempt == 1:
                            return {'auth_failed': True, 'error': last_error}
                        time.sleep(0.5)
                        continue

                    os_info = self._get_host_info(ip, session)
                    logger.info(f"{ip}: Успешное подключение через winrm (NTLM) user={user}")

                    return {
                        'success': True,
                        'auth_method': 'winrm',
                        'hostname': os_info['hostname'],
                        'os': os_info.get('os', 'Windows'),
                        'os_type': 'windows',
                        'type': 'workstation',
                        'user': user,
                        'mac': os_info.get('mac', ''),
                        'kernel_version': os_info.get('kernel_version', '')
                    }
                except Exception as e:
                    error_str = str(e)
                    lowered = error_str.lower()
                    if any(kw in lowered for kw in ['401', 'unauthorized', 'authentication', 'credentials', 'logon failure']):
                        return {'auth_failed': True, 'error': error_str}
                    last_error = error_str
                    if attempt == 1:
                        return {'error': f'Connection error: {error_str}'}
                    time.sleep(0.5)

            return {'auth_failed': True, 'error': last_error or 'Connection test failed'}
        
        # SSO аутентификация
        user = os.environ.get('USERNAME', getpass.getuser())
        transports = ['credssp', 'kerberos'] if sys.platform == 'win32' else ['kerberos']
        
        for transport in transports:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    session = winrm.Session(f'http://{ip}:5985/wsman', auth=(None, None), transport=transport)
                    
                    ok, detail = self._test_connection(session)
                    if not ok:
                        logger.debug(f"Пробуем WinRM SSO для {ip} с {transport}... {detail or 'тест подключения не прошёл'}")
                        continue
                    
                    os_info = self._get_host_info(ip, session)
                    logger.info(f"{ip}: Успешное подключение через winrm (SSO) user={user}")
                    
                    return {
                        'success': True,
                        'auth_method': 'winrm',
                        'hostname': os_info['hostname'],
                        'os': os_info.get('os', 'Windows'),
                        'os_type': 'windows',
                        'type': 'workstation',
                        'user': user,
                        'mac': os_info.get('mac', ''),
                        'kernel_version': os_info.get('kernel_version', '')
                    }
            except Exception as e:
                error_str = str(e).lower()
                logger.debug(f"Пробуем WinRM SSO для {ip} с {transport}... {e}")
                if any(kw in error_str for kw in ['401', 'unauthorized', 'authentication', 'credentials', 'logon failure']):
                    if transport == transports[-1]:
                        return {'auth_failed': True, 'error': f'Authentication failed: {str(e)}'}
        
        return {'error': 'All transports failed'}
    
    # PowerShell-скрипт собирает всё разом и возвращает JSON, где не-ASCII
    # эскейпится как \uXXXX. Это переживает любые проблемы кодировки stdout/SOAP
    # транспорта.
    #
    # Имя ОС читаем из реестра (ProductName в CurrentVersion), а не из
    # Win32_OperatingSystem.Caption: на локализованной Windows 11 Caption
    # приходит с символами '?' вместо национальных букв (известная проблема
    # CIM/WMI с длинными локализованными строками), а ProductName хранится в
    # реестре корректно.
    _HOST_INFO_PS = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$reg=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';"
        "$os=Get-CimInstance Win32_OperatingSystem;"
        "$mac=(Get-NetAdapter|Where-Object Status -eq 'Up'|Select-Object -First 1).MacAddress;"
        "$result=@{"
        "hostname=$env:COMPUTERNAME;"
        "caption=$(if ($reg.ProductName) {$reg.ProductName} else {$os.Caption});"
        "version=$os.Version;"
        "mac=$mac"
        "};"
        "ConvertTo-Json -Compress -InputObject $result"
    )

    def _parse_host_info_json(self, raw):
        text = _decode_output(raw).strip()
        if not text:
            return {}
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            logger.debug("WinRM JSON parse failed: %r", text[:200])
            return {}
        if not isinstance(data, dict):
            return {}
        return data

    def _get_host_info(self, ip, session):
        """Получает информацию о хосте. Подключение уже проверено."""
        os_info = {}

        result = session.run_ps(self._HOST_INFO_PS)
        if result.status_code == 0:
            data = self._parse_host_info_json(result.std_out)
            hostname = str(data.get('hostname', '') or '').strip()
            caption = str(data.get('caption', '') or '').strip()
            version = str(data.get('version', '') or '').strip()
            mac = str(data.get('mac', '') or '').strip()
            if hostname:
                os_info['hostname'] = hostname
            if caption:
                os_info['os'] = caption
            if version:
                os_info['kernel_version'] = version
            if mac:
                os_info['mac'] = mac.replace('-', ':')

        # Fallback на старые системы без CIM / без Get-NetAdapter — тоже через JSON.
        if 'hostname' not in os_info:
            result = session.run_cmd('hostname')
            if result.status_code == 0:
                hostname = _decode_output(result.std_out).strip()
                if hostname:
                    os_info['hostname'] = hostname

        if 'mac' not in os_info:
            result = session.run_cmd('getmac /v /fo csv | findstr /V "disabled"')
            if result.status_code == 0:
                import re
                mac_match = re.search(
                    r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})',
                    _decode_output(result.std_out),
                )
                if mac_match:
                    os_info['mac'] = mac_match.group(0).replace('-', ':')

        return os_info
