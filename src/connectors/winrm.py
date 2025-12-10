import winrm
import warnings
import logging
import getpass
import os
import sys
from . import BaseConnector

logger = logging.getLogger(__name__)

# Suppress noisy errors from the library
logging.getLogger('winrm').setLevel(logging.CRITICAL)
logging.getLogger('requests_kerberos').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)

class WinRMConnector(BaseConnector):
    # Подменяем kerberos-авторизацию на GSSAPI (wheels для 3.13)
    _kerberos_patched = False

    @classmethod
    def _ensure_gssapi_auth(cls):
        if cls._kerberos_patched:
            return
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

    def connect(self, ip, user=None, password=None, key_path=None):
        if user and password:
            return self._connect_auth(ip, user, password)
        else:
            return self._connect_sso(ip)

    def _connect_auth(self, ip, user, password):
        self._ensure_gssapi_auth()
        try:
            session = winrm.Session(f'http://{ip}:5985/wsman', auth=(user, password), transport='ntlm')
            
            # Collect detailed OS information
            os_info = {}
            
            try:
                # Получаем название ОС
                logger.debug(f"[{ip}] AUTH: Executing OS Caption query...")
                result = session.run_ps('(Get-WmiObject Win32_OperatingSystem).Caption')
                logger.debug(f"[{ip}] AUTH: OS Caption - status_code={result.status_code}, stdout_len={len(result.std_out)}, stderr_len={len(result.std_err)}")
                if result.status_code == 0:
                    os_info['os'] = result.std_out.decode().strip()
                    logger.debug(f"[{ip}] AUTH: OS Caption result: '{os_info['os']}'")
                else:
                    logger.debug(f"[{ip}] AUTH: OS Caption failed, stderr: {result.std_err.decode()}")
                
                # Получаем версию ОС
                logger.debug(f"[{ip}] AUTH: Executing OS Version query...")
                result = session.run_ps('(Get-WmiObject Win32_OperatingSystem).Version')
                logger.debug(f"[{ip}] AUTH: OS Version - status_code={result.status_code}, stdout_len={len(result.std_out)}, stderr_len={len(result.std_err)}")
                if result.status_code == 0:
                    os_info['kernel_version'] = result.std_out.decode().strip()
                    logger.debug(f"[{ip}] AUTH: OS Version result: '{os_info['kernel_version']}'")
                else:
                    logger.debug(f"[{ip}] AUTH: OS Version failed, stderr: {result.std_err.decode()}")
                
                # Получаем hostname
                logger.debug(f"[{ip}] AUTH: Executing hostname command...")
                result = session.run_cmd('hostname')
                logger.debug(f"[{ip}] AUTH: hostname - status_code={result.status_code}, stdout_len={len(result.std_out)}, stderr_len={len(result.std_err)}")
                logger.debug(f"[{ip}] AUTH: hostname raw stdout: {result.std_out}")
                logger.debug(f"[{ip}] AUTH: hostname raw stderr: {result.std_err}")
                if result.status_code == 0:
                    os_info['hostname'] = result.std_out.decode().strip()
                    logger.debug(f"[{ip}] AUTH: hostname result: '{os_info['hostname']}'")
                else:
                    logger.debug(f"[{ip}] AUTH: hostname failed, stderr: {result.std_err.decode()}")
                
                # Получаем MAC адрес основного сетевого адаптера
                logger.debug(f"[{ip}] AUTH: Executing MAC address query...")
                result = session.run_ps('(Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1).MacAddress')
                logger.debug(f"[{ip}] AUTH: MAC query - status_code={result.status_code}, stdout_len={len(result.std_out)}, stderr_len={len(result.std_err)}")
                if result.status_code == 0:
                    mac = result.std_out.decode().strip()
                    if mac:
                        os_info['mac'] = mac.replace('-', ':')  # Конвертируем формат Windows в стандартный
                        logger.debug(f"[{ip}] AUTH: MAC address result: '{os_info['mac']}'")
                    else:
                        logger.debug(f"[{ip}] AUTH: MAC address query returned empty")
                else:
                    logger.debug(f"[{ip}] AUTH: MAC query failed, stderr: {result.std_err.decode()}")
                
                # Альтернативный способ для старых систем без Get-NetAdapter
                if 'mac' not in os_info:
                    logger.debug(f"[{ip}] AUTH: Trying alternative MAC query with getmac...")
                    result = session.run_cmd('getmac /v /fo csv | findstr /V "disabled"')
                    logger.debug(f"[{ip}] AUTH: getmac - status_code={result.status_code}, stdout_len={len(result.std_out)}")
                    if result.status_code == 0:
                        output = result.std_out.decode().strip()
                        # Парсим первый MAC из вывода
                        import re
                        mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', output)
                        if mac_match:
                            os_info['mac'] = mac_match.group(0).replace('-', ':')
                            logger.debug(f"[{ip}] AUTH: Alternative MAC result: '{os_info['mac']}'")
                
                logger.debug(f"[{ip}] AUTH: WinRM OS info collected: {os_info}")
                
            except Exception as e:
                logger.debug(f"[{ip}] AUTH: Failed to collect OS info via WinRM: {e}", exc_info=True)
                # Продолжаем без детальной информации
            
            # Формируем результат
            result = {
                'success': True,
                'method': 'winrm',
                'hostname': os_info.get('hostname', ''),
                'os': os_info.get('os', 'Windows'),
                'os_type': 'windows',
                'type': 'workstation',
                'user': user,
                'mac': os_info.get('mac', ''),
                'kernel_version': os_info.get('kernel_version', '')
            }
            
            return result
        except:
            return None
        return None

    def _connect_sso(self, ip):
        self._ensure_gssapi_auth()
        current_user = os.environ.get('USERNAME', getpass.getuser())
        
        # Try different transports that support SSO
        if sys.platform == 'win32':
            transports_to_try = ['credssp', 'kerberos']
        else:
            transports_to_try = ['kerberos']
        
        for transport in transports_to_try:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    
                    session = winrm.Session(
                        f'http://{ip}:5985/wsman', 
                        auth=(None, None), 
                        transport=transport
                    )
                    
                    # Collect detailed OS information
                    os_info = {}
                    
                    try:
                        # Получаем название ОС
                        logger.debug(f"[{ip}] SSO: Executing OS Caption query...")
                        result = session.run_ps('(Get-WmiObject Win32_OperatingSystem).Caption')
                        logger.debug(f"[{ip}] SSO: OS Caption - status_code={result.status_code}, stdout_len={len(result.std_out)}, stderr_len={len(result.std_err)}")
                        if result.status_code == 0:
                            os_info['os'] = result.std_out.decode().strip()
                            logger.debug(f"[{ip}] SSO: OS Caption result: '{os_info['os']}'")
                        else:
                            logger.debug(f"[{ip}] SSO: OS Caption failed, stderr: {result.std_err.decode()}")
                        
                        # Получаем версию ОС
                        logger.debug(f"[{ip}] SSO: Executing OS Version query...")
                        result = session.run_ps('(Get-WmiObject Win32_OperatingSystem).Version')
                        logger.debug(f"[{ip}] SSO: OS Version - status_code={result.status_code}, stdout_len={len(result.std_out)}, stderr_len={len(result.std_err)}")
                        if result.status_code == 0:
                            os_info['kernel_version'] = result.std_out.decode().strip()
                            logger.debug(f"[{ip}] SSO: OS Version result: '{os_info['kernel_version']}'")
                        else:
                            logger.debug(f"[{ip}] SSO: OS Version failed, stderr: {result.std_err.decode()}")
                        
                        # Получаем hostname
                        logger.debug(f"[{ip}] SSO: Executing hostname command...")
                        result = session.run_cmd('hostname')
                        logger.debug(f"[{ip}] SSO: hostname - status_code={result.status_code}, stdout_len={len(result.std_out)}, stderr_len={len(result.std_err)}")
                        logger.debug(f"[{ip}] SSO: hostname raw stdout: {result.std_out}")
                        logger.debug(f"[{ip}] SSO: hostname raw stderr: {result.std_err}")
                        if result.status_code == 0:
                            os_info['hostname'] = result.std_out.decode().strip()
                            logger.debug(f"[{ip}] SSO: hostname result: '{os_info['hostname']}'")
                        else:
                            logger.debug(f"[{ip}] SSO: hostname failed, stderr: {result.std_err.decode()}")
                        
                        # Получаем MAC адрес основного сетевого адаптера
                        logger.debug(f"[{ip}] SSO: Executing MAC address query...")
                        result = session.run_ps('(Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1).MacAddress')
                        logger.debug(f"[{ip}] SSO: MAC query - status_code={result.status_code}, stdout_len={len(result.std_out)}, stderr_len={len(result.std_err)}")
                        if result.status_code == 0:
                            mac = result.std_out.decode().strip()
                            if mac:
                                os_info['mac'] = mac.replace('-', ':')  # Конвертируем формат Windows в стандартный
                                logger.debug(f"[{ip}] SSO: MAC address result: '{os_info['mac']}'")
                            else:
                                logger.debug(f"[{ip}] SSO: MAC address query returned empty")
                        else:
                            logger.debug(f"[{ip}] SSO: MAC query failed, stderr: {result.std_err.decode()}")
                        
                        # Альтернативный способ для старых систем без Get-NetAdapter
                        if 'mac' not in os_info:
                            logger.debug(f"[{ip}] SSO: Trying alternative MAC query with getmac...")
                            result = session.run_cmd('getmac /v /fo csv | findstr /V "disabled"')
                            logger.debug(f"[{ip}] SSO: getmac - status_code={result.status_code}, stdout_len={len(result.std_out)}")
                            if result.status_code == 0:
                                output = result.std_out.decode().strip()
                                # Парсим первый MAC из вывода
                                import re
                                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', output)
                                if mac_match:
                                    os_info['mac'] = mac_match.group(0).replace('-', ':')
                                    logger.debug(f"[{ip}] SSO: Alternative MAC result: '{os_info['mac']}'")
                        
                        logger.debug(f"[{ip}] SSO: WinRM OS info collected: {os_info}")
                        
                    except Exception as e:
                        logger.debug(f"[{ip}] SSO: Failed to collect OS info via WinRM: {e}", exc_info=True)
                        # Продолжаем без детальной информации
                    
                    # Формируем результат
                    return {
                        'success': True,
                        'method': 'winrm',
                        'hostname': os_info.get('hostname', ''),
                        'os': os_info.get('os', 'Windows'),
                        'os_type': 'windows',
                        'type': 'workstation',
                        'user': current_user,
                        'auth_method': 'winrm_sso',
                        'mac': os_info.get('mac', ''),
                        'kernel_version': os_info.get('kernel_version', '')
                    }
            except Exception:
                continue  # Try next transport
        
        return None
