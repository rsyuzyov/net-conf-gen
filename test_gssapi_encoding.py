#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тест кодировки ошибок gssapi/SSPI"""

import sys
import ctypes
from ctypes import wintypes

# Патч для winkerberos - перехватываем вызовы SSPI напрямую
def patch_gssapi_encoding():
    """Патчим winkerberos чтобы правильно декодировать ошибки SSPI"""
    try:
        import winkerberos
        
        # Патчим функцию authGSSClientStep
        original_step = winkerberos.authGSSClientStep
        
        def patched_step(state, challenge):
            try:
                return original_step(state, challenge)
            except Exception as e:
                # Перехватываем ошибку и пытаемся исправить кодировку
                error_msg = str(e)
                if '�' in error_msg and 'SSPI:' in error_msg:
                    # Извлекаем код ошибки из сообщения
                    import re
                    # Пытаемся найти код ошибки Windows
                    match = re.search(r'0x[0-9A-Fa-f]+', error_msg)
                    if match:
                        error_code = int(match.group(), 16)
                    else:
                        # Если кода нет, пробуем стандартные коды SSPI
                        error_code = 0x80090308  # SEC_E_INVALID_TOKEN
                    
                    # Получаем правильное сообщение через Windows API
                    buffer = ctypes.create_unicode_buffer(512)
                    result = ctypes.windll.kernel32.FormatMessageW(
                        0x00001000,  # FORMAT_MESSAGE_FROM_SYSTEM
                        None,
                        error_code,
                        0,
                        buffer,
                        512,
                        None
                    )
                    if result:
                        fixed_msg = f"authGSSClientStep() failed: ('SSPI: InitializeSecurityContext: {buffer.value.strip()}',)"
                        raise type(e)(fixed_msg) from e
                raise
        
        winkerberos.authGSSClientStep = patched_step
        return True
    except Exception as ex:
        print(f"Ошибка патча: {ex}")
        return False

def test_gssapi():
    """Проверка кодировки ошибок от gssapi"""
    
    # Проверяем какие библиотеки используются
    print("Проверка установленных библиотек:")
    for lib in ['gssapi', 'pykerberos', 'winkerberos', 'requests_gssapi', 'requests_kerberos']:
        try:
            mod = __import__(lib)
            print(f"  {lib}: {mod.__file__}")
        except ImportError:
            print(f"  {lib}: не установлен")
    print()
    
    try:
        import winrm
        
        # Заведомо неправильный хост для получения ошибки SSPI
        session = winrm.Session(
            'http://nonexistent-host:5985/wsman',
            auth=(None, None),
            transport='kerberos'
        )
        
        # Попытка выполнить команду
        result = session.run_cmd('hostname')
        
    except Exception as e:
        error_str = str(e)
        print(f"Исходная ошибка:\n{error_str}\n")
        print(f"Байты (repr): {repr(error_str)}\n")
        
        # Попытка исправить кодировку
        try:
            fixed = error_str.encode('latin-1').decode('cp1251')
            print(f"После перекодировки (latin-1 -> cp1251):\n{fixed}\n")
        except Exception as fix_err:
            print(f"Не удалось перекодировать: {fix_err}\n")
        
        # Альтернативный способ
        try:
            fixed2 = error_str.encode('cp437').decode('cp1251')
            print(f"После перекодировки (cp437 -> cp1251):\n{fixed2}\n")
        except Exception as fix_err2:
            print(f"Не удалось перекодировать (способ 2): {fix_err2}\n")

if __name__ == '__main__':
    print(f"Python: {sys.version}")
    print(f"Кодировка stdout: {sys.stdout.encoding}")
    print(f"Кодировка файловой системы: {sys.getfilesystemencoding()}\n")
    
    patched = patch_gssapi_encoding()
    print(f"GSSAPI патч применен: {patched}\n")
    
    test_gssapi()
