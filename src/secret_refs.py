"""Разрешение ссылок на секреты в конфиге.

Значение пароля в конфиге может быть:
  * обычной строкой — используется как есть (обратная совместимость);
  * ``env:NAME`` — значение переменной окружения NAME;
  * ``kdbx:<запись>[#атрибут]`` — поле записи KeePassXC (по умолчанию Password),
    читается через ``keepassxc-cli show -a <атрибут> -s -q``, мастер-пароль подаётся в stdin;
  * ``plain:<строка>`` — буквальная строка (если пароль сам начинается с ``env:``/``kdbx:``).

Параметры сейфа (переменные окружения важнее конфига ``secrets.kdbx``):
  NCG_KDBX_DATABASE     путь к .kdbx                       (database)
  NCG_KDBX_MASTER       мастер-пароль открытым текстом     (—, только env)
  NCG_KDBX_MASTER_DPAPI файл мастера под Windows DPAPI     (master_dpapi)
  NCG_KEEPASSXC_CLI     путь к keepassxc-cli               (cli)

Значения секретов никогда не пишутся в лог и в текст исключений.
"""

import os
import shutil
import subprocess
import sys

ENV_PREFIX = 'env:'
KDBX_PREFIX = 'kdbx:'
PLAIN_PREFIX = 'plain:'

_WINDOWS_CLI = r'C:\Program Files\KeePassXC\keepassxc-cli.exe'


class SecretResolutionError(RuntimeError):
    """Ссылку на секрет не удалось разрешить (текст ошибки не содержит значений)."""


def is_secret_ref(value):
    return isinstance(value, str) and value.startswith((ENV_PREFIX, KDBX_PREFIX, PLAIN_PREFIX))


def _strip_eol(text):
    # keepassxc-cli и PowerShell дописывают перевод строки — в пароль он попасть не должен
    while text.endswith(('\r', '\n')):
        text = text[:-1]
    return text


def _dpapi_unprotect_file(path):
    """Расшифровать файл ConvertFrom-SecureString (hex DPAPI-блоб) без запуска PowerShell."""
    if sys.platform != 'win32':
        raise SecretResolutionError('DPAPI-файл мастера поддерживается только на Windows')
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_char))]

    try:
        with open(path, 'r', encoding='utf-8-sig') as f:
            raw = bytes.fromhex(f.read().strip())
    except (OSError, ValueError) as exc:
        raise SecretResolutionError(f'не удалось прочитать DPAPI-файл {path}: {type(exc).__name__}') from None

    buf = ctypes.create_string_buffer(raw, len(raw))
    blob_in = DATA_BLOB(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    if not crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
        raise SecretResolutionError(f'DPAPI не расшифровал {path} (другой пользователь или машина?)')
    try:
        data = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    # SecureString хранит строку в UTF-16LE
    return _strip_eol(data.decode('utf-16-le'))


class SecretResolver:
    def __init__(self, config=None, environ=None, runner=None):
        cfg = ((config or {}).get('secrets') or {}).get('kdbx') or {}
        self._env = os.environ if environ is None else environ
        self._database = self._env.get('NCG_KDBX_DATABASE') or cfg.get('database')
        self._master_dpapi = self._env.get('NCG_KDBX_MASTER_DPAPI') or cfg.get('master_dpapi')
        self._cli = self._env.get('NCG_KEEPASSXC_CLI') or cfg.get('cli')
        self._runner = runner or subprocess.run
        self._master = None
        self._cache = {}

    def resolve(self, value):
        """Вернуть секрет по значению из конфига; не-ссылки возвращаются как строка."""
        if value is None:
            return None
        if not isinstance(value, str):
            return str(value)
        if value.startswith(PLAIN_PREFIX):
            return value[len(PLAIN_PREFIX):]
        if not value.startswith((ENV_PREFIX, KDBX_PREFIX)):
            return value
        if value not in self._cache:
            if value.startswith(ENV_PREFIX):
                self._cache[value] = self._from_env(value[len(ENV_PREFIX):])
            else:
                self._cache[value] = self._from_kdbx(value[len(KDBX_PREFIX):])
        return self._cache[value]

    def _from_env(self, name):
        name = name.strip()
        if not name:
            raise SecretResolutionError('пустое имя переменной в ссылке env:')
        secret = self._env.get(name)
        if secret is None or secret == '':
            raise SecretResolutionError(f'переменная окружения {name} не задана или пуста')
        return _strip_eol(secret)

    def _cli_path(self):
        if self._cli:
            return self._cli
        found = shutil.which('keepassxc-cli')
        if found:
            return found
        if sys.platform == 'win32' and os.path.exists(_WINDOWS_CLI):
            return _WINDOWS_CLI
        raise SecretResolutionError('keepassxc-cli не найден (задайте NCG_KEEPASSXC_CLI или secrets.kdbx.cli)')

    def _get_master(self):
        if self._master is None:
            master = self._env.get('NCG_KDBX_MASTER')
            if master:
                self._master = _strip_eol(master)
            elif self._master_dpapi:
                self._master = _dpapi_unprotect_file(os.path.expandvars(os.path.expanduser(self._master_dpapi)))
            else:
                raise SecretResolutionError(
                    'мастер-пароль сейфа не задан (NCG_KDBX_MASTER, NCG_KDBX_MASTER_DPAPI или secrets.kdbx.master_dpapi)')
        return self._master

    def _from_kdbx(self, ref):
        entry, _, attribute = ref.partition('#')
        entry = entry.strip()
        attribute = attribute.strip() or 'Password'
        if not entry:
            raise SecretResolutionError('пустое имя записи в ссылке kdbx:')
        if not self._database:
            raise SecretResolutionError('путь к сейфу не задан (NCG_KDBX_DATABASE или secrets.kdbx.database)')
        database = os.path.expandvars(os.path.expanduser(self._database))
        cmd = [self._cli_path(), 'show', '-q', '-s', '-a', attribute, database, entry]
        try:
            proc = self._runner(cmd, input=self._get_master() + '\n', capture_output=True,
                                text=True, encoding='utf-8', timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            raise SecretResolutionError(f'keepassxc-cli не запустился для записи {entry!r}: {type(exc).__name__}') from None
        if proc.returncode != 0:
            err = (proc.stderr or '').strip().splitlines()
            hint = err[-1] if err else f'код {proc.returncode}'
            raise SecretResolutionError(f'запись {entry!r} (атрибут {attribute}) не прочитана: {hint}')
        secret = _strip_eol(proc.stdout or '')
        if not secret:
            raise SecretResolutionError(f'запись {entry!r}: атрибут {attribute} пуст')
        return secret


_default_resolver = None


def configure(config=None, **kwargs):
    """Задать резолвер по умолчанию из конфига (секция secrets.kdbx) и окружения."""
    global _default_resolver
    _default_resolver = SecretResolver(config, **kwargs)
    return _default_resolver


def get_default_resolver():
    global _default_resolver
    if _default_resolver is None:
        _default_resolver = SecretResolver()
    return _default_resolver


def resolve_secret(value):
    return get_default_resolver().resolve(value)
