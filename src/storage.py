"""Хранилище данных сканирования — JSON-файл."""
import glob
import json
import os
import logging
import shutil
import threading
from datetime import datetime
from src.constants import (
    STATUS_COMPLETED,
    STATUS_VIRTUALIZATION_COMPLETED,
    STATUS_WEB_COMPLETED,
)
from src.models import HostRecord
from src.utils import ip_to_int, normalize_os_name

logger = logging.getLogger(__name__)

STATE_VERSION = 1
BACKUP_KEEP = 30
COMPLETED_STATUSES = frozenset({
    STATUS_COMPLETED,
    STATUS_VIRTUALIZATION_COMPLETED,
    STATUS_WEB_COMPLETED,
})


class Storage:
    def __init__(self, output_dir='output'):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        self.state_file = os.path.join(output_dir, 'scan_state.json')
        self.backup_dir = os.path.join(output_dir, 'backups')
        self.meta = {'version': STATE_VERSION, 'last_scan': ''}
        self.data = self._load()
        self._lock = threading.Lock()
        self._dirty = False
        self._make_backup()

    def _load(self):
        if not os.path.exists(self.state_file):
            return {}
        try:
            with open(self.state_file, 'r', encoding='utf-8') as f:
                raw = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load state: {e}")
            return {}

        if isinstance(raw, dict) and 'hosts' in raw and 'meta' in raw:
            self.meta = {**self.meta, **(raw.get('meta') or {})}
            hosts = raw.get('hosts') or {}
            return hosts if isinstance(hosts, dict) else {}

        # Legacy flat format: {<ip>: {...}} — wrap into hosts dict
        if isinstance(raw, dict):
            return raw

        return {}

    def _make_backup(self):
        if not os.path.exists(self.state_file):
            return
        try:
            os.makedirs(self.backup_dir, exist_ok=True)
            stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            dest = os.path.join(self.backup_dir, f'scan_state_{stamp}.json')
            shutil.copy2(self.state_file, dest)
            self._rotate_backups()
        except Exception as e:
            logger.warning(f"Failed to backup state: {e}")

    def _rotate_backups(self):
        pattern = os.path.join(self.backup_dir, 'scan_state_*.json')
        files = sorted(glob.glob(pattern))
        excess = len(files) - BACKUP_KEEP
        for path in files[:excess] if excess > 0 else ():
            try:
                os.remove(path)
            except OSError:
                pass

    def _save(self):
        """Внутренний метод сохранения. Должен вызываться под _lock."""
        try:
            sorted_hosts = dict(sorted(self.data.items(), key=lambda x: ip_to_int(x[0])))
            self.meta['last_scan'] = datetime.now().isoformat()
            self.meta['version'] = STATE_VERSION
            payload = {'meta': dict(self.meta), 'hosts': sorted_hosts}
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def flush(self):
        """Сохранить на диск, если есть изменения. Thread-safe."""
        with self._lock:
            if self._dirty:
                self._save()
                self._dirty = False

    def update_host(self, ip, info, overwrite_protected=False):
        """Обновляет информацию о хосте. Не перезаписывает важные поля пустыми значениями."""
        with self._lock:
            if ip not in self.data:
                self.data[ip] = {}
            else:
                existing_os = self.data[ip].get('os')
                if isinstance(existing_os, str) and existing_os:
                    self.data[ip]['os'] = normalize_os_name(existing_os)

            protected_fields = ['vendor', 'hostname', 'os', 'os_type', 'type', 'model']

            for key, value in info.items():
                if key == 'os' and isinstance(value, str) and value:
                    value = normalize_os_name(value)
                if key in protected_fields and not overwrite_protected:
                    existing_value = self.data[ip].get(key)
                    new_is_empty = value is None or (isinstance(value, str) and not value.strip())
                    existing_is_non_empty = existing_value and (not isinstance(existing_value, str) or existing_value.strip())
                    if new_is_empty and existing_is_non_empty:
                        continue
                self.data[ip][key] = value

            self.data[ip]['last_updated'] = datetime.now().isoformat()
            self._dirty = True

    def update_host_record(self, record):
        self.update_host(record.ip, record.to_dict())

    def apply_discovery_snapshot(self, records, force=False):
        """Применяет результаты discovery к state.

        Семантика:
          - Хост отсутствует в state → добавляется целиком.
          - Хост есть и `force=True` → узел полностью заменяется свежим discovery snapshot.
          - Хост есть, состояние «незавершённое» (scan_status не в COMPLETED_STATUSES)
            → узел полностью заменяется.
          - Хост есть и завершён → не трогаем.
          - Хосты, отсутствующие в новом discovery, остаются в state без изменений.
        """
        now = datetime.now().isoformat()
        with self._lock:
            for record in records:
                base = record.to_dict()
                if isinstance(base.get('os'), str) and base.get('os'):
                    base['os'] = normalize_os_name(base['os'])
                base['last_updated'] = now

                existing = self.data.get(record.ip)
                if existing is None:
                    self.data[record.ip] = base
                    continue

                if force or existing.get('scan_status') not in COMPLETED_STATUSES:
                    self.data[record.ip] = base
                    continue

                # завершён, force=False → не трогаем
            self._dirty = True

    def get_host(self, ip):
        return self.data.get(ip, {})

    def get_host_record(self, ip):
        host = self.get_host(ip)
        if not host:
            return None
        return HostRecord.from_dict(host)

    def iter_host_records(self):
        for ip in sorted(self.data.keys(), key=ip_to_int):
            yield HostRecord.from_dict(self.data[ip])

    def clear(self):
        """Очистить все данные."""
        with self._lock:
            self.data = {}
            self._dirty = True
