"""Хранилище данных сканирования — JSON-файл."""
import json
import os
import logging
import threading
from datetime import datetime
from src.utils import ip_to_int

logger = logging.getLogger(__name__)


class Storage:
    def __init__(self, output_dir='output'):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        self.state_file = os.path.join(output_dir, 'scan_state.json')
        self.data = self._load()
        self._lock = threading.Lock()
        self._dirty = False

    def _load(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load state: {e}")
                return {}
        return {}

    def _save(self):
        """Внутренний метод сохранения. Должен вызываться под _lock."""
        try:
            sorted_data = dict(sorted(self.data.items(), key=lambda x: ip_to_int(x[0])))
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(sorted_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def flush(self):
        """Сохранить на диск, если есть изменения. Thread-safe."""
        with self._lock:
            if self._dirty:
                self._save()
                self._dirty = False

    def update_host(self, ip, info):
        """Обновляет информацию о хосте. Не перезаписывает важные поля пустыми значениями."""
        with self._lock:
            if ip not in self.data:
                self.data[ip] = {}

            protected_fields = ['vendor', 'hostname', 'os', 'os_type', 'type', 'model']

            for key, value in info.items():
                if key in protected_fields:
                    existing_value = self.data[ip].get(key)
                    new_is_empty = value is None or (isinstance(value, str) and not value.strip())
                    existing_is_non_empty = existing_value and (not isinstance(existing_value, str) or existing_value.strip())
                    if new_is_empty and existing_is_non_empty:
                        continue
                self.data[ip][key] = value

            self.data[ip]['last_updated'] = datetime.now().isoformat()
            self._dirty = True

    def get_host(self, ip):
        return self.data.get(ip, {})

    def clear(self):
        """Очистить все данные."""
        with self._lock:
            self.data = {}
            self._dirty = True
