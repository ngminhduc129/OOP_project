import json
from pathlib import Path
from secure_messaging.infrastructure.exceptions import CryptoException


class AppConfig:
    _defaults = dict(key_size=2048, key_dir="data/keys", audit_path="data/audit.jsonl", admins=[])

    def __init__(self, path="config.json"):
        self._path = Path(path)
        self._settings = self._defaults.copy()

    def load(self):
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8-sig"))
        except FileNotFoundError:
            raw = {}
        except (ValueError, OSError) as exc:
            raise CryptoException("Invalid config.json") from exc
        if not isinstance(raw, dict):
            raise CryptoException("Expected a settings object")
        settings = self._defaults | raw
        if settings["key_size"] not in (2048, 3072, 4096):
            raise CryptoException("Invalid RSA key_size")
        for key in ("key_dir", "audit_path"):
            value = settings[key]
            if not isinstance(value, str) or not value or Path(value).is_absolute() or ".." in Path(value).parts:
                raise CryptoException("Expected a relative data path")
        if not isinstance(settings["admins"], list) or not all(isinstance(a, str) for a in settings["admins"]):
            raise CryptoException("Invalid administrator list")
        self._settings = settings
        return self

    def get(self, key):
        return self._settings[key]
