import json
from pathlib import Path
from secure_messaging.infrastructure.exceptions import CryptoException


class AuditLogger:
    def __init__(self, path):
        self._path = Path(path)

    def subscribe(self, messenger):
        messenger.subscribe(self.on_message_processed)

    def on_message_processed(self, event):
        record = {field: event[field] for field in ("time", "user", "action", "algorithm", "result")}
        try:
            self._path.parent.mkdir(exist_ok=True, parents=True)
            with self._path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, ensure_ascii=True) + "\n")
        except OSError as exc:
            raise CryptoException("Cannot append audit log") from exc

    def read_all(self, requester):
        if not requester.is_admin():
            raise PermissionError("Administrator role required")
        try:
            return self._path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise CryptoException("Cannot read audit log") from exc
