from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime
from secure_messaging.infrastructure.exceptions import CryptoException


@dataclass(frozen=True)
class User:
    name: str
    role: str = "user"

    def __post_init__(self):
        if not self.name.strip() or self.role not in {"user", "admin"}:
            raise CryptoException("Invalid user or role")

    def is_admin(self):
        return self.role == "admin"


@dataclass(frozen=True)
class DigitalSignature:
    value: bytes
    signer_id: str
    algorithm: str
    created_at: datetime

    def to_base64(self):
        return b64encode(self.value).decode("ascii")
