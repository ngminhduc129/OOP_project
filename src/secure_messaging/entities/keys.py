"""Key entities shared by PH1 ciphers and PH2 services."""
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from secure_messaging.infrastructure.exceptions import CryptoException


class AsymmetricKey:
    def __init__(self, key, created_at, expires_at):
        if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)) and key.key_size >= 2048:
            self._algorithm = "RSA"
        elif isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)) and isinstance(key.curve, ec.SECP256R1):
            self._algorithm = "ECC"
        else:
            raise CryptoException("Unsupported key")
        if any(not isinstance(t, datetime) or t.utcoffset() is None for t in (created_at, expires_at)):
            raise CryptoException("Expected timezone-aware dates")
        self._created_at, self._expires_at = created_at, expires_at
        self._bits = key.key_size

    algorithm = property(lambda self: self._algorithm)
    bits = property(lambda self: self._bits)
    created_at = property(lambda self: self._created_at)
    expires_at = property(lambda self: self._expires_at)

    def is_expired(self):
        return datetime.now(timezone.utc) >= self.expires_at


class PublicKey(AsymmetricKey):
    def __init__(self, key, created_at, expires_at):
        super().__init__(key, created_at, expires_at)
        self._data = key.public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)

    def export(self):
        return self._data


class PrivateKey(AsymmetricKey):
    def __init__(self, key, created_at, expires_at):
        super().__init__(key, created_at, expires_at)
        self._material = key

    def _get_material(self):
        if self._material is None:
            raise CryptoException("Key was released")
        return self._material

    def wipe(self):
        self._material = None

    def export_encrypted(self, password):
        if not isinstance(password, bytes) or not password:
            raise CryptoException("Password required")
        return self._get_material().private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                                  ser.BestAvailableEncryption(password))


@dataclass(frozen=True)
class KeyPair:
    public: PublicKey
    private: PrivateKey

    def __post_init__(self):
        actual = self.private._get_material().public_key().public_bytes(
            ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
        if actual != self.public.export() or self.private.expires_at != self.public.expires_at:
            raise CryptoException("Key pair mismatch")

    @classmethod
    def from_private(cls, key, created, expires):
        return cls(PublicKey(key.public_key(), created, expires), PrivateKey(key, created, expires))
