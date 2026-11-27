from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from secure_messaging.business.arithmetic.ec_point import ECPoint
from secure_messaging.business.arithmetic.elliptic_curve import EllipticCurve
from secure_messaging.entities.keys import KeyPair
from secure_messaging.infrastructure.repositories import IKeyRepository
from secure_messaging.infrastructure.exceptions import CryptoException
from secure_messaging.infrastructure.key_errors import KeyExpiredException, KeyRevokedException


class KeyService:
    def __init__(self, repository: IKeyRepository):
        self._repo = repository

    def generate(self, owner, algorithm, bits=None, days=365):
        if not owner.strip() or not isinstance(days, int) or not 1 <= days <= 36500:
            raise CryptoException("Invalid owner or validity period")
        if algorithm == "RSA" and bits in (None, 2048, 3072, 4096):
            key = rsa.generate_private_key(public_exponent=65537, key_size=bits or 2048)
        elif algorithm == "ECC" and bits in (None, 256):
            key = ec.generate_private_key(ec.SECP256R1())
            numbers = key.public_key().public_numbers()
            EllipticCurve.named("P-256").validate_public_key(ECPoint(numbers.x, numbers.y))
        else:
            raise CryptoException("Unsupported algorithm or key size")
        now = datetime.now(timezone.utc)
        return KeyPair.from_private(key, now, now + timedelta(days=days))

    def save(self, owner, pair):
        self._repo.save(owner, pair)

    def load(self, owner):
        return self._repo.load(owner)

    get = load

    def revoke(self, owner, requester):
        if not requester.is_admin():
            raise PermissionError("Administrator role required")
        self._repo.revoke(owner)

    def ensure_usable(self, owner):
        if self._repo.is_revoked(owner):
            raise KeyRevokedException("Key revoked")
        pair = self.get(owner)
        if pair.public.is_expired():
            raise KeyExpiredException("Key expired")
        return pair
