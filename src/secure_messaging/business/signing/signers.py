import hashlib
from typing import Protocol
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
from secure_messaging.entities.keys import PrivateKey, PublicKey
from secure_messaging.infrastructure.exceptions import CryptoException


class HashService:
    @staticmethod
    def sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()


class ISigner(Protocol):
    algorithm: str

    def sign(self, digest: bytes, private: PrivateKey) -> bytes: ...
    def verify(self, digest: bytes, signature: bytes, public: PublicKey) -> bool: ...


class _Signer:
    def sign(self, digest, private):
        if len(digest) != 32 or private.algorithm != self.key_type:
            raise CryptoException("Invalid digest or signing key")
        return private._get_material().sign(digest, *self.params)

    def verify(self, digest, signature, public):
        if public.algorithm != self.key_type or len(digest) != 32:
            return False
        key = serialization.load_der_public_key(public.export())
        try:
            key.verify(signature, digest, *self.params)
        except InvalidSignature:
            return False
        return True


class RsaSigner(_Signer):
    algorithm = "RSA-PSS"
    key_type = "RSA"
    params = (padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
              utils.Prehashed(hashes.SHA256()))


class EcdsaSigner(_Signer):
    algorithm = "ECDSA"
    key_type = "ECC"
    params = (ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True),)
