"""Chiến lược ECC-ECIES trên đường cong NIST P-256.

Luồng: sinh khóa tạm (ephemeral) -> ECDH với khóa công khai người nhận ->
HKDF-SHA256 dẫn xuất khóa AES-256 -> AES-GCM mã hóa dữ liệu.

Định dạng bản mã (QT11)::

    ephemeral_public_key (65 byte, điểm không nén)
    || nonce (12 byte)
    || ciphertext + tag (16 byte)

Primitive ECDH/HKDF/AES dùng thư viện ``cryptography``; ``EllipticCurve`` tự cài
chỉ dùng để kiểm tra điểm/khóa công khai (QT6).
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from secure_messaging.business.arithmetic.ec_point import ECPoint
from secure_messaging.business.arithmetic.elliptic_curve import EllipticCurve
from secure_messaging.business.crypto._key_io import load_private_key, load_public_key
from secure_messaging.business.crypto.aes_cipher import NONCE_SIZE, TAG_SIZE, AesCipher
from secure_messaging.business.crypto.cipher_base import CipherBase
from secure_messaging.entities.cipher_type import CipherType
from secure_messaging.infrastructure.exceptions import CryptoException

P256_CURVE_NAME = "secp256r1"
UNCOMPRESSED_POINT_SIZE = 65
AES_KEY_SIZE = 32
HKDF_INFO = b"SecureMessagingSystem/ECIES/P-256/AES-256-GCM/v1"
_COORDINATE_SIZE = 32
_UNCOMPRESSED_PREFIX = 0x04


class EccCipher(CipherBase):
    """ECIES với ECDH P-256, HKDF-SHA256 và AES-256-GCM."""

    def __init__(self, key_pair: Any, curve: EllipticCurve | None = None) -> None:
        super().__init__(CipherType.ECC)
        self._curve = curve if curve is not None else EllipticCurve.named("P-256")

        try:
            public_material = key_pair.public.export()
            private_material = key_pair.private._get_material()
        except AttributeError as exc:
            raise CryptoException("Cặp khóa không đúng hợp đồng PH2 (public/private)") from exc

        public_key = load_public_key(public_material)
        private_key = load_private_key(private_material)
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise CryptoException("EccCipher yêu cầu khóa công khai ECC")
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise CryptoException("EccCipher yêu cầu khóa riêng ECC")
        if public_key.curve.name != P256_CURVE_NAME or private_key.curve.name != P256_CURVE_NAME:
            raise CryptoException("EccCipher chỉ hỗ trợ đường cong NIST P-256")
        if private_key.public_key().public_numbers() != public_key.public_numbers():
            raise CryptoException("Khóa công khai không khớp với khóa riêng")

        numbers = public_key.public_numbers()
        self._curve.validate_public_key(ECPoint(numbers.x, numbers.y))  # QT6

        self._key_pair = key_pair
        self._public_key = public_key
        self._private_key = private_key

    def derive_shared_key(
        self,
        private_key: ec.EllipticCurvePrivateKey,
        peer_public_key: ec.EllipticCurvePublicKey,
    ) -> bytes:
        """Dẫn xuất khóa AES-256 từ bí mật ECDH bằng HKDF-SHA256."""
        try:
            shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        except ValueError as exc:
            raise CryptoException("Không thể thực hiện ECDH với khóa công khai đã cho") from exc

        return HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=None,
            info=HKDF_INFO,
        ).derive(shared_secret)

    def do_encrypt(self, data: bytes) -> bytes:
        """Sinh khóa tạm, ECDH, dẫn xuất khóa AES rồi mã hóa."""
        ephemeral_private = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public = ephemeral_private.public_key()

        numbers = ephemeral_public.public_numbers()
        self._curve.validate_public_key(ECPoint(numbers.x, numbers.y))  # QT6

        shared_key = self.derive_shared_key(ephemeral_private, self._public_key)
        ephemeral_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        return ephemeral_bytes + AesCipher(shared_key).encrypt(data)

    def do_decrypt(self, ciphertext: bytes) -> bytes:
        """Kiểm tra điểm tạm, ECDH lại, dẫn xuất khóa AES và giải mã (QT11)."""
        ephemeral_bytes = ciphertext[:UNCOMPRESSED_POINT_SIZE]
        body = ciphertext[UNCOMPRESSED_POINT_SIZE:]

        if len(ephemeral_bytes) != UNCOMPRESSED_POINT_SIZE or (
            ephemeral_bytes[0] != _UNCOMPRESSED_PREFIX
        ):
            raise CryptoException("Điểm công khai tạm của ECIES không hợp lệ - QT11")

        x = int.from_bytes(ephemeral_bytes[1 : 1 + _COORDINATE_SIZE], "big")
        y = int.from_bytes(ephemeral_bytes[1 + _COORDINATE_SIZE :], "big")
        self._curve.validate_public_key(ECPoint(x, y))  # QT6

        try:
            ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), ephemeral_bytes
            )
        except ValueError as exc:
            raise CryptoException("Điểm công khai tạm của ECIES không hợp lệ") from exc

        shared_key = self.derive_shared_key(self._private_key, ephemeral_public)
        return AesCipher(shared_key).decrypt(body)

    def _min_ciphertext_length(self) -> int:
        return UNCOMPRESSED_POINT_SIZE + NONCE_SIZE + TAG_SIZE
