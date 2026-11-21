"""Chiến lược mã hóa đối xứng AES-GCM.

Định dạng bản mã: ``nonce (12 byte) || ciphertext || tag (16 byte)``.
Nonce được sinh mới bằng ``secrets`` cho mỗi lần mã hóa (QT2), không lưu nonce
trong đối tượng. Khóa hợp lệ dài 16, 24 hoặc 32 byte (QT1).
"""

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from secure_messaging.business.crypto.cipher_base import CipherBase
from secure_messaging.entities.cipher_type import CipherType
from secure_messaging.infrastructure.exceptions import CryptoException

NONCE_SIZE = 12
TAG_SIZE = 16
VALID_KEY_SIZES = (16, 24, 32)


class AesCipher(CipherBase):
    """AES-GCM với khóa AES-128/192/256 và nonce 96 bit."""

    def __init__(self, key: bytes) -> None:
        super().__init__(CipherType.AES)
        if not isinstance(key, bytes):
            raise CryptoException("Khóa AES phải là kiểu bytes")
        if len(key) not in VALID_KEY_SIZES:
            raise CryptoException(
                "Khóa AES phải dài 16, 24 hoặc 32 byte (AES-128/192/256) - QT1"
            )
        self._key = key
        self._aead = AESGCM(key)

    @property
    def key_size(self) -> int:
        """Độ dài khóa tính bằng byte."""
        return len(self._key)

    def generate_nonce(self) -> bytes:
        """Sinh nonce 12 byte mới từ nguồn ngẫu nhiên an toàn (QT2)."""
        return secrets.token_bytes(NONCE_SIZE)

    def do_encrypt(self, data: bytes) -> bytes:
        """Mã hóa với nonce mới, trả ``nonce || ciphertext || tag``."""
        return self._encrypt_with_nonce(data, self.generate_nonce())

    def _encrypt_with_nonce(self, data: bytes, nonce: bytes) -> bytes:
        """Mã hóa với nonce cho trước.

        Chỉ dùng cho kiểm thử vector chuẩn NIST (TC05); luồng sản phẩm luôn đi
        qua ``do_encrypt`` để bảo đảm nonce mới cho mỗi lần mã hóa.
        """
        if not isinstance(data, bytes):
            raise CryptoException("Dữ liệu cần mã hóa phải là kiểu bytes")
        if not isinstance(nonce, bytes) or len(nonce) != NONCE_SIZE:
            raise CryptoException(f"Nonce AES-GCM phải dài đúng {NONCE_SIZE} byte")
        return nonce + self._aead.encrypt(nonce, data, None)

    def do_decrypt(self, ciphertext: bytes) -> bytes:
        """Tách nonce, giải mã và kiểm tra tag; tag sai -> ``CryptoException`` (QT3)."""
        nonce = ciphertext[:NONCE_SIZE]
        body = ciphertext[NONCE_SIZE:]
        try:
            return self._aead.decrypt(nonce, body, None)
        except InvalidTag as exc:
            raise CryptoException(
                "Bản mã AES-GCM không vượt qua kiểm tra toàn vẹn (sai khóa hoặc bị sửa) - QT3"
            ) from exc

    def _min_ciphertext_length(self) -> int:
        return NONCE_SIZE + TAG_SIZE
