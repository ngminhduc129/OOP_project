"""Phần mở rộng: chiến lược ChaCha20-Poly1305.

Minh họa Template Method + Factory có thể mở rộng mà không sửa ``AesCipher``,
``RsaCipher`` hay ``EccCipher``: lớp này chỉ cài các hook ``do_encrypt``/
``do_decrypt`` và đăng ký một dòng trong ``CipherFactory``.

ChaCha20 là lựa chọn bổ sung cho luồng đối xứng, **không** thay thế AES-GCM
trong các luồng đã đặc tả (RSA hybrid, ECIES).
"""

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from secure_messaging.business.crypto.cipher_base import CipherBase
from secure_messaging.entities.cipher_type import CipherType
from secure_messaging.infrastructure.exceptions import CryptoException

NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32


class ChaCha20Cipher(CipherBase):
    """ChaCha20-Poly1305 với khóa 256 bit và nonce 96 bit."""

    def __init__(self, key: bytes) -> None:
        super().__init__(CipherType.CHACHA20)
        if not isinstance(key, bytes):
            raise CryptoException("Khóa ChaCha20 phải là kiểu bytes")
        if len(key) != KEY_SIZE:
            raise CryptoException(f"Khóa ChaCha20 phải dài đúng {KEY_SIZE} byte")
        self._key = key
        self._aead = ChaCha20Poly1305(key)

    def generate_nonce(self) -> bytes:
        """Sinh nonce 12 byte mới cho mỗi lần mã hóa."""
        return secrets.token_bytes(NONCE_SIZE)

    def do_encrypt(self, data: bytes) -> bytes:
        nonce = self.generate_nonce()
        return nonce + self._aead.encrypt(nonce, data, None)

    def do_decrypt(self, ciphertext: bytes) -> bytes:
        nonce = ciphertext[:NONCE_SIZE]
        body = ciphertext[NONCE_SIZE:]
        try:
            return self._aead.decrypt(nonce, body, None)
        except InvalidTag as exc:
            raise CryptoException(
                "Bản mã ChaCha20-Poly1305 không vượt qua kiểm tra toàn vẹn"
            ) from exc

    def _min_ciphertext_length(self) -> int:
        return NONCE_SIZE + TAG_SIZE
