"""Chiến lược RSA hybrid: RSA-OAEP bọc khóa AES-256, AES-GCM mã hóa dữ liệu.

Định dạng bản mã (QT11)::

    wrapped_length (2 byte, big-endian)
    || wrapped_aes_key (RSA-OAEP-SHA256)
    || nonce (12 byte)
    || ciphertext + tag (AES-256-GCM)

Nhờ vậy dữ liệu lớn hơn giới hạn khối OAEP vẫn mã hóa được (QT5); RSA chỉ bọc
một khóa AES 32 byte ngẫu nhiên cho mỗi lần mã hóa.
"""

from __future__ import annotations

import secrets
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from secure_messaging.business.crypto._key_io import load_private_key, load_public_key
from secure_messaging.business.crypto.aes_cipher import NONCE_SIZE, TAG_SIZE, AesCipher
from secure_messaging.business.crypto.cipher_base import CipherBase
from secure_messaging.entities.cipher_type import CipherType
from secure_messaging.infrastructure.exceptions import CryptoException

MIN_RSA_KEY_BITS = 2048
AES_KEY_SIZE = 32
WRAPPED_LENGTH_SIZE = 2
SHA256_DIGEST_SIZE = 32


class RsaCipher(CipherBase):
    """RSA hybrid (RSA-OAEP-SHA256 + AES-256-GCM)."""

    def __init__(self, key_pair: Any) -> None:
        super().__init__(CipherType.RSA)
        try:
            public_material = key_pair.public.export()
            private_material = key_pair.private._get_material()
        except AttributeError as exc:
            raise CryptoException("Cặp khóa không đúng hợp đồng PH2 (public/private)") from exc

        public_key = load_public_key(public_material)
        private_key = load_private_key(private_material)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise CryptoException("RsaCipher yêu cầu khóa công khai RSA")
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise CryptoException("RsaCipher yêu cầu khóa riêng RSA")
        if public_key.key_size < MIN_RSA_KEY_BITS:
            raise CryptoException(f"Khóa RSA phải có tối thiểu {MIN_RSA_KEY_BITS} bit - QT5")
        if private_key.key_size != public_key.key_size:
            raise CryptoException("Khóa công khai và khóa riêng RSA không cùng kích thước")
        if private_key.public_key().public_numbers() != public_key.public_numbers():
            raise CryptoException("Khóa công khai không khớp với khóa riêng")

        self._key_pair = key_pair
        self._public_key = public_key
        self._private_key = private_key

    def max_block_size(self) -> int:
        """Số byte tối đa RSA-OAEP có thể bọc trực tiếp (chỉ để minh họa QT5)."""
        return self._public_key.key_size // 8 - 2 * SHA256_DIGEST_SIZE - 2

    def do_encrypt(self, data: bytes) -> bytes:
        """Sinh khóa AES mới, mã hóa dữ liệu rồi bọc khóa bằng RSA-OAEP."""
        aes_key = secrets.token_bytes(AES_KEY_SIZE)
        body = AesCipher(aes_key).encrypt(data)
        wrapped_key = self._public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return len(wrapped_key).to_bytes(WRAPPED_LENGTH_SIZE, "big") + wrapped_key + body

    def do_decrypt(self, ciphertext: bytes) -> bytes:
        """Kiểm tra định dạng, giải bọc khóa AES rồi giải mã AES-GCM (QT11)."""
        wrapped_length = int.from_bytes(ciphertext[:WRAPPED_LENGTH_SIZE], "big")
        expected_length = self._private_key.key_size // 8
        if wrapped_length != expected_length:
            raise CryptoException("Định dạng bản mã RSA hybrid không hợp lệ - QT11")

        body_offset = WRAPPED_LENGTH_SIZE + wrapped_length
        if len(ciphertext) < body_offset + NONCE_SIZE + TAG_SIZE:
            raise CryptoException("Bản mã RSA hybrid bị thiếu phần AES-GCM - QT11")

        wrapped_key = ciphertext[WRAPPED_LENGTH_SIZE:body_offset]
        body = ciphertext[body_offset:]
        try:
            aes_key = self._private_key.decrypt(
                wrapped_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except ValueError as exc:
            raise CryptoException(
                "Không thể giải bọc khóa AES (sai khóa riêng hoặc bản mã bị sửa)"
            ) from exc

        if len(aes_key) != AES_KEY_SIZE:
            raise CryptoException("Khóa AES giải bọc không hợp lệ")
        return AesCipher(aes_key).decrypt(body)

    def _min_ciphertext_length(self) -> int:
        return WRAPPED_LENGTH_SIZE + self._private_key.key_size // 8 + NONCE_SIZE + TAG_SIZE
