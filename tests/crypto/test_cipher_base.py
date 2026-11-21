"""Test Template Method của ``CipherBase`` (T15).

Kiểm tra quy trình chung thực sự chạy trước/sau hook của lớp con, không chỉ
kiểm tra lớp trừu tượng có tồn tại.
"""

from __future__ import annotations

import pytest

from secure_messaging.business.crypto.cipher_base import CipherBase
from secure_messaging.business.crypto.interfaces import ICipher
from secure_messaging.entities.cipher_type import CipherType
from secure_messaging.infrastructure.exceptions import CryptoException


class RecordingCipher(CipherBase):
    """Cipher giả ghi lại thứ tự gọi hook để kiểm chứng Template Method."""

    def __init__(self) -> None:
        super().__init__(CipherType.AES)
        self.calls: list[str] = []

    def do_encrypt(self, data: bytes) -> bytes:
        self.calls.append("do_encrypt")
        return b"enc:" + data

    def do_decrypt(self, ciphertext: bytes) -> bytes:
        self.calls.append("do_decrypt")
        return ciphertext[4:]

    def _min_ciphertext_length(self) -> int:
        return 4


def test_icipher_is_abstract() -> None:
    with pytest.raises(TypeError):
        ICipher()  # type: ignore[abstract]


def test_cipher_base_is_abstract() -> None:
    with pytest.raises(TypeError):
        CipherBase(CipherType.AES)  # type: ignore[abstract]


def test_template_method_encrypt_calls_hook() -> None:
    cipher = RecordingCipher()

    assert cipher.encrypt(b"hello") == b"enc:hello"
    assert cipher.calls == ["do_encrypt"]


def test_template_method_decrypt_calls_hook() -> None:
    cipher = RecordingCipher()

    assert cipher.decrypt(b"enc:hello") == b"hello"
    assert cipher.calls == ["do_decrypt"]


def test_encrypt_rejects_non_bytes_before_hook() -> None:
    cipher = RecordingCipher()

    with pytest.raises(CryptoException):
        cipher.encrypt("hello")  # type: ignore[arg-type]

    assert cipher.calls == []


def test_encrypt_rejects_empty_data_before_hook() -> None:
    cipher = RecordingCipher()

    with pytest.raises(CryptoException):
        cipher.encrypt(b"")

    assert cipher.calls == []


def test_decrypt_rejects_short_ciphertext_before_hook() -> None:
    cipher = RecordingCipher()

    with pytest.raises(CryptoException):
        cipher.decrypt(b"abc")

    assert cipher.calls == []


def test_cipher_type_property_is_exposed() -> None:
    cipher = RecordingCipher()

    assert cipher.cipher_type is CipherType.AES


def test_cipher_base_rejects_invalid_cipher_type() -> None:
    class InvalidTypeCipher(CipherBase):
        def do_encrypt(self, data: bytes) -> bytes:
            return data

        def do_decrypt(self, ciphertext: bytes) -> bytes:
            return ciphertext

        def _min_ciphertext_length(self) -> int:
            return 0

    with pytest.raises(CryptoException):
        InvalidTypeCipher("AES")  # type: ignore[arg-type]


def test_subclass_only_overrides_hooks() -> None:
    """Lớp con không được override encrypt/decrypt: kiểm tra qua MRO."""
    assert RecordingCipher.encrypt is CipherBase.encrypt
    assert RecordingCipher.decrypt is CipherBase.decrypt
