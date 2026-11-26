"""Test phần mở rộng ``ChaCha20Cipher`` và đăng ký Factory (T40)."""

from __future__ import annotations

import pytest

from secure_messaging.business.crypto.aes_cipher import AesCipher
from secure_messaging.business.crypto.chacha20_cipher import NONCE_SIZE, ChaCha20Cipher
from secure_messaging.business.crypto.cipher_base import CipherBase
from secure_messaging.business.crypto.interfaces import ICipher
from secure_messaging.entities.cipher_type import CipherType
from secure_messaging.infrastructure.exceptions import CryptoException
from secure_messaging.services.cipher_factory import CipherFactory


def test_roundtrip() -> None:
    cipher = ChaCha20Cipher(bytes(32))
    plaintext = "ChaCha20 mở rộng".encode()

    assert cipher.decrypt(cipher.encrypt(plaintext)) == plaintext
    assert cipher.cipher_type is CipherType.CHACHA20


def test_only_overrides_template_hooks() -> None:
    assert ChaCha20Cipher.encrypt is CipherBase.encrypt
    assert ChaCha20Cipher.decrypt is CipherBase.decrypt


@pytest.mark.parametrize("key_size", [0, 16, 24, 31, 33])
def test_rejects_wrong_key_size(key_size: int) -> None:
    with pytest.raises(CryptoException):
        ChaCha20Cipher(bytes(key_size))


def test_nonce_is_fresh() -> None:
    cipher = ChaCha20Cipher(bytes(32))

    first = cipher.encrypt(b"cung ban ro")
    second = cipher.encrypt(b"cung ban ro")

    assert first != second
    assert len(first[:NONCE_SIZE]) == NONCE_SIZE
    assert first[:NONCE_SIZE] != second[:NONCE_SIZE]


def test_rejects_tampered_ciphertext() -> None:
    cipher = ChaCha20Cipher(bytes(32))
    ciphertext = bytearray(cipher.encrypt(b"noi dung"))
    ciphertext[-1] ^= 0x01

    with pytest.raises(CryptoException):
        cipher.decrypt(bytes(ciphertext))


def test_wrong_key_cannot_decrypt() -> None:
    with pytest.raises(CryptoException):
        ChaCha20Cipher(b"\x01" * 32).decrypt(ChaCha20Cipher(bytes(32)).encrypt(b"bi mat"))


def test_registered_in_factory_without_touching_other_ciphers() -> None:
    """ChaCha20 dùng được qua Factory; AES vẫn hoạt động như cũ."""
    chacha = CipherFactory.create_symmetric(CipherType.CHACHA20, bytes(32))
    aes = CipherFactory.create_symmetric(CipherType.AES, bytes(32))

    assert isinstance(chacha, ChaCha20Cipher)
    assert isinstance(chacha, ICipher)
    assert isinstance(aes, AesCipher)
    assert set(CipherFactory.supported_symmetric()) == {CipherType.AES, CipherType.CHACHA20}
    assert chacha.decrypt(chacha.encrypt(b"mo rong")) == b"mo rong"
    assert aes.decrypt(aes.encrypt(b"mo rong")) == b"mo rong"
