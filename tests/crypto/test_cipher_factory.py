"""Test ``CipherFactory`` và Strategy/Template Method ở mức tích hợp (T37, T42)."""

from __future__ import annotations

import pytest

from secure_messaging.business.crypto.aes_cipher import AesCipher
from secure_messaging.business.crypto.cipher_base import CipherBase
from secure_messaging.business.crypto.ecc_cipher import EccCipher
from secure_messaging.business.crypto.interfaces import ICipher
from secure_messaging.business.crypto.rsa_cipher import RsaCipher
from secure_messaging.entities.cipher_type import CipherType
from secure_messaging.infrastructure.exceptions import CryptoException
from secure_messaging.services.cipher_factory import CipherFactory


class MessengerStub:
    """Context tối giản mô phỏng ``SecureMessenger`` cho kiểm thử Strategy."""

    def __init__(self, cipher: ICipher) -> None:
        self._cipher = cipher

    def set_cipher(self, cipher: ICipher) -> None:
        self._cipher = cipher

    def send(self, data: bytes) -> bytes:
        return self._cipher.encrypt(data)

    def receive(self, ciphertext: bytes) -> bytes:
        return self._cipher.decrypt(ciphertext)


def test_creates_aes_cipher() -> None:
    cipher = CipherFactory.create_symmetric(CipherType.AES, bytes(32))

    assert isinstance(cipher, AesCipher)
    assert isinstance(cipher, ICipher)
    assert cipher.cipher_type is CipherType.AES


def test_creates_rsa_cipher(rsa_key_pair) -> None:
    cipher = CipherFactory.create_asymmetric(CipherType.RSA, rsa_key_pair)

    assert isinstance(cipher, RsaCipher)
    assert isinstance(cipher, CipherBase)


def test_creates_ecc_cipher(ec_key_pair) -> None:
    cipher = CipherFactory.create_asymmetric(CipherType.ECC, ec_key_pair)

    assert isinstance(cipher, EccCipher)
    assert isinstance(cipher, CipherBase)


def test_registry_lists_supported_algorithms() -> None:
    # Kiểm tra hợp đồng thay vì tập tuyệt đối: registry được thiết kế để mở rộng
    # (T40 thêm ChaCha20) nên test cũ không phải sửa lại mỗi lần đăng ký thuật toán mới.
    assert CipherType.AES in CipherFactory.supported_symmetric()
    assert {CipherType.RSA, CipherType.ECC} <= set(CipherFactory.supported_asymmetric())


def test_rejects_wrong_algorithm_kind(rsa_key_pair) -> None:
    with pytest.raises(CryptoException):
        CipherFactory.create_symmetric(CipherType.RSA, bytes(32))
    with pytest.raises(CryptoException):
        CipherFactory.create_asymmetric(CipherType.AES, rsa_key_pair)


@pytest.mark.parametrize("invalid_type", [None, "AES", 1])
def test_rejects_invalid_cipher_type(invalid_type: object) -> None:
    with pytest.raises(CryptoException):
        CipherFactory.create_symmetric(invalid_type, bytes(32))  # type: ignore[arg-type]
    with pytest.raises(CryptoException):
        CipherFactory.create_asymmetric(invalid_type, object())  # type: ignore[arg-type]


def test_rejects_non_callable_creator() -> None:
    with pytest.raises(CryptoException):
        CipherFactory.register_symmetric(CipherType.AES, "not-callable")  # type: ignore[arg-type]


def test_strategy_can_be_switched_at_runtime(rsa_key_pair) -> None:
    """Đổi thuật toán lúc chạy mà nơi gọi không đổi."""
    messenger = MessengerStub(CipherFactory.create_symmetric(CipherType.AES, bytes(32)))
    plaintext = b"doi thuat toan luc chay"

    assert messenger.receive(messenger.send(plaintext)) == plaintext

    messenger.set_cipher(CipherFactory.create_asymmetric(CipherType.RSA, rsa_key_pair))

    assert messenger.receive(messenger.send(plaintext)) == plaintext


def test_factory_calls_subclass_hooks_through_template_method(rsa_key_pair) -> None:
    """Cipher do factory trả về vẫn đi qua encrypt/decrypt của CipherBase."""
    cipher = CipherFactory.create_asymmetric(CipherType.RSA, rsa_key_pair)

    assert type(cipher).encrypt is CipherBase.encrypt
    assert type(cipher).decrypt is CipherBase.decrypt
