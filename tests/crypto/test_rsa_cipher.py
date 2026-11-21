"""Test ``RsaCipher``: TC10, TC11, TC33, TC36 và các kiểm thử bảo mật bổ sung."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from secure_messaging.business.crypto.rsa_cipher import (
    WRAPPED_LENGTH_SIZE,
    RsaCipher,
)
from secure_messaging.entities.cipher_type import CipherType
from secure_messaging.infrastructure.exceptions import CryptoException


def test_tc10_roundtrip_with_2048_bit_key(rsa_key_pair) -> None:
    """TC10: RSA hybrid 2048 bit giải mã đúng bản rõ."""
    cipher = RsaCipher(rsa_key_pair)
    plaintext = "Thông điệp ngắn cần bảo mật".encode()

    ciphertext = cipher.encrypt(plaintext)

    assert cipher.decrypt(ciphertext) == plaintext
    assert cipher.cipher_type is CipherType.RSA


def test_tc11_plaintext_larger_than_oaep_block_limit(rsa_key_pair) -> None:
    """TC11: bản rõ 1 MiB (lớn hơn giới hạn khối OAEP) vẫn mã hóa được (QT5)."""
    cipher = RsaCipher(rsa_key_pair)
    plaintext = b"A" * (1024 * 1024)

    assert len(plaintext) > cipher.max_block_size()
    assert cipher.decrypt(cipher.encrypt(plaintext)) == plaintext


def test_tc36_rejects_tampered_aes_gcm_part(rsa_key_pair) -> None:
    """TC36: sửa 1 byte trong phần AES-GCM -> lỗi xác thực (QT3)."""
    cipher = RsaCipher(rsa_key_pair)
    ciphertext = bytearray(cipher.encrypt(b"noi dung quan trong"))
    ciphertext[-1] ^= 0x01

    with pytest.raises(CryptoException):
        cipher.decrypt(bytes(ciphertext))


def test_rejects_tampered_wrapped_key(rsa_key_pair) -> None:
    """Sửa wrapped key -> RSA-OAEP thất bại."""
    cipher = RsaCipher(rsa_key_pair)
    ciphertext = bytearray(cipher.encrypt(b"noi dung"))
    ciphertext[WRAPPED_LENGTH_SIZE + 5] ^= 0x01

    with pytest.raises(CryptoException):
        cipher.decrypt(bytes(ciphertext))


def test_tc33_rejects_malformed_packet(rsa_key_pair) -> None:
    """TC33: bản mã sai định dạng bị từ chối (QT11)."""
    cipher = RsaCipher(rsa_key_pair)
    ciphertext = cipher.encrypt(b"noi dung")

    wrong_length = bytearray(ciphertext)
    wrong_length[:WRAPPED_LENGTH_SIZE] = (1).to_bytes(WRAPPED_LENGTH_SIZE, "big")

    truncated = ciphertext[: len(ciphertext) // 2]
    extended = ciphertext + b"\x00\x00"

    for malformed in (b"", b"\x00", bytes(wrong_length), truncated, extended):
        with pytest.raises(CryptoException):
            cipher.decrypt(malformed)


def test_other_user_cannot_decrypt(rsa_key_pair, rsa_key_pair_other) -> None:
    """Dữ liệu mã hóa cho A không thể giải bằng khóa của B."""
    for_alice = RsaCipher(rsa_key_pair).encrypt(b"chi danh cho Alice")
    bob_cipher = RsaCipher(rsa_key_pair_other)

    with pytest.raises(CryptoException):
        bob_cipher.decrypt(for_alice)


def test_every_encryption_uses_fresh_aes_key_and_nonce(rsa_key_pair) -> None:
    """Mỗi lần mã hóa sinh khóa AES và nonce mới."""
    cipher = RsaCipher(rsa_key_pair)

    first = cipher.encrypt(b"cung mot ban ro")
    second = cipher.encrypt(b"cung mot ban ro")

    assert first != second
    assert first[:WRAPPED_LENGTH_SIZE] == second[:WRAPPED_LENGTH_SIZE]
    wrapped_length = int.from_bytes(first[:WRAPPED_LENGTH_SIZE], "big")
    first_nonce = first[WRAPPED_LENGTH_SIZE + wrapped_length :][:12]
    second_nonce = second[WRAPPED_LENGTH_SIZE + wrapped_length :][:12]
    assert first_nonce != second_nonce
    assert first[WRAPPED_LENGTH_SIZE : WRAPPED_LENGTH_SIZE + wrapped_length] != (
        second[WRAPPED_LENGTH_SIZE : WRAPPED_LENGTH_SIZE + wrapped_length]
    )


def test_rejects_rsa_key_smaller_than_2048_bits(key_pair_factory) -> None:
    """QT5: khóa RSA nhỏ hơn 2048 bit bị từ chối."""
    weak_pair = key_pair_factory(
        rsa.generate_private_key(public_exponent=65537, key_size=1024)
    )

    with pytest.raises(CryptoException):
        RsaCipher(weak_pair)


def test_rejects_ec_key_pair(ec_key_pair) -> None:
    """Sai loại khóa: RsaCipher không nhận cặp khóa ECC."""
    with pytest.raises(CryptoException):
        RsaCipher(ec_key_pair)


def test_rejects_mismatched_key_pair(rsa_key_pair, rsa_key_pair_other) -> None:
    """Khóa công khai của A ghép với khóa riêng của B bị từ chối."""
    mismatched = SimpleNamespace(public=rsa_key_pair.public, private=rsa_key_pair_other.private)

    with pytest.raises(CryptoException):
        RsaCipher(mismatched)


def test_rejects_invalid_key_pair_contract() -> None:
    with pytest.raises(CryptoException):
        RsaCipher(object())


def test_max_block_size_for_2048_bit_key(rsa_key_pair) -> None:
    """RSA-OAEP-SHA256 với khóa 2048 bit chỉ bọc được 190 byte."""
    assert RsaCipher(rsa_key_pair).max_block_size() == 256 - 2 * 32 - 2


def test_packet_layout(rsa_key_pair) -> None:
    """Bản mã = 2 byte độ dài + wrapped key 256 byte + nonce 12 + ct + tag."""
    cipher = RsaCipher(rsa_key_pair)
    plaintext = b"x" * 32

    ciphertext = cipher.encrypt(plaintext)

    wrapped_length = int.from_bytes(ciphertext[:WRAPPED_LENGTH_SIZE], "big")
    assert wrapped_length == 256
    assert len(ciphertext) == WRAPPED_LENGTH_SIZE + 256 + 12 + len(plaintext) + 16


def test_rejects_empty_plaintext(rsa_key_pair) -> None:
    with pytest.raises(CryptoException):
        RsaCipher(rsa_key_pair).encrypt(b"")
