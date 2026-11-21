"""Test ``AesCipher``: TC05-TC08 và các trường hợp biên (QT1, QT2, QT3)."""

from __future__ import annotations

import pytest

from secure_messaging.business.crypto.aes_cipher import NONCE_SIZE, TAG_SIZE, AesCipher
from secure_messaging.entities.cipher_type import CipherType
from secure_messaging.infrastructure.exceptions import CryptoException

# Vector chuẩn McGrew-Viega, AES-GCM Test Case 2 (khóa 128 bit, nonce 96 bit).
NIST_KEY = bytes(16)
NIST_NONCE = bytes(12)
NIST_PLAINTEXT = bytes(16)
NIST_CIPHERTEXT = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")
NIST_TAG = bytes.fromhex("ab6e47d42cec13bdf53a67b21257bddf")


def test_tc05_nist_aes_gcm_test_case_2() -> None:
    """TC05: vector NIST cho đúng ciphertext và tag."""
    cipher = AesCipher(NIST_KEY)

    result = cipher._encrypt_with_nonce(NIST_PLAINTEXT, NIST_NONCE)

    assert result[:NONCE_SIZE] == NIST_NONCE
    assert result[NONCE_SIZE : NONCE_SIZE + 16] == NIST_CIPHERTEXT
    assert result[NONCE_SIZE + 16 :] == NIST_TAG
    assert cipher.decrypt(result) == NIST_PLAINTEXT


def test_tc06_rejects_invalid_key_length() -> None:
    """TC06: khóa 15 byte bị từ chối (QT1)."""
    with pytest.raises(CryptoException):
        AesCipher(bytes(15))


@pytest.mark.parametrize("key_size", [16, 24, 32])
def test_accepts_valid_key_sizes(key_size: int) -> None:
    """QT1: chấp nhận AES-128/192/256."""
    cipher = AesCipher(bytes(range(key_size)))

    assert cipher.key_size == key_size
    assert cipher.decrypt(cipher.encrypt(b"du lieu")) == b"du lieu"


def test_tc07_rejects_tampered_ciphertext() -> None:
    """TC07: sửa 1 byte bản mã -> lỗi xác thực (QT3)."""
    cipher = AesCipher(bytes(32))
    ciphertext = bytearray(cipher.encrypt(b"thong diep can bao ve"))
    ciphertext[NONCE_SIZE + 3] ^= 0x01

    with pytest.raises(CryptoException):
        cipher.decrypt(bytes(ciphertext))


def test_rejects_tampered_nonce() -> None:
    """Sửa nonce cũng phải làm hỏng xác thực."""
    cipher = AesCipher(bytes(32))
    ciphertext = bytearray(cipher.encrypt(b"thong diep"))
    ciphertext[0] ^= 0xFF

    with pytest.raises(CryptoException):
        cipher.decrypt(bytes(ciphertext))


def test_rejects_tampered_tag() -> None:
    """Sửa tag phải bị phát hiện."""
    cipher = AesCipher(bytes(32))
    ciphertext = bytearray(cipher.encrypt(b"thong diep"))
    ciphertext[-1] ^= 0x01

    with pytest.raises(CryptoException):
        cipher.decrypt(bytes(ciphertext))


def test_tc08_nonce_is_fresh_for_every_encryption() -> None:
    """TC08: hai lần mã hóa cùng dữ liệu cho nonce và bản mã khác nhau (QT2)."""
    cipher = AesCipher(bytes(16))
    plaintext = b"cung mot ban ro"

    first = cipher.encrypt(plaintext)
    second = cipher.encrypt(plaintext)

    assert first != second
    assert first[:NONCE_SIZE] != second[:NONCE_SIZE]
    assert len(first[:NONCE_SIZE]) == NONCE_SIZE
    assert len(second[:NONCE_SIZE]) == NONCE_SIZE


def test_nonce_is_unique_over_many_encryptions() -> None:
    """QT2: không lặp nonce trong nhiều lần mã hóa."""
    cipher = AesCipher(bytes(16))

    nonces = {cipher.encrypt(b"x")[:NONCE_SIZE] for _ in range(200)}

    assert len(nonces) == 200


def test_wrong_key_cannot_decrypt() -> None:
    """Sai khóa -> không giải mã được, không trả dữ liệu rác."""
    sender = AesCipher(bytes(32))
    receiver = AesCipher(b"\x01" * 32)

    with pytest.raises(CryptoException):
        receiver.decrypt(sender.encrypt(b"bi mat"))


def test_ciphertext_layout() -> None:
    """Bản mã = nonce 12 byte + ciphertext + tag 16 byte."""
    cipher = AesCipher(bytes(32))
    plaintext = b"a" * 40

    ciphertext = cipher.encrypt(plaintext)

    assert len(ciphertext) == NONCE_SIZE + len(plaintext) + TAG_SIZE
    assert cipher.cipher_type is CipherType.AES


def test_rejects_empty_plaintext() -> None:
    """UC1: dữ liệu rỗng không hợp lệ."""
    with pytest.raises(CryptoException):
        AesCipher(bytes(16)).encrypt(b"")


def test_rejects_truncated_ciphertext() -> None:
    """Bản mã ngắn hơn nonce + tag bị từ chối trước khi giải mã."""
    with pytest.raises(CryptoException):
        AesCipher(bytes(16)).decrypt(bytes(NONCE_SIZE + TAG_SIZE - 1))


def test_rejects_non_bytes_key() -> None:
    with pytest.raises(CryptoException):
        AesCipher("0123456789abcdef")  # type: ignore[arg-type]
