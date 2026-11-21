"""Test ``EccCipher``: TC13, TC33, TC35 và các kiểm thử bảo mật bổ sung."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from secure_messaging.business.arithmetic.ec_point import ECPoint
from secure_messaging.business.arithmetic.elliptic_curve import EllipticCurve
from secure_messaging.business.crypto.ecc_cipher import (
    UNCOMPRESSED_POINT_SIZE,
    EccCipher,
)
from secure_messaging.entities.cipher_type import CipherType
from secure_messaging.infrastructure.exceptions import CryptoException


def test_tc13_ecies_roundtrip(ec_key_pair) -> None:
    """TC13: ECIES P-256 giải mã đúng bản rõ."""
    cipher = EccCipher(ec_key_pair)
    plaintext = "Dữ liệu gửi qua ECIES".encode()

    ciphertext = cipher.encrypt(plaintext)

    assert cipher.decrypt(ciphertext) == plaintext
    assert cipher.cipher_type is CipherType.ECC


def test_tc35_ciphertext_structure(ec_key_pair) -> None:
    """TC35: bản mã 32 byte = 65 + 12 + 32 + 16; 65 byte đầu là điểm không nén hợp lệ (QT11)."""
    plaintext = b"x" * 32

    ciphertext = EccCipher(ec_key_pair).encrypt(plaintext)

    assert len(ciphertext) == UNCOMPRESSED_POINT_SIZE + 12 + 32 + 16
    ephemeral = ciphertext[:UNCOMPRESSED_POINT_SIZE]
    assert ephemeral[0] == 0x04

    numbers = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), ephemeral
    ).public_numbers()
    EllipticCurve.named("P-256").validate_public_key(ECPoint(numbers.x, numbers.y))


def test_tc33_rejects_malformed_packets(ec_key_pair) -> None:
    """TC33: bản mã sai định dạng (thiếu trường, điểm sai) bị từ chối (QT11)."""
    cipher = EccCipher(ec_key_pair)
    ciphertext = cipher.encrypt(b"noi dung")

    bad_prefix = bytearray(ciphertext)
    bad_prefix[0] = 0x02

    off_curve_point = b"\x04" + b"\x00" * 64 + ciphertext[UNCOMPRESSED_POINT_SIZE:]
    coordinate_out_of_range = (
        b"\x04"
        + (EllipticCurve.named("P-256").p).to_bytes(32, "big")
        + b"\x00" * 32
        + ciphertext[UNCOMPRESSED_POINT_SIZE:]
    )

    for malformed in (
        b"",
        ciphertext[:UNCOMPRESSED_POINT_SIZE],
        bytes(bad_prefix),
        off_curve_point,
        coordinate_out_of_range,
        ciphertext + b"\x00",
    ):
        with pytest.raises(CryptoException):
            cipher.decrypt(malformed)


def test_rejects_tampered_nonce(ec_key_pair) -> None:
    """Sai/sửa nonce -> xác thực GCM thất bại."""
    cipher = EccCipher(ec_key_pair)
    ciphertext = bytearray(cipher.encrypt(b"noi dung"))
    ciphertext[UNCOMPRESSED_POINT_SIZE] ^= 0x01

    with pytest.raises(CryptoException):
        cipher.decrypt(bytes(ciphertext))


def test_rejects_tampered_ciphertext(ec_key_pair) -> None:
    """Sửa phần ciphertext -> xác thực GCM thất bại."""
    cipher = EccCipher(ec_key_pair)
    ciphertext = bytearray(cipher.encrypt(b"noi dung"))
    ciphertext[-1] ^= 0x01

    with pytest.raises(CryptoException):
        cipher.decrypt(bytes(ciphertext))


def test_rejects_tampered_ephemeral_point(ec_key_pair) -> None:
    """Sửa điểm tạm -> điểm không hợp lệ hoặc ECDH cho khóa khác."""
    cipher = EccCipher(ec_key_pair)
    ciphertext = bytearray(cipher.encrypt(b"noi dung"))
    ciphertext[1] ^= 0x01

    with pytest.raises(CryptoException):
        cipher.decrypt(bytes(ciphertext))


def test_other_user_cannot_decrypt(ec_key_pair, ec_key_pair_other) -> None:
    """Dữ liệu mã hóa cho A không thể giải bằng khóa của B."""
    for_alice = EccCipher(ec_key_pair).encrypt(b"chi danh cho Alice")

    with pytest.raises(CryptoException):
        EccCipher(ec_key_pair_other).decrypt(for_alice)


def test_every_encryption_uses_fresh_ephemeral_key_and_nonce(ec_key_pair) -> None:
    """Mỗi lần mã hóa sinh ephemeral key và nonce mới."""
    cipher = EccCipher(ec_key_pair)

    first = cipher.encrypt(b"cung mot ban ro")
    second = cipher.encrypt(b"cung mot ban ro")

    assert first != second
    assert first[:UNCOMPRESSED_POINT_SIZE] != second[:UNCOMPRESSED_POINT_SIZE]
    assert (
        first[UNCOMPRESSED_POINT_SIZE : UNCOMPRESSED_POINT_SIZE + 12]
        != second[UNCOMPRESSED_POINT_SIZE : UNCOMPRESSED_POINT_SIZE + 12]
    )


def test_ecdh_derives_same_key_on_both_sides(ec_key_pair, ec_key_pair_other) -> None:
    """ECDH + HKDF phải cho cùng khóa ở hai phía."""
    alice = EccCipher(ec_key_pair)
    bob = EccCipher(ec_key_pair_other)
    alice_private = ec_key_pair.private._get_material()
    bob_public = bob._public_key

    alice_key = alice.derive_shared_key(alice_private, bob_public)
    bob_key = bob.derive_shared_key(bob._private_key, alice._public_key)

    assert alice_key == bob_key
    assert len(alice_key) == 32


def test_rejects_rsa_key_pair(rsa_key_pair) -> None:
    """Sai loại khóa: EccCipher không nhận cặp khóa RSA."""
    with pytest.raises(CryptoException):
        EccCipher(rsa_key_pair)


def test_rejects_non_p256_curve(key_pair_factory) -> None:
    """Chỉ hỗ trợ P-256."""
    p384_pair = key_pair_factory(ec.generate_private_key(ec.SECP384R1()))

    with pytest.raises(CryptoException):
        EccCipher(p384_pair)


def test_rejects_mismatched_key_pair(ec_key_pair, ec_key_pair_other) -> None:
    mismatched = SimpleNamespace(public=ec_key_pair.public, private=ec_key_pair_other.private)

    with pytest.raises(CryptoException):
        EccCipher(mismatched)


def test_accepts_public_key_as_der_subject_public_key_info(ec_key_pair) -> None:
    """Hợp đồng PH2: PublicKey.export() trả DER SubjectPublicKeyInfo."""
    der = ec_key_pair.public.export()

    assert der[0] == 0x30
    assert serialization.load_der_public_key(der).curve.name == "secp256r1"
    assert EccCipher(ec_key_pair).cipher_type is CipherType.ECC
