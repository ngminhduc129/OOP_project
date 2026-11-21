"""Fixture dùng chung cho test PH1.

Trong khi PH2 chưa cung cấp ``KeyPair``/``PublicKey``/``PrivateKey``, test dùng
đối tượng giả tuân thủ đúng hợp đồng đã thống nhất:

- ``key_pair.public.export()`` -> DER bytes (SubjectPublicKeyInfo).
- ``key_pair.private._get_material()`` -> đối tượng private key của ``cryptography``.

Không tạo lại entity của PH2 trong mã nguồn sản phẩm.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


@dataclass(frozen=True)
class FakePublicKey:
    """Khóa công khai giả: chỉ cài ``export()`` theo hợp đồng PH2."""

    _der: bytes

    def export(self) -> bytes:
        return self._der


@dataclass(frozen=True)
class FakePrivateKey:
    """Khóa riêng giả: chỉ cài ``_get_material()`` theo hợp đồng PH2."""

    _material: Any

    def _get_material(self) -> Any:
        return self._material


@dataclass(frozen=True)
class FakeKeyPair:
    """Cặp khóa giả thay cho ``KeyPair`` của PH2 trong unit test."""

    public: FakePublicKey
    private: FakePrivateKey


def make_key_pair(private_key: Any) -> FakeKeyPair:
    """Bọc một private key của ``cryptography`` thành cặp khóa giả."""
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return FakeKeyPair(public=FakePublicKey(public_der), private=FakePrivateKey(private_key))


@pytest.fixture(scope="session")
def key_pair_factory():
    """Trả về hàm bọc private key thành cặp khóa giả cho test cần khóa riêng."""
    return make_key_pair


@pytest.fixture(scope="session")
def rsa_key_pair() -> FakeKeyPair:
    """Cặp khóa RSA 2048 bit cho người dùng A."""
    return make_key_pair(rsa.generate_private_key(public_exponent=65537, key_size=2048))


@pytest.fixture(scope="session")
def rsa_key_pair_other() -> FakeKeyPair:
    """Cặp khóa RSA 2048 bit cho người dùng B."""
    return make_key_pair(rsa.generate_private_key(public_exponent=65537, key_size=2048))


@pytest.fixture(scope="session")
def ec_key_pair() -> FakeKeyPair:
    """Cặp khóa ECC P-256 cho người dùng A."""
    return make_key_pair(ec.generate_private_key(ec.SECP256R1()))


@pytest.fixture(scope="session")
def ec_key_pair_other() -> FakeKeyPair:
    """Cặp khóa ECC P-256 cho người dùng B."""
    return make_key_pair(ec.generate_private_key(ec.SECP256R1()))
