"""Test ``ECPoint``: TC27 và các ràng buộc dữ liệu."""

from __future__ import annotations

import pytest

from secure_messaging.business.arithmetic.ec_point import ECPoint
from secure_messaging.infrastructure.exceptions import CryptoException


def test_tc27_infinity_point() -> None:
    """TC27: điểm vô cực nhận diện đúng; điểm G của P-256 là điểm hữu hạn."""
    infinity = ECPoint.infinity()
    generator = ECPoint(
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    )

    assert infinity.is_at_infinity() is True
    assert generator.is_at_infinity() is False


def test_points_are_value_objects() -> None:
    assert ECPoint(3, 5) == ECPoint(3, 5)
    assert ECPoint(3, 5) != ECPoint(5, 3)
    assert len({ECPoint(3, 5), ECPoint(3, 5)}) == 1


def test_rejects_partial_coordinates() -> None:
    with pytest.raises(CryptoException):
        ECPoint(x=3)
    with pytest.raises(CryptoException):
        ECPoint(y=5)


def test_rejects_infinity_with_coordinates() -> None:
    with pytest.raises(CryptoException):
        ECPoint(x=1, y=1, is_infinity=True)


def test_rejects_negative_and_non_integer_coordinates() -> None:
    with pytest.raises(CryptoException):
        ECPoint(-1, 2)
    with pytest.raises(CryptoException):
        ECPoint(1.5, 2)  # type: ignore[arg-type]


def test_point_is_immutable() -> None:
    point = ECPoint(3, 5)

    with pytest.raises(AttributeError):
        point.x = 7  # type: ignore[misc]
