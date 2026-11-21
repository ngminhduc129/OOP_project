"""Test ``EllipticCurve`` P-256: TC12, TC32 và luật nhóm."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from secure_messaging.business.arithmetic.ec_point import ECPoint
from secure_messaging.business.arithmetic.elliptic_curve import EllipticCurve
from secure_messaging.infrastructure.exceptions import CryptoException


@pytest.fixture(scope="module")
def curve() -> EllipticCurve:
    return EllipticCurve.named("P-256")


def test_tc12_generator_is_on_curve_and_fake_point_is_not(curve: EllipticCurve) -> None:
    """TC12: G thuộc P-256, điểm (1,1) không thuộc."""
    assert curve.is_on_curve(curve.g) is True
    assert curve.is_on_curve(ECPoint(1, 1)) is False


def test_tc32_validate_public_key(curve: EllipticCurve) -> None:
    """TC32: điểm vô cực, x >= p, (1,1) bị từ chối; G hợp lệ (QT6)."""
    with pytest.raises(CryptoException):
        curve.validate_public_key(ECPoint.infinity())
    with pytest.raises(CryptoException):
        curve.validate_public_key(ECPoint(curve.p, 1))
    with pytest.raises(CryptoException):
        curve.validate_public_key(ECPoint(1, 1))

    curve.validate_public_key(curve.g)


def test_curve_parameters_match_nist_p256() -> None:
    curve = EllipticCurve.named("P-256")

    assert curve.p == 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    assert curve.a == curve.p - 3
    assert curve.n == 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    assert EllipticCurve.named("secp256r1") is curve


def test_named_rejects_unknown_curve() -> None:
    with pytest.raises(CryptoException):
        EllipticCurve.named("P-521")


def test_add_generator_to_itself_equals_double(curve: EllipticCurve) -> None:
    assert curve.add(curve.g, curve.g) == curve.double(curve.g)


def test_add_inverse_points_gives_infinity(curve: EllipticCurve) -> None:
    x, y = curve.g.x, curve.g.y
    assert x is not None and y is not None
    inverse = ECPoint(x, (-y) % curve.p)

    assert curve.is_on_curve(inverse)
    assert curve.add(curve.g, inverse).is_at_infinity()


def test_infinity_is_additive_identity(curve: EllipticCurve) -> None:
    infinity = ECPoint.infinity()

    assert curve.add(curve.g, infinity) == curve.g
    assert curve.add(infinity, curve.g) == curve.g
    assert curve.add(infinity, infinity).is_at_infinity()
    assert curve.double(infinity).is_at_infinity()


def test_double_point_with_zero_y_gives_infinity() -> None:
    # Trên đường cong y^2 = x^3 + x mod 17, điểm (0, 0) có y = 0.
    curve = EllipticCurve(17, 1, 0, 19, ECPoint(0, 0))
    zero_y = ECPoint(0, 0)

    assert curve.is_on_curve(zero_y)
    assert curve.double(zero_y).is_at_infinity()


def test_scalar_multiplication_matches_library(curve: EllipticCurve) -> None:
    """Đối chiếu phép nhân vô hướng tự cài với thư viện (chỉ trong test)."""
    for scalar in (1, 2, 3, 7, 12345):
        expected = ec.derive_private_key(scalar, ec.SECP256R1()).public_key().public_numbers()
        actual = curve.multiply(curve.g, scalar)

        assert (actual.x, actual.y) == (expected.x, expected.y)
        assert curve.is_on_curve(actual)


def test_multiply_by_one_returns_same_point(curve: EllipticCurve) -> None:
    assert curve.multiply(curve.g, 1) == curve.g


@pytest.mark.parametrize("scalar", [0, -1, -5])
def test_multiply_rejects_invalid_scalar(curve: EllipticCurve, scalar: int) -> None:
    with pytest.raises(CryptoException):
        curve.multiply(curve.g, scalar)


def test_multiply_rejects_scalar_not_less_than_order(curve: EllipticCurve) -> None:
    with pytest.raises(CryptoException):
        curve.multiply(curve.g, curve.n)


def test_multiply_rejects_point_not_on_curve(curve: EllipticCurve) -> None:
    with pytest.raises(CryptoException):
        curve.multiply(ECPoint(1, 1), 2)


def test_add_rejects_point_not_on_curve(curve: EllipticCurve) -> None:
    with pytest.raises(CryptoException):
        curve.add(curve.g, ECPoint(1, 1))


def test_rejects_singular_curve() -> None:
    # a = 0, b = 0 -> 4a^3 + 27b^2 = 0.
    with pytest.raises(CryptoException):
        EllipticCurve(17, 0, 0, 19, ECPoint(5, 1))


def test_rejects_composite_modulus() -> None:
    with pytest.raises(CryptoException):
        EllipticCurve(15, 2, 2, 19, ECPoint(5, 1))


def test_rejects_generator_not_on_curve() -> None:
    with pytest.raises(CryptoException):
        EllipticCurve(17, 2, 2, 19, ECPoint(1, 1))
