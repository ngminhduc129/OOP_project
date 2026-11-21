"""Test ``BigIntCalculator``: TC01-TC04, TC09 và các trường hợp biên."""

from __future__ import annotations

import pytest

from secure_messaging.business.arithmetic.bigint_calculator import BigIntCalculator
from secure_messaging.infrastructure.exceptions import CryptoException


def test_tc01_mod_pow() -> None:
    """TC01: 4^13 mod 497 = 445."""
    assert BigIntCalculator.mod_pow(4, 13, 497) == 445


def test_tc02_mod_inverse() -> None:
    """TC02: 17^-1 mod 3120 = 2753."""
    assert BigIntCalculator.mod_inverse(17, 3120) == 2753


def test_tc03_gcd() -> None:
    """TC03: gcd(48, 18) = 6."""
    assert BigIntCalculator.gcd(48, 18) == 6


def test_tc04_carmichael_number_is_not_prime() -> None:
    """TC04: 561 là số Carmichael, phải trả False."""
    assert BigIntCalculator.is_probable_prime(561) is False


def test_tc09_small_rsa_math() -> None:
    """TC09: minh họa RSA nhỏ (không padding), chỉ kiểm tra số học."""
    n, e, message, d = 3233, 17, 65, 2753

    ciphertext = BigIntCalculator.mod_pow(message, e, n)
    recovered = BigIntCalculator.mod_pow(ciphertext, d, n)

    assert ciphertext == 2790
    assert recovered == message


@pytest.mark.parametrize(
    ("base", "exponent", "modulus"),
    [(2, 10, 1000), (123456789, 987654321, 1000000007), (7, 0, 13), (5, 1, 13)],
)
def test_mod_pow_matches_builtin_pow(base: int, exponent: int, modulus: int) -> None:
    """Đối chiếu với pow() của Python (chỉ trong test)."""
    assert BigIntCalculator.mod_pow(base, exponent, modulus) == pow(base, exponent, modulus)


def test_mod_pow_handles_negative_base() -> None:
    assert BigIntCalculator.mod_pow(-3, 3, 7) == pow(-3, 3, 7)


@pytest.mark.parametrize(("base", "exponent", "modulus"), [(2, -1, 7), (2, 3, 0), (2, 3, -5)])
def test_mod_pow_rejects_invalid_arguments(base: int, exponent: int, modulus: int) -> None:
    with pytest.raises(CryptoException):
        BigIntCalculator.mod_pow(base, exponent, modulus)


def test_gcd_edge_cases() -> None:
    assert BigIntCalculator.gcd(0, 0) == 0
    assert BigIntCalculator.gcd(0, 7) == 7
    assert BigIntCalculator.gcd(-48, 18) == 6
    assert BigIntCalculator.gcd(17, 3120) == 1


def test_mod_inverse_rejects_when_not_coprime() -> None:
    with pytest.raises(CryptoException):
        BigIntCalculator.mod_inverse(6, 9)


def test_mod_inverse_rejects_zero_and_bad_modulus() -> None:
    with pytest.raises(CryptoException):
        BigIntCalculator.mod_inverse(0, 7)
    with pytest.raises(CryptoException):
        BigIntCalculator.mod_inverse(3, 1)


def test_mod_inverse_accepts_negative_and_large_input() -> None:
    assert BigIntCalculator.mod_inverse(-1, 7) == 6
    modulus = 2**127 - 1
    inverse = BigIntCalculator.mod_inverse(12345, modulus)
    assert inverse * 12345 % modulus == 1


@pytest.mark.parametrize(("a", "prime"), [(4, 7), (3, 13), (8, 17), (0, 11)])
def test_mod_sqrt_returns_valid_root(a: int, prime: int) -> None:
    root = BigIntCalculator.mod_sqrt(a, prime)

    assert root * root % prime == a % prime


def test_mod_sqrt_rejects_non_residue() -> None:
    with pytest.raises(CryptoException):
        BigIntCalculator.mod_sqrt(5, 13)


def test_mod_sqrt_rejects_composite_modulus() -> None:
    with pytest.raises(CryptoException):
        BigIntCalculator.mod_sqrt(4, 15)


@pytest.mark.parametrize("n", [2, 3, 5, 97, 7919, 2**61 - 1])
def test_is_probable_prime_accepts_primes(n: int) -> None:
    assert BigIntCalculator.is_probable_prime(n) is True


@pytest.mark.parametrize("n", [-7, 0, 1, 4, 25, 341, 2047, 3233])
def test_is_probable_prime_rejects_composites(n: int) -> None:
    assert BigIntCalculator.is_probable_prime(n) is False


@pytest.mark.parametrize("bits", [8, 16, 32])
def test_generate_prime_has_requested_size(bits: int) -> None:
    prime = BigIntCalculator.generate_prime(bits)

    assert prime.bit_length() == bits
    assert BigIntCalculator.is_probable_prime(prime)


def test_generate_prime_rejects_too_few_bits() -> None:
    with pytest.raises(CryptoException):
        BigIntCalculator.generate_prime(1)


def test_rejects_bool_arguments() -> None:
    with pytest.raises(CryptoException):
        BigIntCalculator.gcd(True, 5)  # type: ignore[arg-type]
