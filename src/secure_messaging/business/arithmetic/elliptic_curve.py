"""Số học đường cong elliptic ``y^2 = x^3 + a*x + b (mod p)``.

Tự cài để học tập và minh họa thuật toán (cộng, nhân đôi, nhân vô hướng
double-and-add). Luồng ECIES thật trong ``EccCipher`` dùng primitive của thư
viện ``cryptography``; lớp này dùng để kiểm tra điểm/khóa công khai (QT6).
"""

from __future__ import annotations

from functools import lru_cache

from secure_messaging.business.arithmetic.bigint_calculator import BigIntCalculator
from secure_messaging.business.arithmetic.ec_point import ECPoint
from secure_messaging.infrastructure.exceptions import CryptoException

_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


class EllipticCurve:
    """Đường cong ngắn Weierstrass trên trường nguyên tố."""

    def __init__(self, p: int, a: int, b: int, n: int, g: ECPoint) -> None:
        for name, value in (("p", p), ("a", a), ("b", b), ("n", n)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise CryptoException(f"Tham số {name} của đường cong phải là số nguyên")
        if p <= 3:
            raise CryptoException("Modulus p của đường cong phải lớn hơn 3")
        if not BigIntCalculator.is_probable_prime(p):
            raise CryptoException("Modulus p của đường cong phải là số nguyên tố")
        if (4 * a**3 + 27 * b**2) % p == 0:
            raise CryptoException("Đường cong suy biến: 4a^3 + 27b^2 phải khác 0 modulo p")
        if n <= 1:
            raise CryptoException("Bậc n của nhóm phải lớn hơn 1")
        if not isinstance(g, ECPoint):
            raise CryptoException("Điểm cơ sở G phải là ECPoint")

        self._p = p
        self._a = a % p
        self._b = b % p
        self._n = n
        self._g = g

        self.validate_public_key(g)

    @property
    def p(self) -> int:
        """Modulus của trường nguyên tố."""
        return self._p

    @property
    def a(self) -> int:
        """Hệ số a của phương trình đường cong."""
        return self._a

    @property
    def b(self) -> int:
        """Hệ số b của phương trình đường cong."""
        return self._b

    @property
    def n(self) -> int:
        """Bậc của nhóm điểm."""
        return self._n

    @property
    def g(self) -> ECPoint:
        """Điểm cơ sở (generator)."""
        return self._g

    @staticmethod
    def named(name: str = "P-256") -> EllipticCurve:
        """Trả về đường cong chuẩn theo tên (chỉ hỗ trợ NIST P-256)."""
        if name not in {"P-256", "secp256r1", "prime256v1"}:
            raise CryptoException(f"Không hỗ trợ đường cong: {name}")
        return EllipticCurve._p256()

    @staticmethod
    @lru_cache(maxsize=1)
    def _p256() -> EllipticCurve:
        return EllipticCurve(_P256_P, _P256_A, _P256_B, _P256_N, ECPoint(_P256_GX, _P256_GY))

    def is_on_curve(self, point: ECPoint) -> bool:
        """Kiểm tra điểm nằm trên đường cong (điểm vô cực luôn hợp lệ)."""
        if not isinstance(point, ECPoint):
            raise CryptoException("Đối tượng kiểm tra phải là ECPoint")
        if point.is_at_infinity():
            return True
        x, y = point.x, point.y
        assert x is not None and y is not None
        if not (0 <= x < self._p and 0 <= y < self._p):
            return False
        return (y * y - (x * x * x + self._a * x + self._b)) % self._p == 0

    def validate_public_key(self, point: ECPoint) -> None:
        """Kiểm tra khóa công khai ECC (QT6); ném ``CryptoException`` nếu sai."""
        if not isinstance(point, ECPoint):
            raise CryptoException("Khóa công khai ECC phải là ECPoint")
        if point.is_at_infinity():
            raise CryptoException("Khóa công khai ECC không được là điểm vô cực")
        x, y = point.x, point.y
        assert x is not None and y is not None
        if not (0 <= x < self._p and 0 <= y < self._p):
            raise CryptoException("Tọa độ khóa công khai ECC phải nằm trong [0, p-1]")
        if not self.is_on_curve(point):
            raise CryptoException("Khóa công khai ECC không nằm trên đường cong P-256")

    def add(self, point1: ECPoint, point2: ECPoint) -> ECPoint:
        """Cộng hai điểm trên đường cong."""
        self._require_curve_point(point1)
        self._require_curve_point(point2)

        if point1.is_at_infinity():
            return point2
        if point2.is_at_infinity():
            return point1

        x1, y1 = point1.x, point1.y
        x2, y2 = point2.x, point2.y
        assert x1 is not None and y1 is not None and x2 is not None and y2 is not None

        if x1 == x2:
            if (y1 + y2) % self._p == 0:
                return ECPoint.infinity()
            return self.double(point1)

        slope = (y2 - y1) * BigIntCalculator.mod_inverse(x2 - x1, self._p) % self._p
        x3 = (slope * slope - x1 - x2) % self._p
        y3 = (slope * (x1 - x3) - y1) % self._p
        return self._checked(ECPoint(x3, y3))

    def double(self, point: ECPoint) -> ECPoint:
        """Nhân đôi một điểm."""
        self._require_curve_point(point)

        if point.is_at_infinity():
            return ECPoint.infinity()
        x, y = point.x, point.y
        assert x is not None and y is not None
        if y == 0:
            return ECPoint.infinity()

        slope = (3 * x * x + self._a) * BigIntCalculator.mod_inverse(2 * y, self._p) % self._p
        x3 = (slope * slope - 2 * x) % self._p
        y3 = (slope * (x - x3) - y) % self._p
        return self._checked(ECPoint(x3, y3))

    def multiply(self, point: ECPoint, scalar: int) -> ECPoint:
        """Nhân vô hướng ``scalar * point`` bằng double-and-add."""
        self._require_curve_point(point)
        if isinstance(scalar, bool) or not isinstance(scalar, int):
            raise CryptoException("Hệ số nhân vô hướng phải là số nguyên")
        if not 1 <= scalar < self._n:
            raise CryptoException(f"Hệ số nhân vô hướng phải nằm trong [1, n-1] (n = {self._n})")

        result = ECPoint.infinity()
        addend = point
        remaining = scalar
        while remaining:
            if remaining & 1:
                result = self.add(result, addend)
            addend = self.double(addend)
            remaining >>= 1
        return result

    def _require_curve_point(self, point: ECPoint) -> None:
        if not isinstance(point, ECPoint):
            raise CryptoException("Phép toán đường cong yêu cầu ECPoint")
        if not self.is_on_curve(point):
            raise CryptoException("Điểm không nằm trên đường cong")

    def _checked(self, point: ECPoint) -> ECPoint:
        if not self.is_on_curve(point):
            raise CryptoException("Kết quả phép toán không nằm trên đường cong")
        return point
