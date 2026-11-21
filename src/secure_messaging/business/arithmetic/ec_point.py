"""Điểm trên đường cong elliptic (Value Object).

``ECPoint`` chỉ biểu diễn dữ liệu; mọi phép toán do ``EllipticCurve`` thực hiện.
Điểm vô cực được biểu diễn bằng ``ECPoint.infinity()`` (``x = y = None``).
"""

from __future__ import annotations

from dataclasses import dataclass

from secure_messaging.infrastructure.exceptions import CryptoException


@dataclass(frozen=True, slots=True)
class ECPoint:
    """Một điểm hữu hạn ``(x, y)`` hoặc điểm vô cực."""

    x: int | None = None
    y: int | None = None
    is_infinity: bool = False

    def __post_init__(self) -> None:
        if self.is_infinity:
            if self.x is not None or self.y is not None:
                raise CryptoException("Điểm vô cực không được có tọa độ")
            return
        if self.x is None or self.y is None:
            raise CryptoException("Điểm hữu hạn phải có đủ tọa độ x và y")
        for name, value in (("x", self.x), ("y", self.y)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise CryptoException(f"Tọa độ {name} của điểm phải là số nguyên")
            if value < 0:
                raise CryptoException(f"Tọa độ {name} của điểm phải không âm")

    @classmethod
    def infinity(cls) -> ECPoint:
        """Tạo điểm vô cực (phần tử trung hòa của phép cộng)."""
        return cls(is_infinity=True)

    def is_at_infinity(self) -> bool:
        """``True`` nếu đây là điểm vô cực."""
        return self.is_infinity
