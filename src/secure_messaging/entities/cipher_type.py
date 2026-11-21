"""Định danh thuật toán mật mã dùng trong toàn hệ thống.

AES, RSA, ECC là lựa chọn thuật toán trong luồng mã hóa/giải mã (UC1, UC2),
không phải Use Case độc lập.
"""

from enum import Enum


class CipherType(Enum):
    """Thuật toán mã hóa được hệ thống hỗ trợ."""

    AES = "AES"
    RSA = "RSA"
    ECC = "ECC"
