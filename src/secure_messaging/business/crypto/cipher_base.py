"""Khung xử lý chung cho mọi thuật toán mã hóa (Template Method Pattern).

``encrypt``/``decrypt`` giữ cố định thứ tự: kiểm tra kiểu dữ liệu, kiểm tra
độ dài tối thiểu của bản mã, rồi mới gọi hook ``do_encrypt``/``do_decrypt``
do lớp con cài đặt. Lớp con chỉ override các hook, không lặp lại quy trình.
"""

from abc import abstractmethod

from secure_messaging.business.crypto.interfaces import ICipher
from secure_messaging.entities.cipher_type import CipherType
from secure_messaging.infrastructure.exceptions import CryptoException


class CipherBase(ICipher):
    """Lớp cơ sở triển khai Template Method cho các cipher cụ thể."""

    def __init__(self, cipher_type: CipherType) -> None:
        if not isinstance(cipher_type, CipherType):
            raise CryptoException("Loại thuật toán không hợp lệ")
        self._cipher_type = cipher_type

    @property
    def cipher_type(self) -> CipherType:
        """Thuật toán của lớp con."""
        return self._cipher_type

    def encrypt(self, data: bytes) -> bytes:
        """Template Method: kiểm tra đầu vào -> hook -> kiểm tra đầu ra."""
        self._validate_bytes(data, "Dữ liệu cần mã hóa")
        if not data:
            raise CryptoException("Dữ liệu cần mã hóa không được rỗng")
        ciphertext = self.do_encrypt(data)
        self._validate_bytes(ciphertext, "Bản mã")
        if not ciphertext:
            raise CryptoException("Kết quả mã hóa không hợp lệ")
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Template Method: kiểm tra độ dài tối thiểu -> hook."""
        self._validate_bytes(ciphertext, "Bản mã")
        minimum = self._min_ciphertext_length()
        if len(ciphertext) < minimum:
            raise CryptoException(
                f"Bản mã không hợp lệ: cần tối thiểu {minimum} byte, nhận {len(ciphertext)} byte"
            )
        plaintext = self.do_decrypt(ciphertext)
        self._validate_bytes(plaintext, "Bản rõ")
        return plaintext

    @abstractmethod
    def do_encrypt(self, data: bytes) -> bytes:
        """Hook mã hóa do lớp con cài đặt."""

    @abstractmethod
    def do_decrypt(self, ciphertext: bytes) -> bytes:
        """Hook giải mã do lớp con cài đặt."""

    @abstractmethod
    def _min_ciphertext_length(self) -> int:
        """Độ dài tối thiểu (byte) của một bản mã hợp lệ theo định dạng của lớp con."""

    @staticmethod
    def _validate_bytes(value: object, name: str) -> None:
        if not isinstance(value, bytes):
            raise CryptoException(f"{name} phải là kiểu bytes")
