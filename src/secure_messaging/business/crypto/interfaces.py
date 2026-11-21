"""Hợp đồng chiến lược mã hóa (Strategy Pattern).

``ICipher`` là abstraction mà tầng dịch vụ (``SecureMessenger``) sử dụng.
Khóa được truyền một lần khi khởi tạo chiến lược cụ thể, không truyền lại
trong mỗi lời gọi ``encrypt``/``decrypt``.
"""

from abc import ABC, abstractmethod

from secure_messaging.entities.cipher_type import CipherType


class ICipher(ABC):
    """Giao diện chung cho mọi thuật toán mã hóa."""

    @property
    @abstractmethod
    def cipher_type(self) -> CipherType:
        """Thuật toán mà chiến lược này cài đặt."""

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """Mã hóa ``data`` và trả về bản mã tự chứa (kèm nonce/tag)."""

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Giải mã ``ciphertext``; ném ``CryptoException`` nếu không hợp lệ."""
