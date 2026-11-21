"""Factory tạo chiến lược mã hóa theo ``CipherType``.

Việc khởi tạo cipher được tập trung tại đây; nơi gọi (``SecureMessenger``,
``ConsoleMenu``) chỉ biết ``ICipher``. Registry cho phép đăng ký thuật toán mới
(``ChaCha20Cipher``) mà không sửa logic của các cipher cũ.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, ClassVar

from secure_messaging.business.crypto.aes_cipher import AesCipher
from secure_messaging.business.crypto.ecc_cipher import EccCipher
from secure_messaging.business.crypto.interfaces import ICipher
from secure_messaging.business.crypto.rsa_cipher import RsaCipher
from secure_messaging.entities.cipher_type import CipherType
from secure_messaging.infrastructure.exceptions import CryptoException

SymmetricCreator = Callable[[bytes], ICipher]
AsymmetricCreator = Callable[[Any], ICipher]


class CipherFactory:
    """Registry + factory cho các chiến lược ``ICipher``."""

    _symmetric_creators: ClassVar[dict[CipherType, SymmetricCreator]] = {}
    _asymmetric_creators: ClassVar[dict[CipherType, AsymmetricCreator]] = {}

    @classmethod
    def register_symmetric(cls, cipher_type: CipherType, creator: SymmetricCreator) -> None:
        """Đăng ký cipher đối xứng (nhận khóa bytes)."""
        cls._register(cls._symmetric_creators, cipher_type, creator)

    @classmethod
    def register_asymmetric(cls, cipher_type: CipherType, creator: AsymmetricCreator) -> None:
        """Đăng ký cipher bất đối xứng (nhận cặp khóa)."""
        cls._register(cls._asymmetric_creators, cipher_type, creator)

    @classmethod
    def create_symmetric(cls, cipher_type: CipherType, key: bytes) -> ICipher:
        """Tạo cipher đối xứng theo loại thuật toán."""
        if not isinstance(cipher_type, CipherType):
            raise CryptoException("Loại thuật toán không hợp lệ")
        creator = cls._symmetric_creators.get(cipher_type)
        if creator is None:
            raise CryptoException(
                f"Thuật toán {cipher_type.value} không hỗ trợ mã hóa đối xứng"
            )
        return creator(key)

    @classmethod
    def create_asymmetric(cls, cipher_type: CipherType, key_pair: Any) -> ICipher:
        """Tạo cipher bất đối xứng theo loại thuật toán."""
        if not isinstance(cipher_type, CipherType):
            raise CryptoException("Loại thuật toán không hợp lệ")
        creator = cls._asymmetric_creators.get(cipher_type)
        if creator is None:
            raise CryptoException(
                f"Thuật toán {cipher_type.value} không hỗ trợ mã hóa bất đối xứng"
            )
        return creator(key_pair)

    @classmethod
    def supported_symmetric(cls) -> tuple[CipherType, ...]:
        """Danh sách thuật toán đối xứng đã đăng ký."""
        return tuple(cls._symmetric_creators)

    @classmethod
    def supported_asymmetric(cls) -> tuple[CipherType, ...]:
        """Danh sách thuật toán bất đối xứng đã đăng ký."""
        return tuple(cls._asymmetric_creators)

    @staticmethod
    def _register(
        registry: dict[CipherType, Any], cipher_type: CipherType, creator: Any
    ) -> None:
        if not isinstance(cipher_type, CipherType):
            raise CryptoException("Loại thuật toán không hợp lệ")
        if not callable(creator):
            raise CryptoException("Bộ khởi tạo cipher phải là callable")
        registry[cipher_type] = creator


CipherFactory.register_symmetric(CipherType.AES, AesCipher)
CipherFactory.register_asymmetric(CipherType.RSA, RsaCipher)
CipherFactory.register_asymmetric(CipherType.ECC, EccCipher)
