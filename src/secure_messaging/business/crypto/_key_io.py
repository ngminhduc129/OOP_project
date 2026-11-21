"""Nạp khóa từ hợp đồng của PH2 (``PublicKey.export`` / ``PrivateKey._get_material``).

Đây là **nơi duy nhất** trong PH1 chuyển dữ liệu khóa sang đối tượng của thư
viện ``cryptography``. Nếu PH2 đổi cách trả khóa, chỉ cần sửa module này.

Hợp đồng đã thống nhất:
- ``PublicKey.export()`` -> DER bytes (SubjectPublicKeyInfo).
- ``PrivateKey._get_material()`` -> đối tượng private key của ``cryptography``
  (chấp nhận thêm DER bytes để tương thích khi tích hợp).
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from secure_messaging.infrastructure.exceptions import CryptoException

PublicKeyObject = rsa.RSAPublicKey | ec.EllipticCurvePublicKey
PrivateKeyObject = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


def load_public_key(material: Any) -> PublicKeyObject:
    """Chuyển DER/PEM bytes của khóa công khai thành đối tượng thư viện."""
    if not isinstance(material, bytes) or not material:
        raise CryptoException("Khóa công khai phải là bytes DER/PEM không rỗng")

    try:
        key = serialization.load_der_public_key(material)
    except (ValueError, TypeError):
        try:
            key = serialization.load_pem_public_key(material)
        except (ValueError, TypeError) as exc:
            raise CryptoException("Khóa công khai không đúng định dạng DER/PEM") from exc

    if not isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        raise CryptoException("Loại khóa công khai không được hỗ trợ")
    return key


def load_private_key(material: Any) -> PrivateKeyObject:
    """Trả về đối tượng private key; không serialize lại nếu đã là object."""
    if isinstance(material, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        return material
    if isinstance(material, bytes) and material:
        try:
            key = serialization.load_der_private_key(material, password=None)
        except (ValueError, TypeError) as exc:
            raise CryptoException("Khóa riêng không đúng định dạng DER") from exc
        if isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            return key
    raise CryptoException("Khóa riêng phải là đối tượng private key hợp lệ")
