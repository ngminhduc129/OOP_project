from secure_messaging.infrastructure.exceptions import CryptoException


class KeyRevokedException(CryptoException):
    """The repository marks this key as revoked."""


class KeyExpiredException(CryptoException):
    """The validity period has ended."""
