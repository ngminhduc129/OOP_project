"""Integration test PH1: Factory -> ICipher -> round-trip, đổi chiến lược, tầng.

Các test xuyên phân hệ với ``SecureMessenger`` được đánh dấu skip khi PH2 chưa
cung cấp lớp đó — không giả lập kết quả pass.
"""

from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path

import pytest

from secure_messaging.business.crypto.interfaces import ICipher
from secure_messaging.entities.cipher_type import CipherType
from secure_messaging.infrastructure.exceptions import CryptoException
from secure_messaging.services.cipher_factory import CipherFactory

SOURCE_ROOT = Path(__file__).resolve().parents[2] / "src" / "secure_messaging"
PLAINTEXT = b"Thong diep tich hop giua cac thuat toan."


class MessengerStub:
    """Context mô phỏng ``SecureMessenger`` (Strategy Context) cho PH1."""

    def __init__(self, cipher: ICipher) -> None:
        self._cipher = cipher

    def set_cipher(self, cipher: ICipher) -> None:
        self._cipher = cipher

    def send(self, data: bytes) -> bytes:
        return self._cipher.encrypt(data)

    def receive(self, ciphertext: bytes) -> bytes:
        return self._cipher.decrypt(ciphertext)


def _build_cipher(algorithm: str, rsa_key_pair, ec_key_pair) -> ICipher:
    if algorithm == "AES":
        return CipherFactory.create_symmetric(CipherType.AES, bytes(range(32)))
    if algorithm == "CHACHA20":
        return CipherFactory.create_symmetric(CipherType.CHACHA20, bytes(range(32)))
    if algorithm == "RSA":
        return CipherFactory.create_asymmetric(CipherType.RSA, rsa_key_pair)
    if algorithm == "ECC":
        return CipherFactory.create_asymmetric(CipherType.ECC, ec_key_pair)
    raise AssertionError(f"Thuật toán không hỗ trợ trong test: {algorithm}")


@pytest.mark.parametrize("algorithm", ["AES", "CHACHA20", "RSA", "ECC"])
def test_every_algorithm_roundtrips_through_factory(
    algorithm: str, rsa_key_pair, ec_key_pair
) -> None:
    cipher = _build_cipher(algorithm, rsa_key_pair, ec_key_pair)

    assert isinstance(cipher, ICipher)
    assert cipher.decrypt(cipher.encrypt(PLAINTEXT)) == PLAINTEXT


def test_strategy_can_change_between_all_algorithms(rsa_key_pair, ec_key_pair) -> None:
    messenger = MessengerStub(_build_cipher("AES", rsa_key_pair, ec_key_pair))

    for algorithm in ("AES", "CHACHA20", "RSA", "ECC", "AES"):
        messenger.set_cipher(_build_cipher(algorithm, rsa_key_pair, ec_key_pair))
        assert messenger.receive(messenger.send(PLAINTEXT)) == PLAINTEXT


def test_ciphertext_from_another_algorithm_is_rejected(rsa_key_pair, ec_key_pair) -> None:
    aes_ciphertext = _build_cipher("AES", rsa_key_pair, ec_key_pair).encrypt(PLAINTEXT)
    rsa_ciphertext = _build_cipher("RSA", rsa_key_pair, ec_key_pair).encrypt(PLAINTEXT)

    with pytest.raises(CryptoException):
        _build_cipher("CHACHA20", rsa_key_pair, ec_key_pair).decrypt(aes_ciphertext)
    with pytest.raises(CryptoException):
        _build_cipher("ECC", rsa_key_pair, ec_key_pair).decrypt(rsa_ciphertext)


def test_plaintext_is_never_recovered_with_wrong_key(
    rsa_key_pair, ec_key_pair, rsa_key_pair_other, ec_key_pair_other
) -> None:
    for_alice_rsa = _build_cipher("RSA", rsa_key_pair, ec_key_pair).encrypt(PLAINTEXT)
    for_alice_ecc = _build_cipher("ECC", rsa_key_pair, ec_key_pair).encrypt(PLAINTEXT)

    with pytest.raises(CryptoException):
        CipherFactory.create_asymmetric(CipherType.RSA, rsa_key_pair_other).decrypt(for_alice_rsa)
    with pytest.raises(CryptoException):
        CipherFactory.create_asymmetric(CipherType.ECC, ec_key_pair_other).decrypt(for_alice_ecc)


def test_large_payload_roundtrip_for_hybrid_schemes(rsa_key_pair, ec_key_pair) -> None:
    payload = b"Z" * (256 * 1024)

    for algorithm in ("RSA", "ECC"):
        cipher = _build_cipher(algorithm, rsa_key_pair, ec_key_pair)
        assert cipher.decrypt(cipher.encrypt(payload)) == payload


def test_business_layer_does_not_import_upward() -> None:
    """Chiều gọi: business không được import services/presentation."""
    forbidden = ("secure_messaging.services", "secure_messaging.presentation")
    business_root = SOURCE_ROOT / "business"

    for module_path in business_root.rglob("*.py"):
        source = module_path.read_text(encoding="utf-8")
        for marker in forbidden:
            assert marker not in source, f"{module_path} import ngược lên {marker}"


def test_no_circular_imports_between_ph1_modules() -> None:
    modules = [
        "secure_messaging.entities.cipher_type",
        "secure_messaging.infrastructure.exceptions",
        "secure_messaging.business.crypto.interfaces",
        "secure_messaging.business.crypto.cipher_base",
        "secure_messaging.business.crypto.aes_cipher",
        "secure_messaging.business.crypto.chacha20_cipher",
        "secure_messaging.business.crypto.rsa_cipher",
        "secure_messaging.business.crypto.ecc_cipher",
        "secure_messaging.business.arithmetic.bigint_calculator",
        "secure_messaging.business.arithmetic.ec_point",
        "secure_messaging.business.arithmetic.elliptic_curve",
        "secure_messaging.services.cipher_factory",
    ]

    for name in modules:
        assert importlib.import_module(name) is not None


SECURE_MESSENGER_AVAILABLE = (
    importlib.util.find_spec("secure_messaging.services.secure_messenger") is not None
)


@pytest.mark.skipif(
    not SECURE_MESSENGER_AVAILABLE,
    reason="PH2 chưa cung cấp SecureMessenger (tích hợp sẽ bật khi C hoàn thành)",
)
def test_secure_messenger_uses_ph1_cipher(rsa_key_pair) -> None:
    from secure_messaging.services.secure_messenger import SecureMessenger  # noqa: PLC0415

    messenger = SecureMessenger()
    messenger.set_cipher(CipherFactory.create_asymmetric(CipherType.RSA, rsa_key_pair))

    assert messenger.receive(messenger.send(PLAINTEXT)) == PLAINTEXT
