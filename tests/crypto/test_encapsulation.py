"""T53: rà soát đóng gói phần mật mã.

Kiểm tra ba yêu cầu của T53:

- trường dữ liệu nhạy cảm là private, không có thuộc tính public ngoài ``cipher_type``;
- constructor kiểm tra tham số và luôn ném ``CryptoException``;
- thông điệp lỗi thống nhất: có nội dung, nêu đúng tham số sai.
"""

from __future__ import annotations

import pytest

from secure_messaging.business.crypto.aes_cipher import AesCipher
from secure_messaging.business.crypto.chacha20_cipher import ChaCha20Cipher
from secure_messaging.business.crypto.ecc_cipher import EccCipher
from secure_messaging.business.crypto.rsa_cipher import RsaCipher
from secure_messaging.infrastructure.exceptions import CryptoException

KEY_ACCESSORS = {"key", "aes_key", "private_key", "key_pair", "private", "secret"}


def _public_fields(instance: object) -> list[str]:
    """Tên các thuộc tính instance không bắt đầu bằng dấu gạch dưới."""
    return sorted(name for name in vars(instance) if not name.startswith("_"))


def test_aes_cipher_has_no_public_fields() -> None:
    assert _public_fields(AesCipher(bytes(32))) == []


def test_chacha20_cipher_has_no_public_fields() -> None:
    assert _public_fields(ChaCha20Cipher(bytes(32))) == []


def test_rsa_cipher_has_no_public_fields(rsa_key_pair) -> None:
    assert _public_fields(RsaCipher(rsa_key_pair)) == []


def test_ecc_cipher_has_no_public_fields(ec_key_pair) -> None:
    assert _public_fields(EccCipher(ec_key_pair)) == []


def test_cipher_type_is_the_only_public_state(rsa_key_pair, ec_key_pair) -> None:
    """``cipher_type`` là API public; không có accessor nào trả về khóa."""
    for cipher in (
        AesCipher(bytes(32)),
        ChaCha20Cipher(bytes(32)),
        RsaCipher(rsa_key_pair),
        EccCipher(ec_key_pair),
    ):
        public = {name for name in dir(cipher) if not name.startswith("_")}
        assert "cipher_type" in public
        assert public & KEY_ACCESSORS == set()


def test_repr_and_str_do_not_leak_symmetric_key() -> None:
    key = bytes(range(32))

    for cipher in (AesCipher(key), ChaCha20Cipher(key)):
        text = repr(cipher) + str(cipher)
        assert repr(key) not in text
        assert key.hex() not in text


def test_repr_and_str_do_not_leak_rsa_private_numbers(rsa_key_pair) -> None:
    cipher = RsaCipher(rsa_key_pair)
    numbers = rsa_key_pair.private._get_material().private_numbers()
    text = repr(cipher) + str(cipher)

    assert str(numbers.d) not in text
    assert str(numbers.p) not in text
    assert str(numbers.q) not in text


@pytest.mark.parametrize("cipher_class", [AesCipher, ChaCha20Cipher])
@pytest.mark.parametrize("bad_key", [None, "khóa", bytearray(32), 32, [0] * 32])
def test_symmetric_cipher_rejects_non_bytes_key(cipher_class, bad_key) -> None:
    with pytest.raises(CryptoException) as error:
        cipher_class(bad_key)

    assert str(error.value).strip()


@pytest.mark.parametrize(
    "cipher_class, valid_size",
    [(AesCipher, 16), (ChaCha20Cipher, 32)],
)
def test_wrong_key_size_error_mentions_key_and_size(cipher_class, valid_size) -> None:
    with pytest.raises(CryptoException) as error:
        cipher_class(bytes(valid_size - 1))

    message = str(error.value)
    assert "Khóa" in message
    assert str(valid_size) in message


def test_rsa_cipher_rejects_object_without_key_contract() -> None:
    with pytest.raises(CryptoException) as error:
        RsaCipher(object())

    assert str(error.value).strip()


def test_rsa_cipher_rejects_ec_key_pair(ec_key_pair) -> None:
    with pytest.raises(CryptoException) as error:
        RsaCipher(ec_key_pair)

    assert "RSA" in str(error.value)


def test_ecc_cipher_rejects_rsa_key_pair(rsa_key_pair) -> None:
    with pytest.raises(CryptoException) as error:
        EccCipher(rsa_key_pair)

    assert "ECC" in str(error.value)


@pytest.mark.parametrize(
    "build_cipher",
    [
        lambda rsa_pair, ec_pair: AesCipher(bytes(32)),
        lambda rsa_pair, ec_pair: ChaCha20Cipher(bytes(32)),
        lambda rsa_pair, ec_pair: RsaCipher(rsa_pair),
        lambda rsa_pair, ec_pair: EccCipher(ec_pair),
    ],
)
def test_template_method_rejects_non_bytes_data(build_cipher, rsa_key_pair, ec_key_pair) -> None:
    """Kiểm tra tham số nằm ở CipherBase nên mọi cipher có cùng hành vi."""
    cipher = build_cipher(rsa_key_pair, ec_key_pair)

    with pytest.raises(CryptoException) as encrypt_error:
        cipher.encrypt("chuỗi")  # type: ignore[arg-type]
    with pytest.raises(CryptoException) as decrypt_error:
        cipher.decrypt("chuỗi")  # type: ignore[arg-type]

    assert "bytes" in str(encrypt_error.value)
    assert "bytes" in str(decrypt_error.value)


def test_error_messages_are_consistent(rsa_key_pair) -> None:
    """Mọi lỗi tham số đều là CryptoException với thông điệp bắt đầu bằng chữ hoa."""
    cases = (
        lambda: AesCipher(b""),
        lambda: ChaCha20Cipher(b""),
        lambda: RsaCipher(rsa_key_pair).encrypt(b""),
        lambda: RsaCipher(rsa_key_pair).decrypt(b""),
    )

    for case in cases:
        with pytest.raises(CryptoException) as error:
            case()
        message = str(error.value)
        assert message.strip()
        assert message[0].isupper()
