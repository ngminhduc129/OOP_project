# PH1 – Cryptography Subsystem (SecureMessagingSystem)

Tài liệu thành phần, design pattern, thuật toán và ánh xạ quy tắc nghiệp vụ của phân hệ 1
(Minh Đức). Mã nguồn: `src/secure_messaging/`. Test: `tests/crypto/`, `tests/integration/`.

## 1. Phạm vi

| Use case | Nội dung | Thành phần PH1 |
|---|---|---|
| UC1 | Mã hóa dữ liệu (AES / RSA / ECC) | `ICipher`, `CipherBase`, `AesCipher`, `RsaCipher`, `EccCipher`, `CipherFactory` |
| UC2 | Nhận và giải mã dữ liệu | các lớp trên (`decrypt`) |
| UC3 | Sinh cặp khóa | `EllipticCurve` (kiểm tra tham số/khóa ECC), `BigIntCalculator` (minh họa số học) |
| UC4 | Lưu và tải khóa | PH2 (`KeyService`, `FileKeyRepository`); PH1 chỉ cung cấp primitive mật mã |

AES, RSA, ECC là **lựa chọn thuật toán** trong UC1/UC2, không phải use case riêng.

## 2. Mười thành phần

| # | Thành phần | Trách nhiệm | Thuộc tính | Phương thức chính | Quan hệ |
|---|---|---|---|---|---|
| 1 | `ICipher` | Hợp đồng chiến lược mã hóa | `cipher_type` (property) | `encrypt(data)`, `decrypt(ciphertext)` | được `CipherBase` thực thi |
| 2 | `CipherType` | Định danh thuật toán | `AES`, `RSA`, `ECC`, `CHACHA20` | — | được Factory đọc |
| 3 | `CipherBase` | Template Method: kiểm tra đầu vào rồi gọi hook | `_cipher_type` | `encrypt`, `decrypt`, `do_encrypt*`, `do_decrypt*`, `_min_ciphertext_length*`, `_validate_bytes` | cha của 4 cipher |
| 4 | `AesCipher` | AES-GCM đối xứng | `_key`, `_aead` | `__init__(key)`, `generate_nonce`, `do_encrypt`, `do_decrypt`, `key_size` | kế thừa `CipherBase` |
| 5 | `RsaCipher` | RSA hybrid (OAEP bọc khóa AES, AES-GCM mã hóa dữ liệu) | `_key_pair`, `_public_key`, `_private_key` | `__init__(key_pair)`, `max_block_size`, `do_encrypt`, `do_decrypt` | dùng `AesCipher` |
| 6 | `EccCipher` | ECIES P-256 (ECDH + HKDF + AES-GCM) | `_key_pair`, `_curve`, `_public_key`, `_private_key` | `__init__(key_pair, curve=None)`, `derive_shared_key`, `do_encrypt`, `do_decrypt` | dùng `EllipticCurve`, `AesCipher` |
| 7 | `CipherFactory` | Factory + registry tạo `ICipher` | `_symmetric_creators`, `_asymmetric_creators` | `create_symmetric`, `create_asymmetric`, `register_symmetric`, `register_asymmetric`, `supported_*` | tạo 4 cipher, đọc `CipherType` |
| 8 | `BigIntCalculator` | Số học số lớn tự cài (học tập) | — | `gcd`, `mod_pow`, `mod_inverse`, `mod_sqrt`, `is_probable_prime`, `generate_prime` | được `EllipticCurve` dùng |
| 9 | `ECPoint` | Value Object điểm ECC | `x`, `y`, `is_infinity` | `infinity()`, `is_at_infinity()` | được `EllipticCurve` nhận/trả |
| 10 | `EllipticCurve` | Luật nhóm trên `y² = x³ + ax + b (mod p)` | `p`, `a`, `b`, `n`, `g` | `is_on_curve`, `validate_public_key`, `add`, `double`, `multiply`, `named()` | dùng `BigIntCalculator`, `ECPoint` |

Mở rộng: `ChaCha20Cipher` (kế thừa `CipherBase`, chỉ override hook, đăng ký vào Factory).

## 3. Design Pattern

### 3.1 Strategy

- **Abstraction**: `ICipher`.
- **Concrete strategies**: `AesCipher`, `RsaCipher`, `EccCipher`, `ChaCha20Cipher`.
- **Context**: `SecureMessenger` (PH2) gọi `set_cipher()`; trong PH1, `MessengerStub` của test
  mô phỏng đúng hợp đồng này.
- **Lợi ích**: đổi thuật toán lúc chạy (`AES → RSA → ECC → ChaCha20`) mà nơi gọi không đổi.
  Bằng chứng: `tests/crypto/test_cipher_factory.py::test_strategy_can_be_switched_at_runtime`,
  `tests/integration/test_crypto_integration.py::test_strategy_can_change_between_all_algorithms`.

### 3.2 Factory

- `CipherFactory` giữ hai registry (`CipherType -> creator`).
- `create_symmetric(type, key)` cho AES/ChaCha20; `create_asymmetric(type, key_pair)` cho RSA/ECC.
- Không có `if/elif` chọn thuật toán ngoài Factory; nơi gọi chỉ nhận `ICipher`.
- Đăng ký mặc định ở cuối `cipher_factory.py`; extension chỉ thêm một dòng đăng ký.

### 3.3 Template Method

`CipherBase.encrypt` cố định thứ tự:

1. kiểm tra `data` là `bytes` và không rỗng;
2. gọi hook `do_encrypt`;
3. kiểm tra kết quả là `bytes` không rỗng.

`CipherBase.decrypt` kiểm tra kiểu, kiểm tra độ dài tối thiểu (`_min_ciphertext_length`),
rồi mới gọi `do_decrypt`. Lớp con **chỉ** override `do_encrypt`, `do_decrypt`,
`_min_ciphertext_length`; test `test_subclass_only_overrides_hooks` kiểm tra
`type(cipher).encrypt is CipherBase.encrypt`.

### 3.4 Đánh giá mở rộng (checklist 12)

Thêm `ChaCha20Cipher` cần: 1 file mới + 1 giá trị enum + 2 dòng đăng ký; không sửa
`AesCipher`/`RsaCipher`/`EccCipher`/`CipherBase`. Điều này chứng minh OCP ở mức thực tế,
đồng thời cho thấy Factory registry là điểm mở rộng duy nhất.

## 4. Thuật toán

### 4.1 AES-GCM

- Khóa 16/24/32 byte (AES-128/192/256), nonce 96 bit, tag 128 bit.
- Nonce sinh mới bằng `secrets.token_bytes(12)` cho mỗi lần mã hóa (QT2).
- Bản mã: `nonce (12) || ciphertext || tag (16)`.
- Tag sai (sửa bản mã, sai khóa) → `CryptoException` (QT3).
- Vector kiểm chứng: McGrew–Viega Test Case 2 (TC05).

### 4.2 RSA hybrid

- RSA-OAEP: digest SHA-256, MGF1-SHA256, label rỗng.
- Khóa RSA tối thiểu 2048 bit (QT5).
- Mỗi lần mã hóa: sinh khóa AES-256 mới + nonce mới, mã hóa dữ liệu bằng AES-GCM,
  bọc khóa AES bằng RSA-OAEP.
- Bản mã (QT11): `wrapped_length (2 byte) || wrapped_key || nonce (12) || ct+tag`.
- Với khóa 2048 bit, `max_block_size() = 256 - 64 - 2 = 190` byte; dữ liệu lớn hơn
  vẫn mã hóa được vì chỉ khóa AES được bọc (TC11: 1 MiB).

### 4.3 ECC-ECIES

- Đường cong NIST P-256, ECDH, HKDF-SHA256 (`salt=None`,
  `info=b"SecureMessagingSystem/ECIES/P-256/AES-256-GCM/v1"`), AES-256-GCM.
- Bản mã (QT11): `ephemeral_public (65 byte, không nén) || nonce (12) || ct+tag`.
- Mỗi lần mã hóa sinh ephemeral key mới; khóa AES dẫn xuất lại ở phía nhận.
- Điểm ephemeral và khóa công khai người nhận được kiểm tra bằng `EllipticCurve`
  (`validate_public_key`, QT6) trước khi ECDH.

### 4.4 BigIntCalculator

| Phương thức | Thuật toán |
|---|---|
| `gcd` | Euclid, trả số không âm |
| `mod_pow` | bình phương-nhân, kiểm tra modulus > 0, số mũ ≥ 0 |
| `mod_inverse` | Euclid mở rộng, ném lỗi khi `gcd != 1` |
| `mod_sqrt` | Tonelli–Shanks, kiểm tra modulus nguyên tố lẻ và ký hiệu Legendre |
| `is_probable_prime` | Miller–Rabin: 12 cơ sở nhỏ + 8 cơ sở ngẫu nhiên khi n ≥ 2^64 |
| `generate_prime` | `secrets.randbits`, bật bit cao và bit thấp |

Lớp này **không** dùng cho khóa thật; RSA/ECC thật dùng `cryptography`.

### 4.5 EllipticCurve

- Kiểm tra `p` nguyên tố, `4a³ + 27b² ≠ 0 (mod p)`, `n > 1`, `G` hợp lệ khi khởi tạo.
- `is_on_curve`: điểm vô cực hợp lệ; tọa độ ngoài `[0, p-1]` → `False`.
- `validate_public_key`: từ chối điểm vô cực, tọa độ ngoài miền, điểm ngoài đường cong (QT6).
- `add`/`double`: xử lý điểm vô cực, hai điểm đối nhau (→ vô cực), hai điểm trùng nhau (→ double).
- `multiply(point, scalar)`: double-and-add, scalar trong `[1, n-1]`, kiểm tra kết quả trên đường cong.

## 5. Ánh xạ quy tắc nghiệp vụ

| Mã | Nội dung (sheet `Quy tắc`) | Lớp.Phương thức | Exception | Test |
|---|---|---|---|---|
| QT1 | Khóa AES dài 16/24/32 byte | `AesCipher.__init__` | `CryptoException` | TC06 |
| QT2 | Nonce 96 bit mới mỗi lần mã hóa | `AesCipher.generate_nonce`, `do_encrypt` | — (luôn sinh mới) | TC08 |
| QT3 | Bản mã GCM bị sửa → lỗi xác thực | `AesCipher.do_decrypt`, `RsaCipher.do_decrypt` | `CryptoException` | TC07, TC36 |
| QT5 | Dữ liệu lớn dùng hybrid; khóa RSA < 2048 bit bị từ chối | `RsaCipher.__init__`, `do_encrypt`, `do_decrypt` | `CryptoException` | TC11 |
| QT6 | Điểm/khóa ECC phải hợp lệ | `EllipticCurve.is_on_curve`, `validate_public_key`, `EccCipher.__init__`, `do_decrypt` | `CryptoException` | TC12, TC32 |
| QT11 | Đúng định dạng bản mã RSA hybrid/ECIES | `RsaCipher.do_decrypt`, `EccCipher.do_encrypt`, `do_decrypt` | `CryptoException` | TC33, TC35 |

## 6. Hợp đồng tích hợp PH2

| Hợp đồng | PH1 sử dụng | Ghi chú |
|---|---|---|
| `CryptoException` | `secure_messaging.infrastructure.exceptions` | **Dùng chung**; PH2 kế thừa cho `KeyRevokedException`, `KeyExpiredException`; không định nghĩa lại |
| `KeyPair.public.export()` | trả DER bytes (SubjectPublicKeyInfo) | nạp một lần trong `__init__` của cipher |
| `KeyPair.private._get_material()` | trả object private key của `cryptography` | không serialize lại; `_key_io` chấp nhận thêm DER bytes để tương thích |
| `SecureMessenger.set_cipher/send/receive` | context của Strategy | PH1 không phụ thuộc trực tiếp; integration test skip khi chưa có |

PH1 **không** tạo `KeyPair`, **không** đọc/ghi file, **không** `print/input`, **không** log khóa.
Test PH1 dùng `FakeKeyPair` trong `tests/conftest.py` tuân thủ đúng hai hợp đồng trên.

## 7. Thay đổi interface so với UML gốc

| Thay đổi | Lý do | Ảnh hưởng PH2 |
|---|---|---|
| Thêm `CipherType.CHACHA20` | Bắt buộc để đăng ký extension (T40) | Chỉ thêm giá trị enum, không phá code cũ |
| `EllipticCurve` có `g` và `validate_public_key` | Sheet `Lớp` và QT6 yêu cầu | Không |
| Method đặt `snake_case` | PEP 8 + README | Không (UML `.mmd` đã đồng bộ) |

## 8. Chạy thử

```bash
pip install -e ".[dev]"
pytest tests/crypto tests/integration
pytest
```
