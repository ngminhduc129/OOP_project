# PH1 – Test report (kết quả chạy thật)

## 1. Môi trường

| Hạng mục | Giá trị |
|---|---|
| Python | 3.12.10 |
| cryptography | 50.0.2 |
| pytest | 9.2.0 |
| Hệ điều hành | Windows (win32) |
| Ngày chạy | 2026-11-21 |

## 2. Lệnh và kết quả tổng hợp

```text
python -m pytest
151 passed, 1 skipped in 0.23s
```

- Tổng số test đã chạy: **152** (151 pass, 1 skip, 0 fail).
- Skip: `tests/integration/test_crypto_integration.py::test_secure_messenger_uses_ph1_cipher`
  — lý do: PH2 chưa cung cấp `SecureMessenger`; test tự bật khi module xuất hiện.
- 18 test case được giao cho PH1 (TC01–TC13, TC27, TC32, TC33, TC35, TC36): **pass toàn bộ**.

## 3. Test case theo checklist (sheet `Test case`)

| ID | Lớp / Phương thức | Input | Kết quả mong đợi | Thực tế | Kết quả |
|---|---|---|---|---|---|
| TC01 | `BigIntCalculator.mod_pow` | b=4, e=13, m=497 | 445 | 445 | Pass |
| TC02 | `BigIntCalculator.mod_inverse` | a=17, m=3120 | 2753 | 2753 | Pass |
| TC03 | `BigIntCalculator.gcd` | a=48, b=18 | 6 | 6 | Pass |
| TC04 | `BigIntCalculator.is_probable_prime` | n=561 | False | False | Pass |
| TC05 | `AesCipher` (AES-GCM) | khóa/nonce/bản rõ 0x00, vector McGrew–Viega TC2 | ct `0388dace…`, tag `ab6e47d4…` | khớp | Pass |
| TC06 | `AesCipher.__init__` | khóa 15 byte | `CryptoException` | `CryptoException` | Pass |
| TC07 | `AesCipher.decrypt` | bản mã sửa 1 byte | `CryptoException` | `CryptoException` | Pass |
| TC08 | `AesCipher.encrypt` | cùng khóa, cùng bản rõ, 2 lần | bản mã khác nhau, nonce 12 byte | khác nhau, 12 byte | Pass |
| TC09 | `BigIntCalculator.mod_pow` (RSA nhỏ) | n=3233, e=17, m=65 | c=2790; giải mã 65 | 2790; 65 | Pass |
| TC10 | `RsaCipher.encrypt/decrypt` | RSA 2048 bit, chuỗi ngắn | bản rõ ban đầu | khớp | Pass |
| TC11 | `RsaCipher.encrypt` | bản rõ 1 MiB | giải mã đúng, không lỗi | khớp | Pass |
| TC12 | `EllipticCurve.is_on_curve` | G của P-256; (1,1) | True; False | True; False | Pass |
| TC13 | `EccCipher.encrypt/decrypt` | cặp khóa P-256, chuỗi bất kỳ | bản rõ khớp | khớp | Pass |
| TC27 | `ECPoint.is_at_infinity` | điểm vô cực; điểm G | True; False | True; False | Pass |
| TC32 | `EllipticCurve.validate_public_key` | ∞; x ≥ p; (1,1); G | 3 lỗi; G hợp lệ | đúng | Pass |
| TC33 | `RsaCipher.decrypt`, `EccCipher.decrypt` | bản mã cắt ngắn/sai trường | `CryptoException` | `CryptoException` | Pass |
| TC35 | `EccCipher.encrypt` | bản rõ 32 byte, khóa P-256 | 65+12+32+16 = 125 byte, 65 byte đầu là điểm hợp lệ | 125 byte, hợp lệ | Pass |
| TC36 | `RsaCipher.decrypt` | sửa 1 byte phần AES-GCM | `CryptoException` | `CryptoException` | Pass |

## 4. Kiểm thử bảo mật bổ sung (ngoài 18 TC)

| Nhóm | Test | Kết quả |
|---|---|---|
| Cách ly người dùng | `test_other_user_cannot_decrypt` (RSA, ECC) | Pass |
| Sai khóa riêng | `test_wrong_key_cannot_decrypt` (AES, ChaCha20) | Pass |
| Ephemeral/nonce mới | `test_every_encryption_uses_fresh_ephemeral_key_and_nonce`, `test_tc08_*`, `test_nonce_is_fresh` | Pass |
| Tamper từng trường | wrapped key, nonce, ciphertext, tag, ephemeral point, length prefix | Pass |
| Sai loại khóa | RSA nhận khóa ECC; ECC nhận RSA; RSA 1024 bit; ECDH P-384 | Pass |
| Định dạng | cắt ngắn, prefix sai, wrapped length sai, byte thừa, điểm ∞/ngoài cong/x ≥ p | Pass |
| Kiến trúc | `test_business_layer_does_not_import_upward`, `test_no_circular_imports_between_ph1_modules` | Pass |
| Pattern | Factory trả đúng lớp, đổi Strategy lúc chạy, Template Method chỉ override hook, ChaCha20 đăng ký | Pass |

## 5. Lỗi phát hiện và đã sửa trong quá trình phát triển

| Lỗi | Nguyên nhân | Cách sửa |
|---|---|---|
| `test_mod_inverse_accepts_negative_and_large_input` fail | Test so sánh nghịch đảo với chính `a` (sai logic test) | Kiểm tra `inverse * a % m == 1` |
| `test_mod_sqrt_returns_valid_root[10-17]` fail | 10 không phải thặng dư bậc hai mod 17 (dữ liệu test sai) | Đổi sang 8 (8 = 5² mod 17) |
| `test_double_point_with_zero_y_gives_infinity` không hợp lệ | Chọn điểm `(3,0)` không thuộc đường cong đã chọn | Dùng đường cong `y² = x³ + x mod 17` với điểm `(0,0)` |
| `EllipticCurve.named` trả instance khác nhau cho alias | `lru_cache` khóa theo chuỗi tên | Chuẩn hóa alias về một hàm `_p256()` được cache |
| `test_registry_lists_supported_algorithms` fail sau khi thêm ChaCha20 | Test cũ khẳng định tập đối xứng chỉ có AES | Đổi sang kiểm tra "chứa AES"; test extension khẳng định tập đầy đủ |

Không có test nào bị xóa, bị skip hoặc bị nới lỏng để đạt trạng thái xanh.

## 6. Chưa đạt / còn chờ

| Hạng mục | Trạng thái | Ghi chú |
|---|---|---|
| Integration với `SecureMessenger` | Skip | Chờ PH2 (Quang Chiến) cung cấp module |
| Kiểm tra `ruff` | Chưa chạy | `ruff` chưa cài trong môi trường; `pyproject.toml` đã cấu hình sẵn |
| T47 – chạy trên máy khác | Chưa thực hiện | Cần môi trường thứ hai và bản publish (T46 của PH2) |
