# PH1 – Bảng vai trò lớp theo Design Pattern (T42)

Đối chiếu từng vai trò của ba mẫu thiết kế với lớp thật trong `src/secure_messaging/`
và test chứng minh. Tài liệu này là nguồn cho mục "Design Pattern" của báo cáo PH1
(`docs/report/ph1_crypto.md`).

## 1. Strategy

| Vai trò | Lớp / thành phần | Vị trí |
|---|---|---|
| Strategy (abstraction) | `ICipher` | `business/crypto/interfaces.py` |
| ConcreteStrategy | `AesCipher` | `business/crypto/aes_cipher.py` |
| ConcreteStrategy | `RsaCipher` | `business/crypto/rsa_cipher.py` |
| ConcreteStrategy | `EccCipher` | `business/crypto/ecc_cipher.py` |
| ConcreteStrategy (mở rộng) | `ChaCha20Cipher` | `business/crypto/chacha20_cipher.py` |
| Context | `SecureMessenger` (PH2) | `services/secure_messenger.py` |
| Client | `ConsoleMenu` (PH2) | `presentation/` |

`ICipher` chỉ có hai thao tác `encrypt` / `decrypt` cộng thuộc tính `cipher_type`.
Context giữ một `ICipher` và không biết lớp cụ thể; đổi thuật toán lúc chạy bằng
`set_cipher()`.

**Bằng chứng:**

- `tests/crypto/test_cipher_factory.py::test_strategy_can_be_switched_at_runtime`
- `tests/integration/test_crypto_integration.py::test_strategy_can_change_between_all_algorithms`
  (test tích hợp thuộc T45, hiện nằm trên `feature/crypto`)

## 2. Factory

| Vai trò | Lớp / thành phần | Vị trí |
|---|---|---|
| Product | `ICipher` | `business/crypto/interfaces.py` |
| ConcreteProduct | `AesCipher`, `ChaCha20Cipher`, `RsaCipher`, `EccCipher` | `business/crypto/` |
| Creator | `CipherFactory` | `services/cipher_factory.py` |
| Client | `SecureMessenger`, `ConsoleMenu` (PH2) | `services/`, `presentation/` |

`CipherFactory` giữ hai registry `CipherType -> creator`:

- `create_symmetric(cipher_type, key)` cho `AES`, `CHACHA20`;
- `create_asymmetric(cipher_type, key_pair)` cho `RSA`, `ECC`.

Không có `if/elif` theo tên thuật toán ở nơi gọi; việc chọn lớp cụ thể chỉ nằm trong
registry. Thuật toán mới được thêm bằng `register_symmetric` / `register_asymmetric`
mà không sửa logic factory.

**Bằng chứng:**

- `test_creates_aes_cipher`, `test_creates_rsa_cipher`, `test_creates_ecc_cipher`
- `test_registry_lists_supported_algorithms`
- `test_rejects_wrong_algorithm_kind`, `test_rejects_invalid_cipher_type`
- `test_rejects_non_callable_creator`

## 3. Template Method

| Vai trò | Thành phần | Vị trí |
|---|---|---|
| AbstractClass | `CipherBase` | `business/crypto/cipher_base.py` |
| Template method | `CipherBase.encrypt`, `CipherBase.decrypt` | `cipher_base.py` |
| Primitive operation | `do_encrypt`, `do_decrypt`, `_min_ciphertext_length` | lớp con cipher |
| ConcreteClass | `AesCipher`, `RsaCipher`, `EccCipher`, `ChaCha20Cipher` | `business/crypto/` |

Thứ tự cố định trong `CipherBase`:

1. `encrypt`: kiểm tra `data` là `bytes` và không rỗng → `do_encrypt` → kiểm tra
   kết quả là `bytes` không rỗng.
2. `decrypt`: kiểm tra `ciphertext` là `bytes` → kiểm tra độ dài tối thiểu
   (`_min_ciphertext_length`) → `do_decrypt`.

Lớp con chỉ override hook, không lặp lại phần kiểm tra.

**Bằng chứng:**

- `tests/crypto/test_cipher_base.py::test_subclass_only_overrides_hooks`
- `tests/crypto/test_cipher_base.py::test_encrypt_rejects_empty_data`
- `tests/crypto/test_cipher_base.py::test_decrypt_rejects_short_ciphertext`
- `tests/crypto/test_cipher_factory.py::test_factory_calls_subclass_hooks_through_template_method`
- `tests/crypto/test_chacha20_cipher.py::test_only_overrides_template_hooks`

## 4. Đánh giá mở rộng (T40)

Thêm `ChaCha20Cipher` cần:

| Thay đổi | Số dòng | Loại |
|---|---|---|
| File mới `business/crypto/chacha20_cipher.py` | 1 file | Bắt buộc |
| File mới `tests/crypto/test_chacha20_cipher.py` | 1 file | Bắt buộc |
| `CipherType.CHACHA20` | 1 dòng enum | **Ngoại lệ E1** |
| `import ChaCha20Cipher` | 1 dòng | Bắt buộc (kỹ thuật) |
| `register_symmetric(CipherType.CHACHA20, ChaCha20Cipher)` | 1 dòng | Bắt buộc |
| Sửa test cũ | **0 dòng** | — |

### 4.1 Ngoại lệ E1 — vì sao phải sửa `CipherType`

`CipherFactory` dùng `CipherType` làm khóa registry và `_register()` kiểm tra
`isinstance(cipher_type, CipherType)`. Vì vậy thuật toán mới **không thể** được đăng ký
nếu enum chưa có giá trị tương ứng: `CipherType.CHACHA20` là thay đổi **bắt buộc về
chức năng**, không phải để thuận tiện. Đây là ngoại lệ duy nhất so với quy định
"chỉ thêm file mới và 1 dòng đăng ký" (AGENTS.md), đã được nhóm thống nhất trước khi merge.

### 4.2 Vì sao không phải sửa test cũ

`test_registry_lists_supported_algorithms` (T37) kiểm tra **hợp đồng** thay vì tập tuyệt đối:
`AES` có mặt trong registry đối xứng, `RSA` và `ECC` có mặt trong registry bất đối xứng.
Nhờ vậy T40 không phải sửa test của task trước. Nếu test viết dạng `== {CipherType.AES}`
thì T40 buộc phải sửa test cũ — đã kiểm chứng: khôi phục assertion cũ cho
`1 failed, 140 passed`.

Không sửa `AesCipher`, `RsaCipher`, `EccCipher`, `CipherBase` hay test của chúng. Đây là
bằng chứng thực tế cho Open/Closed Principle ở mức registry của Factory, đồng thời cho thấy
Template Method giữ nguyên quy trình kiểm tra dùng chung.

**Bằng chứng:** `tests/crypto/test_chacha20_cipher.py::test_registered_in_factory_without_touching_other_ciphers`
