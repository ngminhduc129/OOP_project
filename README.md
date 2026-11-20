# SecureMessagingSystem

Hệ thống bảo mật dữ liệu và chữ ký số chạy trên console, viết bằng Python theo hướng lập trình hướng đối tượng. Hệ thống hỗ trợ mã hóa/giải mã bằng **AES-GCM, RSA-OAEP, ECC-ECIES**, ký và xác minh chữ ký bằng **RSA-PSS, ECDSA**, quản lý cặp khóa, thu hồi khóa và ghi nhật ký hoạt động.

> Đây là bài tập lớn môn Lập trình hướng đối tượng. Mã nguồn phục vụ học tập, chưa qua kiểm định bảo mật, **không dùng để bảo vệ dữ liệu thật**.

## Thành viên

| Thành viên | Phân hệ | Phụ trách chính |
|---|---|---|
| Minh Đức | 1 – Mật mã | AES, RSA, ECC, số học số lớn, đường cong elliptic, `CipherFactory` |
| Quang Chiến | 2 – Khóa, chữ ký, ứng dụng | Khóa, ký số, kho khóa, `SecureMessenger`, nhật ký, giao diện, đóng gói |

## Chức năng

| UC | Tên | Tác nhân | Hàm điều khiển |
|---|---|---|---|
| UC1 | Mã hóa dữ liệu | Người dùng | `ConsoleMenu.handle_encrypt` |
| UC2 | Nhận dữ liệu và giải mã | Người dùng | `SecureMessenger.receive` |
| UC3 | Sinh cặp khóa công khai và khóa riêng tư | Người dùng | `KeyService.generate` |
| UC4 | Lưu và tải cặp khóa từ kho lưu trữ | Người dùng | `KeyService.get`, `IKeyRepository.save/load` |
| UC5 | Ký số tài liệu | Người dùng | `ConsoleMenu.handle_sign` |
| UC6 | Xác minh chữ ký số | Người dùng | `ConsoleMenu.handle_verify` |
| UC7 | Thu hồi khóa | Quản trị viên | `ConsoleMenu.revoke_key` |
| UC8 | Xem nhật ký hoạt động hệ thống | Quản trị viên | `ConsoleMenu.view_log` |

AES, RSA, ECC (mã hóa) và RSA-PSS, ECDSA (ký) là lựa chọn thuật toán trong luồng của từng use case, không phải use case riêng. Quản trị viên kế thừa mọi quyền của Người dùng. Đặc tả đầy đủ nằm trong báo cáo, mục 1.

## Yêu cầu

- Python 3.11 trở lên
- Git

## Cài đặt

```bash
git clone <URL-repository>
cd SecureMessagingSystem

python -m venv .venv
# Windows:      .venv\Scripts\activate
# Linux/macOS:  source .venv/bin/activate

pip install -e ".[dev]"
```

## Chạy chương trình

```bash
python -m secure_messaging
```

Khóa được lưu trong `data/keys/` và nhật ký trong `data/logs/`, cả hai nằm cạnh chương trình (đường dẫn tương đối, chạy được trên máy khác). Hai thư mục này đã nằm trong `.gitignore`, **không commit khóa lên Git**.

## Chạy kiểm thử

```bash
pytest                 # toàn bộ test
pytest tests/crypto    # chỉ phần mật mã
pytest tests/signing   # chỉ phần chữ ký
```

Bộ test gồm 25 test case (TC01–TC25), chia theo lớp được kiểm tra: số học, AES/RSA/ECC, khóa và kho khóa, chữ ký, `SecureMessenger`/`AuditLogger`, phân quyền. Dữ liệu mẫu dùng chung đặt trong `tests/test_data/`.

Kiểm tra phong cách mã và quy tắc tầng:

```bash
ruff check .           # phong cách mã (PEP 8)
lint-imports           # kiểm tra chiều gọi giữa các tầng
```

## Đóng gói thành một tệp thực thi

```bash
pyinstaller --onefile --name SecureMessagingSystem src/secure_messaging/__main__.py
```

Tệp tạo ra nằm trong `dist/`. Chạy tệp này trên máy khác không cần cài Python. Thư mục `data/` được tạo cạnh tệp thực thi ở lần chạy đầu.

## Kiến trúc

Hệ thống có 25 lớp chia thành 5 tầng. Chiều gọi chỉ đi xuống, không có lời gọi ngược lên tầng trên.

| Tầng | Thư mục | Lớp |
|---|---|---|
| Giao diện | `presentation/` | `ConsoleMenu` |
| Dịch vụ | `services/` | `SecureMessenger`, `KeyService`, `CipherFactory`, `AuditLogger` |
| Nghiệp vụ | `business/` | `ICipher`, `CipherBase`, `AesCipher`, `RsaCipher`, `EccCipher`, `EllipticCurve`, `BigIntCalculator`, `ISigner`, `RsaSigner`, `EcdsaSigner` |
| Thực thể | `entities/` | `CipherType`, `User`, `DigitalSignature`, `AsymmetricKey`, `PublicKey`, `PrivateKey`, `KeyPair` |
| Hạ tầng | `infrastructure/` | `IKeyRepository`, `FileKeyRepository`, `CryptoException` |

### Design Pattern

| Mẫu | Vai trò các lớp | Lý do dùng |
|---|---|---|
| Strategy | `ICipher` là chiến lược; `AesCipher`, `RsaCipher`, `EccCipher` là chiến lược cụ thể; `SecureMessenger` là ngữ cảnh | Đổi thuật toán lúc chạy (`set_cipher`) mà không sửa code gọi |
| Factory | `CipherFactory` tạo `ICipher` theo `CipherType` | Gom việc khởi tạo vào một chỗ, nơi gọi chỉ biết interface |
| Template Method | `CipherBase` định nghĩa khung `encrypt/decrypt`; lớp con cài `_do_encrypt/_do_decrypt` | Mọi thuật toán dùng chung bước kiểm tra đầu vào |
| Repository | `IKeyRepository`, `FileKeyRepository`; `KeyService` là client | Đổi nơi lưu khóa mà không sửa nghiệp vụ |
| Observer | `SecureMessenger` phát sự kiện `MessageProcessed`; `AuditLogger` đăng ký nhận | Ghi nhật ký mà `SecureMessenger` không phụ thuộc `AuditLogger` |

### Cấu trúc thư mục

```

SecureMessagingSystem/
├── pyproject.toml
├── README.md
├── .gitignore
│
├── config/
│   └── config.json
│
├── data/
│   ├── keys/
│   └── logs/
│
├── docs/
│   ├── uml/
│   ├── use_cases/
│   └── reports/
│
├── src/
│   └── secure_messaging/
│       ├── __init__.py
│       ├── __main__.py
│       │
│       ├── presentation/
│       │   ├── __init__.py
│       │   └── console_menu.py
│       │
│       ├── services/
│       │   ├── __init__.py
│       │   ├── key_service.py
│       │   ├── secure_messenger.py
│       │   └── audit_logger.py
│       │
│       ├── business/
│       │   ├── __init__.py
│       │   ├── crypto/
│       │   │   ├── __init__.py
│       │   │   ├── interfaces.py
│       │   │   ├── cipher_base.py
│       │   │   ├── aes_cipher.py
│       │   │   ├── rsa_cipher.py
│       │   │   ├── ecc_cipher.py
│       │   │   └── cipher_factory.py
│       │   │
│       │   ├── arithmetic/
│       │   │   ├── __init__.py
│       │   │   ├── bigint_calculator.py
│       │   │   ├── ec_point.py
│       │   │   └── elliptic_curve.py
│       │   │
│       │   └── signing/
│       │       ├── __init__.py
│       │       ├── interfaces.py
│       │       ├── rsa_signer.py
│       │       ├── ecdsa_signer.py
│       │       └── digital_signature.py
│       │
│       ├── entities/
│       │   ├── __init__.py
│       │   ├── user.py
│       │   └── keys/
│       │       ├── __init__.py
│       │       ├── asymmetric_key.py
│       │       ├── public_key.py
│       │       ├── private_key.py
│       │       └── key_pair.py
│       │
│       ├── infrastructure/
│       │   ├── __init__.py
│       │   ├── config/
│       │   │   ├── __init__.py
│       │   │   └── app_config.py
│       │   └── persistence/
│       │       ├── __init__.py
│       │       ├── key_repository.py
│       │       └── file_key_repository.py
│       │
│       └── exceptions/
│           ├── __init__.py
│           ├── crypto_exception.py
│           ├── key_revoked_exception.py
│           └── key_expired_exception.py
│
└── tests/
    ├── unit/
    ├── integration/
    └── conftest.py

```

## Quy tắc nghiệp vụ

| Mã | Quy tắc | Cài đặt tại |
|---|---|---|
| QT1 | Khóa AES dài 16, 24 hoặc 32 byte | `AesCipher.__init__` |
| QT2 | Mỗi lần mã hóa GCM sinh nonce mới | `AesCipher` (`_generate_nonce`, `_do_encrypt`) |
| QT3 | Bản mã GCM bị sửa thì giải mã báo lỗi xác thực | `AesCipher._do_decrypt` |
| QT4 | Khóa RSA có n ≥ 2048 bit, e = 65537, gcd(e, φ) = 1 | `KeyService.generate` |
| QT5 | Dữ liệu vượt giới hạn khối RSA-OAEP thì báo lỗi | `RsaCipher` (`_max_block_size`, `_do_encrypt`) |
| QT6 | Điểm ECC phải nằm trên đường cong đã chọn | `EllipticCurve.is_on_curve` |
| QT7 | Luôn băm SHA-256 trước khi ký và khi xác minh | `RsaSigner`, `EcdsaSigner` |
| QT8 | Khóa hết hạn hoặc bị thu hồi thì không được dùng để ký | `KeyService.ensure_not_revoked`, `SecureMessenger.sign` |
| QT9 | Khóa riêng không được xuất ra ngoài hay ghi vào log | `PrivateKey`, `AuditLogger` |
| QT10 | Chỉ Quản trị viên được thu hồi khóa và xem nhật ký | `ConsoleMenu` (kiểm tra `User.is_admin`) |

Vi phạm quy tắc thì ném `CryptoException` (trừ khi bảng nói khác); các test tương ứng nằm trong `tests/`.

## Làm việc nhóm với Git

| Nhánh | Mục đích |
|---|---|
| `main` | Bản ổn định, chỉ nhận merge từ `integration` |
| `feature/crypto` | Phân hệ 1 (Minh Đức) |
| `feature/signature` | Phân hệ 2 (Quang Chiến) |
| `integration` | Tích hợp hai phân hệ, chạy đầu-cuối trước khi lên `main` |

- Gộp nhánh bằng Pull Request; mỗi người duyệt ít nhất một PR của người kia.
- Commit theo quy ước `feat`, `fix`, `test`, `docs`, `chore`, ví dụ `feat(aes): implement AesCipher with GCM and nonce handling`.
- Các interface chung (`ICipher`, `ISigner`, `IKeyRepository`, `BigIntCalculator`, `KeyPair`) được chốt từ tuần 1; đổi chữ ký phải báo người còn lại.

## Tài liệu

- Báo cáo: `docs/report/`
- UML lớp: `docs/uml/`
- Sơ đồ use case, hoạt động, tuần tự: `docs/diagrams/`
