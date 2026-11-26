"""Cây ngoại lệ dùng chung của toàn hệ thống.

``CryptoException`` là ngoại lệ gốc cho cả PH1 (mật mã) và PH2 (khóa, chữ ký).
PH2 kế thừa lớp này cho ``KeyRevokedException`` và ``KeyExpiredException``;
không định nghĩa lại một ``CryptoException`` khác trong PH2.
"""


class CryptoException(Exception):
    """Lỗi nghiệp vụ mật mã: khóa/đầu vào/bản mã không hợp lệ.

    Thông điệp không được chứa khóa riêng, bản rõ hay mật khẩu (QT9).
    """
