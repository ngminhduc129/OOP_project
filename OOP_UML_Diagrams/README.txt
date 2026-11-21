BỘ MÃ NGUỒN SƠ ĐỒ UML - DỰA TRÊN OOP_Project_Plan_Revised.xlsx

Danh sách:
00_class_diagram.mmd          Class Diagram bằng Mermaid
01_use_case.puml              Use Case Diagram bằng PlantUML
02_sequence_ecies.puml        Sequence: mã hóa ECC-ECIES (UC1)
03_sequence_rsa_keygen.puml   Sequence: sinh khóa RSA (UC3)
04_sequence_sign_verify.puml  Sequence: ký và xác minh (UC5, UC6)
05_activity_revoke_audit.puml Activity: thu hồi khóa và ghi nhật ký (UC7)

Cách xem:
- Mermaid: mở file .mmd tại Mermaid Live Editor hoặc dùng Mermaid extension.
- PlantUML: mở file .puml tại PlantUML server, PlantUML extension của VS Code,
  hoặc IDE có hỗ trợ PlantUML.

Lưu ý về mức độ chi tiết:
- Các tên Use Case, lớp, phương thức và quy tắc được lấy theo workbook.
- Ở sequence ECIES, plan chỉ nêu ECIES và DeriveSharedKey, chưa khóa chi tiết
  KDF/định dạng gói tin; sơ đồ để phần này ở mức khái quát, không tự áp đặt
  một cấu hình mật mã cụ thể.
- Sequence sinh RSA mô tả luồng p, q, Miller-Rabin, GCD và ModInverse theo
  các thành phần/hàm đã có trong plan.
- Sơ đồ ký/xác minh thể hiện HashService.SHA256 và Signer nhận digest
  ở chế độ Prehashed, đúng QT7.
- Nếu tên hàm trong code triển khai thay đổi, cần cập nhật sơ đồ cho khớp code.
