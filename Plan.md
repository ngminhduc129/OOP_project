# plan.md (machine-readable; AI-first)

[meta]
project=CryptoLab; course=LTHDT final; checklist_items=20; tasks=58; weeks=6
start=2026-11-16 (assumed); deadline=2026-12-25 (assumed, unconfirmed)
owners: D=Minh Đức (phase1 crypto, branch feature/crypto); C=Quang Chiến (phase2 keys/signing/app, branch feature/signature); B=both
phase: 0=common 1=crypto 2=signature
status: todo|doing|review|blocked:<reason>|done
pri: H|M|L
refs: agent.md (rules); project_reference.md (design); docs/uml/00_gop_chi_tiet.mmd (UML)

[weeks]
w1|2026-11-16|2026-11-20|interfaces frozen; use cases, rules, class dictionary, UML draft; repo
w2|2026-11-23|2026-11-27|BigIntCalculator, AesCipher, keys, repository + tests; integration meeting 1
w3|2026-11-30|2026-12-04|RsaCipher, RsaSigner, KeyService + tests; cross-phase relations checked
w4|2026-12-07|2026-12-11|EllipticCurve, EccCipher, EcdsaSigner, AuditLogger + tests; pattern rationale
w5|2026-12-14|2026-12-18|CipherFactory, SecureMessenger, menus, roles; extensions committed; integration runs UC1-UC8
w6|2026-12-21|2026-12-25|sequence diagrams, publish single-file, report, README, demo, cross Q&A

[tasks]
id|week|owner|item|phase|pri|status|task|done_when
T01|1|C|19|0|H|todo|Dựng repo Git: nhánh main, feature/crypto, feature/signature, integration; .gitignore, .editorconfig; khung solution 5 tầng|Repo chạy được, cả 2 clone và build được
T02|1|D|1|1|H|todo|Viết đặc tả UC1–UC4 (mã hóa AES/RSA/ECC, giải mã & đổi thuật toán): tác nhân, tiền điều kiện, luồng chính, luồng ngoại lệ, hàm điều khiển|Bảng Use case có đủ cột; khớp tên hàm dự kiến
T03|1|C|1|2|H|todo|Viết đặc tả UC5–UC8 (sinh khóa, ký, xác minh, quản trị khóa và nhật ký)|Bảng Use case có đủ cột; tác nhân Quản trị viên rõ ràng
T04|1|B|16|0|H|todo|Họp chốt và đóng băng hợp đồng interface: ICipher, ISigner, IKeyRepository, BigIntCalculator, KeyPair/PublicKey/PrivateKey|File Contracts commit lên main; sau mốc này đổi chữ ký phải báo người kia
T05|1|D|3|1|H|todo|Viết quy tắc nghiệp vụ QT1, QT2, QT3, QT5, QT6 kèm Lớp.Phương thức cài đặt|Bảng quy tắc có cột vị trí cài đặt
T06|1|C|3|2|H|todo|Viết quy tắc nghiệp vụ QT4, QT7, QT8, QT9, QT10 kèm Lớp.Phương thức cài đặt|Bảng quy tắc có cột vị trí cài đặt
T07|1|D|2|1|H|todo|Từ điển lớp phân hệ 1 (10 lớp): thuộc tính, kiểu, ý nghĩa, ràng buộc|Mỗi thuộc tính có giải thích
T08|1|C|2|2|H|todo|Từ điển lớp phân hệ 2 (20 lớp): thuộc tính, kiểu, ý nghĩa, ràng buộc|Mỗi thuộc tính có giải thích
T09|1|D|5|1|M|todo|Vẽ UML phân hệ 1 bản nháp (Mermaid 02)|Đủ thuộc tính và phương thức, đường nối thẳng
T10|1|C|5|2|M|todo|Vẽ UML tổng thể và phân hệ 2 bản nháp (Mermaid 00, 03)|Đủ ≥ 16 lớp, đủ 5 loại quan hệ
T11|1|C|8|0|M|todo|Sơ đồ package 5 tầng và quy tắc chiều gọi: Giao diện → Dịch vụ → Nghiệp vụ → Hạ tầng|Mỗi lớp thuộc đúng 1 tầng
T12|1|B|15|0|M|todo|Thống nhất Coding Convention (PascalCase, _camelCase, commit feat/fix/test/docs) và lịch họp 15 phút hàng tuần|Ghi trong README/.editorconfig
T13|2|D|2|1|H|todo|Cài BigIntCalculator: ModPow, ModInverse, ModSqrt, Gcd, Miller-Rabin, GeneratePrime|Chạy đúng TC01–TC04
T14|2|D|18|1|H|todo|Viết test BigIntCalculator (TC01–TC04)|4 test pass
T15|2|D|14|1|H|todo|Cài ICipher, CipherType, CipherBase (Template Method: Encrypt → ValidateInput → DoEncrypt)|Lớp con chỉ override DoEncrypt/DoDecrypt
T16|2|D|3|1|H|todo|Cài AesCipher (khóa 16/24/32 byte, nonce mới mỗi lần, GCM phát hiện sửa bản mã) → QT1, QT2, QT3|Chạy đúng TC05–TC08
T17|2|D|18|1|H|todo|Viết test AES (vector FIPS-197, khóa sai độ dài, bản mã bị sửa, nonce khác nhau)|TC05–TC08 pass
T18|2|C|13|2|H|todo|Cài AsymmetricKey, PublicKey, PrivateKey, KeyPair: private, kiểm tra hợp lệ, Wipe, GetMaterial internal|Không có API public xuất khóa riêng (TC14)
T19|2|C|19|2|M|todo|Cài CryptoException, KeyRevokedException, AppConfig và appsettings.json|Cấu hình đọc được từ file, thiếu file có xử lý (TC25)
T20|2|C|11|2|H|todo|Cài IKeyRepository và FileKeyRepository (đường dẫn tương đối ./data/keys)|Lưu rồi nạp lại đúng khóa (TC15)
T21|2|C|18|2|M|todo|Viết test khóa và kho khóa (TC14–TC16, TC25)|4 test pass
T22|2|B|19|0|M|todo|Họp tích hợp 1: review chéo pull request, kiểm tra hợp đồng interface còn nguyên|Mỗi người duyệt ít nhất 1 PR của người kia
T23|3|D|3|1|H|todo|Cài RsaCipher (OAEP, MaxBlockSize, báo lỗi khi vượt giới hạn) → QT5|Chạy đúng TC09–TC11
T24|3|D|18|1|H|todo|Viết test RSA (ví dụ nhỏ n=3233, round-trip 2048 bit, dữ liệu quá dài)|TC09–TC11 pass
T25|3|C|14|2|H|todo|Cài HashService, ISigner, RsaSigner (hash-then-sign, PSS)|RsaSigner thay thế được ISigner
T26|3|C|3|2|H|todo|Cài KeyService: Generate (RSA n ≥ 2048, e = 65537), Get, Revoke, EnsureNotRevoked → QT4, QT8|Chạy đúng TC22
T27|3|C|18|2|H|todo|Viết test ký/xác minh RSA, sửa nội dung, sai khóa, khóa bị thu hồi (TC17–TC19, TC22)|4 test pass
T28|3|B|6|0|M|todo|Rà quan hệ xuyên phân hệ trong code (RsaSigner→BigIntCalculator, RsaCipher→KeyPair, KeyService→BigIntCalculator) và đối chiếu UML|Mỗi mũi tên xuyên phân hệ có trong code
T29|4|D|3|1|H|todo|Cài EllipticCurve và ECPoint (IsOnCurve, Add, Double, Multiply; đường cong P-256) → QT6|Chạy đúng TC12
T30|4|D|14|1|H|todo|Cài EccCipher (ECIES: ECDH + KDF + AES-GCM), override DoEncrypt/DoDecrypt|Round-trip đúng (TC13)
T31|4|D|18|1|H|todo|Viết test ECC (điểm trên/ngoài đường cong, round-trip ECIES)|TC12–TC13 pass
T32|4|C|14|2|H|todo|Cài EcdsaSigner (nonce k tất định theo RFC 6979)|Chạy đúng TC20, TC21
T33|4|C|11|2|H|todo|Cài AuditLogger (Observer) và sự kiện MessageProcessed của SecureMessenger|Mỗi thao tác sinh 1 dòng log (TC23)
T34|4|C|18|2|M|todo|Viết test ECDSA, Observer, phân quyền (TC20, TC21, TC23, TC24)|4 test pass
T35|4|D|9|1|M|todo|Viết lý do chọn Strategy, Factory (+ Template Method)|Mỗi mẫu có lý do gắn với bài toán
T36|4|C|9|2|M|todo|Viết lý do chọn Repository, Observer|Mỗi mẫu có lý do gắn với bài toán
T37|5|D|11|1|H|todo|Cài CipherFactory (CreateSymmetric/CreateAsymmetric); Strategy đổi thuật toán lúc chạy|Không có if/else theo tên thuật toán ngoài Factory
T38|5|C|4|2|H|todo|Cài SecureMessenger (Context/Facade), ConsoleMenu, AdminMenu với kiểm tra vai trò|Giao diện không chứa logic nghiệp vụ; chạy TC24
T39|5|C|4|2|M|todo|Bảng phân quyền Người dùng/Quản trị viên → hàm điều khiển; ranh giới giao diện/nghiệp vụ|Khớp UC1–UC8
T40|5|D|12|1|H|todo|Mở rộng: thêm ChaCha20Cipher và đăng ký vào Factory, không sửa code cũ; ghi đánh giá Strategy/Factory|Commit riêng chỉ thêm file mới và 1 dòng đăng ký
T41|5|C|12|2|H|todo|Mở rộng: thêm InMemoryKeyRepository, không sửa KeyService; ghi đánh giá Repository/Observer|Commit riêng chỉ thêm file mới
T42|5|D|10|1|M|todo|Bảng vai trò lớp trong Strategy, Factory, Template Method đối chiếu với code|Mỗi vai trò chỉ đúng tên lớp
T43|5|C|10|2|M|todo|Bảng vai trò lớp trong Repository, Observer đối chiếu với code|Mỗi vai trò chỉ đúng tên lớp
T44|5|B|16|0|H|todo|Thử thay cài đặt: đổi FileKeyRepository ↔ InMemoryKeyRepository, AES ↔ ChaCha20; phần kia không lỗi|Toàn bộ test vẫn pass
T45|5|B|17|0|H|todo|Tích hợp trên nhánh integration, chạy đầu-cuối (sinh khóa → mã hóa → ký → xác minh → thu hồi)|Demo chạy hết các UC1–UC8
T46|6|C|17|2|H|todo|dotnet publish single-file, kiểm tra đường dẫn tương đối, chạy thử trên máy khác, chụp ảnh minh chứng|Chạy được không cần cài thêm
T47|6|D|17|1|M|todo|Kiểm tra chạy đủ 3 thuật toán trên máy khác từ bản publish|Ảnh chụp kết quả
T48|6|D|7|1|H|todo|Vẽ 2 sơ đồ tuần tự: mã hóa ECIES; sinh khóa RSA (Miller-Rabin, ModInverse)|Thứ tự gọi hàm khớp code chạy thật
T49|6|C|7|2|H|todo|Vẽ sơ đồ tuần tự ký–xác minh và sơ đồ hoạt động thu hồi khóa + ghi nhật ký|Thứ tự gọi hàm khớp code chạy thật
T50|6|B|5|0|H|todo|Chốt UML cuối: đối chiếu từng lớp, thuộc tính, phương thức với code; cập nhật file Mermaid|Không còn chỗ lệch giữa UML và code
T51|6|B|8|0|M|todo|Đối chiếu package thực tế với sơ đồ tầng; kiểm tra không có lời gọi ngược tầng|Báo cáo mục 4 khớp cấu trúc thư mục
T52|6|B|6|0|M|todo|Bảng 5 loại quan hệ (kế thừa, thực thi, kết tập, hợp thành, phụ thuộc) kèm ví dụ lớp trong code|Mỗi loại có ≥ 1 ví dụ; có ví dụ xuyên phân hệ
T53|6|D|13|1|M|todo|Rà soát đóng gói phần mật mã: private, kiểm tra tham số, thông điệp lỗi thống nhất|Không có trường public ngoài ý muốn
T54|6|C|15|2|M|todo|Rà soát SRP, interface ≤ 4 phương thức, áp dụng convention; quyết định giữ hay bỏ HashService|Mỗi lớp nêu được 1 trách nhiệm
T55|6|D|20|1|H|todo|Viết báo cáo phần mật mã và kịch bản demo mã hóa|Báo cáo có số trang cho cột Minh chứng
T56|6|C|20|2|H|todo|Viết README (cài đặt, chạy, test), báo cáo phần khóa/chữ ký, slide, kịch bản demo ký|README chạy theo được trên máy sạch
T57|6|B|20|0|H|todo|Tập demo và hỏi đáp chéo: mỗi người giải thích code và thiết kế của người kia|Cả 2 trả lời được về lớp, pattern, test của nhau
T58|6|B|19|0|M|todo|Kiểm tra Git: ≥ 20 commit tổng, mỗi người ≥ 10, nhánh hợp lý, đã merge qua PR|Sheet 'Git commit' ở trạng thái Đạt

[coverage]  # checklist item -> tasks
1:T02,T03
2:T07,T08,T13
3:T05,T06,T16,T23,T26,T29
4:T38,T39
5:T09,T10,T50
6:T28,T52
7:T48,T49
8:T11,T51
9:T35,T36
10:T42,T43
11:T20,T33,T37
12:T40,T41
13:T18,T53
14:T15,T25,T30,T32
15:T12,T54
16:T04,T44
17:T45,T46,T47
18:T14,T17,T21,T24,T27,T31,T34
19:T01,T19,T22,T58
20:T55,T56,T57

[targets]
use_cases>=8 (4/4); rules>=8 (5/5); classes_in_uml>=16 (planned 30); patterns>=3; diagrams_seq_or_activity>=4 (2/2)
tests>=20 (each>=10; planned 25: D=13 TC01-13, C=12 TC14-25); commits>=20 (each>=10; planned 14/14)
done_all: every task status=done; build+test green on main; UML matches code; publish runs on another machine; both can explain both parts

[update_rules]
edit only the status field; only rows where owner=you or owner=B for your part; never mark another owner's row
done only if tests pass and the related commit exists; blocked needs a reason
changes to rows/fields other than status -> separate PR, both approve
status edits go in the same PR as the code