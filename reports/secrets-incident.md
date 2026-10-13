# Secret giả trong lịch sử Git — checkpoint 4

- **Scanner và phiên bản:** Gitleaks **v8.30.1** (`gitleaks version` → `8.30.1`), cấu hình `.gitleaks.toml`.
- **Lệnh quét lịch sử:** `gitleaks git --config .gitleaks.toml --redact --verbose .` → exit code 1, `4 commits scanned`, `leaks found: 1` (đúng như dự kiến).
- **Rule bắt được:** `lab24-synthetic-token` (rule tự định nghĩa trong `.gitleaks.toml`, regex `LAB24_FAKE_TOKEN=LAB24-DEMO-[A-Z0-9]{16}`).
- **Commit chứa token giả:** `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`, "chore: seed student lab with synthetic secret exercise").
- **File và dòng:** `lab-fake-secret.txt`, dòng 1. File này đã bị xoá khỏi HEAD ở commit sau nhưng vẫn nằm trong lịch sử. Fingerprint: `1bdd849922156c868a5ee9293d68f5b72e242d2c:lab-fake-secret.txt:lab24-synthetic-token:1`.
- **Quét file hiện tại:** `gitleaks dir --config .gitleaks.toml .` → `no leaks found`, exit code 0.
- **Hook:** `.pre-commit-config.yaml` dùng hook `gitleaks-system` từ repo chính thức, `rev: v8.30.1`, `pass_filenames: false`. `pre-commit run --all-files` → `Detect hardcoded secrets... Passed`.
- **Hash lock:** `requirements.lock` sinh bằng `python -m piptools compile --generate-hashes -o requirements.lock requirements.txt`; mọi package có `--hash=sha256:`. `pip install --require-hashes -r requirements.lock` (kiểm bằng `--dry-run`) giải quyết được.

## Đánh giá

Token này **giả và vô hiệu** (định dạng `LAB24-DEMO`), nên đây là bằng chứng cho checkpoint, không phải sự cố bảo mật thật. Không có credential thật nào trong repo.

## Nếu đây là secret thật thì phải làm gì

1. **Rotate / thu hồi ngay** credential tại nhà cung cấp (revoke token, cấp token mới, cập nhật nơi dùng), rồi kiểm log truy cập trong khoảng thời gian bị lộ.
2. Chỉ sau đó mới làm sạch lịch sử (ví dụ `git filter-repo`), đồng thời coi mọi bản clone/fork đã có secret là đã bị lộ.
3. Thêm pre-commit hook và quét CI để chặn lần sau.

## Vì sao xoá file khỏi HEAD, pin dependency hoặc hook vẫn chưa đủ

- Xoá file ở commit sau **không thu hồi credential**: secret vẫn nằm trong lịch sử Git và trong mọi clone đã có. Ai từng đọc repo vẫn dùng được nó nếu chưa rotate.
- `requirements.lock` với hash chỉ bảo vệ chuỗi cung ứng (đảm bảo cài đúng artifact đã biết), không liên quan tới secret đã lộ.
- Pre-commit hook chỉ **ngăn** lần commit mới (phòng ngừa), không sửa lịch sử cũ và có thể bị bỏ qua bằng `--no-verify`. Bước phản ứng bắt buộc khi secret đã lộ là rotate/thu hồi.
