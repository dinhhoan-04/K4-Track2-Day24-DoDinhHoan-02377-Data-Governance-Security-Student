"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
# Chuỗi số liên tiếp 8-16 chữ số, không dính vào chữ số khác.
_DIGITS_RE = re.compile(r"(?<!\d)\d{8,16}(?!\d)")
# SĐT có dấu phân cách (0912 345 678, 0912-345-678, 0912.345.678) hoặc +84.
_PHONE_SEP_RE = re.compile(r"(?<![\d+])(?:\+84|0)\d{2}[ .-]\d{3}[ .-]\d{3,4}(?!\d)")
_PHONE_INTL_RE = re.compile(r"(?<![\d+])\+84\d{9}(?!\d)")

_BANK_HINT = re.compile(r"stk|t[àa]i kho[ảa]n|tai khoan|bank|ng[âa]n h[àa]ng|ngan hang|chuy[ểe]n kho[ảa]n|chuyen khoan", re.I)
_CCCD_HINT = re.compile(r"cccd|cmnd|c[ăa]n c[ưu][ớo]c|can cuoc|citizen", re.I)
_PHONE_HINT = re.compile(r"s[đd]t|sdt|[đd]i[ệe]n tho[ạa]i|dien thoai|phone|zalo|hotline|li[êe]n h[ệe]|lien he|tel", re.I)


def _context(text: str, start: int) -> str:
    """Đoạn chữ ngay trước entity, cắt tại dấu phân cách mệnh đề gần nhất."""
    window = text[max(0, start - 30):start]
    for sep in (",", ";", "\n"):
        idx = window.rfind(sep)
        if idx != -1:
            window = window[idx + 1:]
    return window


def _classify(text: str, start: int, value: str) -> str:
    ctx = _context(text, start)
    # Từ khoá gần entity nhất thắng.
    best, best_pos = None, -1
    for label, pattern in (("VN_BANK_ACCOUNT", _BANK_HINT), ("VN_CCCD", _CCCD_HINT), ("VN_PHONE", _PHONE_HINT)):
        for m in pattern.finditer(ctx):
            if m.start() > best_pos:
                best, best_pos = label, m.start()
    if best == "VN_PHONE" and not (len(value) in (10, 11) and value.startswith("0")):
        best = None
    if best == "VN_CCCD" and len(value) != 12:
        best = None
    if best:
        return best
    if len(value) == 10 and value.startswith("0"):
        return "VN_PHONE"
    if len(value) == 12:
        return "VN_CCCD"
    return "VN_BANK_ACCOUNT"


def detect(text: str) -> list[dict]:
    entities: list[dict] = []
    taken: list[tuple[int, int]] = []

    def free(s: int, e: int) -> bool:
        return all(e <= ts or s >= te for ts, te in taken)

    def add(kind: str, s: int, e: int) -> None:
        if free(s, e):
            entities.append({"type": kind, "start": s, "end": e})
            taken.append((s, e))

    for m in _EMAIL_RE.finditer(text):
        add("EMAIL", m.start(), m.end())
    for regex in (_PHONE_SEP_RE, _PHONE_INTL_RE):
        for m in regex.finditer(text):
            add("VN_PHONE", m.start(), m.end())
    for m in _DIGITS_RE.finditer(text):
        add(_classify(text, m.start(), m.group()), m.start(), m.end())
    entities.sort(key=lambda e: e["start"])
    return entities


def redact(text: str) -> str:
    out = text
    for ent in sorted(detect(text), key=lambda e: e["start"], reverse=True):
        out = out[:ent["start"]] + f"[REDACTED_{ent['type']}]" + out[ent["end"]:]
    return out
