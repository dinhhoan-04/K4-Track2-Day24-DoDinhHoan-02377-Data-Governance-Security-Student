"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

RUN_TTL = timedelta(minutes=15)
PARENT_SCOPES = ("search_docs", "read_customer")  # quyền của orchestrator đã ủy quyền
_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)[a-z]?\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _args_hash(args: dict) -> str:
    return hashlib.sha256(json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


class _Gate:
    """PEP + audit cho một run: mọi tool call đi qua `call()`."""

    def __init__(self, ledger_path: Path, principal_id: str, agent_id: str, run_id: str,
                 scopes: tuple[str, ...], depth: int, purpose: str, expires_at: str):
        self.path, self.principal_id, self.agent_id, self.run_id = ledger_path, principal_id, agent_id, run_id
        self.scopes, self.depth, self.purpose, self.expires_at = scopes, depth, purpose, expires_at

    def decide(self, tool: str, args: dict, classification: str, egress: bool = False):
        allow, reason = policy.check(policy.PolicyContext(
            data_classification=classification,
            request_purpose=self.purpose,
            agent_owner=self.agent_id,
            delegation_depth=self.depth,
            egress_enabled=egress,
            principal_id=self.principal_id,
            requested_tool=tool,
            agent_scopes=self.scopes,
            parent_scopes=PARENT_SCOPES if self.depth > 0 else (),
            expires_at=self.expires_at,
        ))
        self.log(tool, args, classification, "allow" if allow else "deny", reason or "no reason given")
        return allow, reason

    def log(self, tool: str, args: dict, classification: str, decision: str, reason: str, **extra) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": self.agent_id,
            "run_id": self.run_id,
            "on_behalf_of": self.principal_id,
            "expires_at": self.expires_at,
            "tool": tool,
            "args_hash": _args_hash(args),
            "classification": classification,
            "decision": decision,
            "reason": reason,
        }
        entry.update(extra)
        ledger.append(entry, self.path)


def _ticket_ids(docs: list[dict]) -> list[int]:
    """Chỉ lấy số từ TÊN FILE — dữ liệu typed duy nhất đi qua boundary."""
    ids = set()
    for doc in docs:
        m = _TICKET_FILE_RE.match(str(doc.get("id", "")))
        if m:
            ids.add(int(m.group(1)))
    return sorted(ids)


def _customers_for_tickets(ticket_ids: list[int]) -> list[str]:
    """Nguồn tin cậy: data/customers.json -> related_tickets (không dùng free text)."""
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    wanted = set(ticket_ids)
    return [c["customer_id"] for c in customers if wanted & set(c.get("related_tickets", []))]


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    expires_at = (datetime.now(timezone.utc) + RUN_TTL).isoformat()
    session = uuid.uuid4().hex[:12]

    # ---- Run A: untrusted content. Không read_customer, không http_post. ----
    gate_a = _Gate(ledger_path, principal_id, "lab24-agent/run-a", f"{session}-a",
                   ("search_docs",), 0, "summarize-tickets", expires_at)
    allowed, _ = gate_a.decide("search_docs", {"query": message}, "internal")
    docs: list[dict] = []
    injected = None
    if allowed:
        docs = tools.search_docs(message)
        injected = llm.find_injection("\n\n".join(d["text"] for d in docs))
        gate_a.log("find_injection", {"docs": [d["id"] for d in docs]}, "internal", "allow",
                   "untrusted text scanned for logging only; its customer_ids/urls are never used",
                   injection_detected=injected is not None,
                   matched_markers=list(injected.matched_markers) if injected else [])
    ticket_ids = _ticket_ids(docs)  # list[int] — thứ duy nhất sang Run B

    # ---- Run B: private data. Chỉ nhận list[int], suy customer_id từ related_tickets. ----
    gate_b = _Gate(ledger_path, principal_id, "lab24-agent/run-b", f"{session}-b",
                   ("read_customer",), 1, "support-reply", expires_at)
    collected: list[dict] = []
    for customer_id in _customers_for_tickets(ticket_ids):
        # Kiểm quyền TRƯỚC khi đọc, không đọc rồi mới lọc.
        ok, _ = gate_b.decide("read_customer", {"customer_id": customer_id}, "restricted")
        if not ok:
            continue
        try:
            collected.append(tools.read_customer(customer_id))
        except tools.ToolError:
            continue

    # ---- Egress do nội dung untrusted đề xuất: chỉ là *đề xuất*, PEP quyết định. ----
    if injected is not None:
        gate_x = _Gate(ledger_path, principal_id, "lab24-agent/run-b", f"{session}-b",
                       ("http_post",), 1, "support-reply", expires_at)
        classification = "restricted" if collected else "internal"
        body = {"records": [json.loads(pii.redact(json.dumps(r, ensure_ascii=False))) for r in collected]}
        ok, _ = gate_x.decide("http_post", {"url": injected.target_url, "body": body},
                              classification, egress=True)
        if ok:
            tools.http_post(injected.target_url, body)

    safe_docs = [{**d, "text": pii.redact(d["text"])} for d in docs]
    return llm.summarize(safe_docs)
