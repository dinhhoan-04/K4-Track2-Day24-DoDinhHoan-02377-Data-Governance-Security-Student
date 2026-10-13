"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    # Nguồn tin cậy mô phỏng; lỗi đọc file => fail closed (không có principal nào).
    try:
        return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _expired(expires_at: str) -> bool | None:
    """True nếu đã hết hạn, None nếu thiếu/không parse được (coi là deny)."""
    if not expires_at:
        return None
    try:
        parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed <= datetime.now(timezone.utc)


def check(context: PolicyContext) -> tuple[bool, str]:
    """Trả về (allow, reason); reason luôn non-empty."""
    # Rule tối thiểu: dữ liệu restricted không được đi cùng egress.
    if context.data_classification == "restricted" and context.egress_enabled is True:
        return False, "deny: restricted data must not be combined with egress (lethal trifecta)"

    principal = _load_principals().get(context.principal_id) if context.principal_id else None
    if not principal:
        return False, f"deny: unknown or missing principal {context.principal_id!r}"

    expired = _expired(context.expires_at)
    if expired is None:
        return False, "deny: missing or invalid expires_at for this run"
    if expired:
        return False, f"deny: run expired at {context.expires_at}"

    tool = context.requested_tool
    if not tool:
        return False, "deny: no requested_tool specified"
    if tool not in principal.get("allowed_tools", []):
        return False, f"deny: principal {context.principal_id} is not allowed to use {tool}"
    if context.request_purpose not in principal.get("purposes", []):
        return False, (f"deny: purpose {context.request_purpose!r} is not permitted "
                       f"for principal {context.principal_id}")
    if tool not in context.agent_scopes:
        return False, f"deny: {tool} is outside the agent scopes"
    if context.delegation_depth > 0 and tool not in context.parent_scopes:
        return False, f"deny: {tool} exceeds parent_scopes of the delegating agent"

    return True, (f"allow: {context.principal_id} may use {tool} for {context.request_purpose} "
                  f"({context.data_classification}, depth={context.delegation_depth})")
