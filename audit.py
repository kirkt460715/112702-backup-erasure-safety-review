"""村账务备份的本地只读审计工具。

数据来自三个相互独立、结构为对象数组的 JSON 来源（见 ``records/``）：

- ``retention``：台账的分类、到期、更正与合法保留措施；
- ``snapshots``：备份方每一代快照的记录身份、分区与派生索引；
- ``restores``：恢复经办的实际挂接、访问就绪与清理验证回执。

本模块只读取这些合成清单/回执并生成审计结论，不读取、恢复或删除任何真实资料。

核心不变量（与任务约定对应）：

1. 清理回报必须区分“清除”与“隐藏”，只有可核实的清除证明才算清理；
2. 证明按 记录身份 + 范围 + 快照代/恢复目标 匹配，旧证明不自动覆盖重建副本；
3. 保全只覆盖台账指定的记录和期间，既不能放过同盘其他附件，也不能删除仍保全的凭证；
4. 身份以跨来源可核实的 ID 引用为准，同名不同归属不合并；
5. 无法核对完整性时，保留采集缺口与待查范围，不把“未知”判成“已清理”。

无第三方依赖，Python 3.11。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

# 允许 `python3 -I /abs/path/audit.py` 从任意目录运行（-I 隐含 -P，不会自动加入脚本目录）。
sys.path.insert(0, str(Path(__file__).resolve().parent))

from records_view import load_sources  # noqa: E402

DEFAULT_RECORDS = Path(__file__).with_name("records")

EXPECTED_SOURCES = ("retention", "snapshots", "restores")

# ---------------------------------------------------------------------------
# 词表与归一化
# ---------------------------------------------------------------------------

_ERASURE_TOKENS = {
    "clean", "cleanup", "cleaned", "erase", "erased", "erasure", "delete",
    "deleted", "deletion", "purge", "purged", "remove", "removed", "removal",
    "shred", "shredded", "destroy", "destroyed", "wipe", "wiped", "clear",
    "cleared", "expunge", "expunged",
    "清除", "清理", "删除", "销毁", "擦除", "清净",
}
_HIDING_TOKENS = {
    "hide", "hidden", "conceal", "concealed", "mask", "masked", "invisible",
    "obscure", "obscured", "cloak", "stealth",
    "隐藏", "遮蔽", "屏蔽", "不可见",
}
_PROOF_OK = {
    "confirmed", "confirm", "verified", "verify", "certified", "attested",
    "complete", "completed", "done", "success", "successful", "true", "ok",
    "已确认", "已核实", "已验证", "证实",
}
_PROOF_BAD = {
    "unconfirmed", "not_confirmed", "pending", "failed", "failure", "rejected", "none", "no",
    "false", "unknown", "inconclusive",
    "未确认", "待验证", "失败", "否认",
}
_ACCESS_POSITIVE = {
    "approved", "approve", "ready", "access_ready", "granted", "grant",
    "accessible", "allowed", "allow", "open", "online", "available", "passed",
    "可访问", "已批准", "批准", "就绪", "放行", "可读取",
}
_ACCESS_BLOCKED = {
    "not_approved", "unapproved", "denied", "deny", "blocked", "block",
    "revoked", "revoke", "forbidden", "prohibited", "not_ready", "unready",
    "unavailable", "closed", "restricted", "disabled", "inaccessible",
    "拒绝", "未批准", "不批准", "阻断", "已阻止", "不可访问", "未就绪", "限制",
}
_ACCESS_PENDING = {
    "pending", "waiting", "review", "in_review", "requested", "tbd",
    "pending_approval", "待批准", "待审核", "待定",
}

_DAY_FIELDS = (
    "day", "done_day", "event_day", "at_day", "issued_day", "recorded_day",
    "verified_day", "checked_day", "attached_day", "opened_day",
    "observed_day", "as_of_day", "as_of", "reported_day", "completed_day",
    "today", "current_day",
)
_EXPIRY_FIELDS = (
    "expires", "expires_day", "expire_day", "expiry_day", "expiry",
    "due_day", "cleanup_due_day", "clean_after_day",
)
_HOLD_FIELDS = (
    "hold_until", "legal_hold_until", "retain_until", "preserve_until",
    "hold_to_day", "legal_hold_to",
)
_CATEGORY_FIELDS = ("category", "classification", "data_category", "record_type")
_NAME_FIELDS = ("name", "filename", "file_name", "display_name", "attachment_name")
_CORRECTION_FIELDS = ("corrects", "amends", "supersedes", "replaces", "correction_of")
_TARGET_FIELDS = ("target", "restored", "restore_target", "target_id", "restored_target")
_SNAPSHOT_BIND_FIELDS = ("snapshot", "generation", "snapshot_id", "from_snapshot", "backup", "from")
_HASH_KEY_HINTS = ("sha256", "sha1", "md5", "checksum", "digest", "signature", "hash")

KIND_LABELS = {
    "primary": "线上主副本",
    "snapshot_record": "快照内记录副本",
    "derived_index": "派生索引副本",
    "restored_record": "恢复目标内记录副本",
    "restored_index": "恢复目标内派生索引副本",
    "reported_scope": "回报涉及范围",
    "unknown_scope": "未知名范围",
}

STATUS_LABELS = {
    "cleaned_verified": "已清除并核实",
    "hidden_not_erased": "仅隐藏，未清除",
    "cleanup_unconfirmed": "清除证明未证实",
    "pending_reverification": "重建副本待实际再验证",
    "reverification_missing": "重建副本缺少再验证回执",
    "expired_residual_copy": "已到期但仍有残留副本",
    "expired_uncleaned_primary": "已到期主副本未见有效清除证明",
    "expired_accessible": "已到期副本仍可访问（恢复将重现）",
    "evidence_conflict": "证据相互矛盾",
    "held_lawfully": "保全期内，有合法保留依据",
    "held_verified": "保全记录已在恢复目标核验在位",
    "held_verification_pending": "保全依据有效，但恢复目标核验待定",
    "held_not_reverified": "保全记录在恢复目标上缺少核验",
    "within_retention": "尚在正常保留期内",
    "hold_period_ended": "保全期间已届满，待台账确认续期或清理",
    "classification_gap": "缺少台账分类/到期信息",
    "timing_indeterminate": "无法确定基准日期，到期状态存疑",
    "unresolved_reference": "引用无法核对",
}


def as_list(value: Any) -> list[Any]:
    """字符串当作单个范围；None 为空；列表/元组原样展开。"""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def entry_token(value: Any) -> str:
    """把范围/身份元素归一为可比较 token；兼容 {id|item|scope|name: ...} 对象。"""
    if isinstance(value, dict):
        value = (value.get("scope") or value.get("id") or value.get("item")
                 or value.get("name") or value.get("index") or value.get("target")
                 or value.get("identity"))
    return token_text(value)


def scope_tokens(value: Any) -> list[str]:
    return [entry_token(v) for v in as_list(value) if v is not None]


def token_text(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def _contains_any(text: str, words: Iterable[str]) -> bool:
    return any(word in text for word in words)


def normalize_access(value: Any) -> str:
    """把访问就绪/批准回报归一为 accessible/blocked/pending/unknown。"""
    if isinstance(value, bool):
        return "accessible" if value else "blocked"
    if value is None:
        return "unknown"
    raw = str(value).strip().lower()
    norm = token_text(value)
    if norm in _ACCESS_BLOCKED or _contains_any(raw, ("拒绝", "阻断", "未批准", "不可访问", "未就绪")):
        return "blocked"
    if norm in _ACCESS_POSITIVE or _contains_any(raw, ("可访问", "已批准", "就绪", "放行")):
        return "accessible"
    if norm in _ACCESS_PENDING:
        return "pending"
    if norm.startswith(("not_", "un", "denied")):
        return "blocked"
    return "unknown"


def proof_strength(value: Any) -> str:
    if isinstance(value, bool):
        return "confirmed" if value else "unconfirmed"
    if value is None:
        return "unspecified"
    norm = token_text(value)
    if norm in _PROOF_OK or _contains_any(str(value), ("已确认", "已核实", "已验证", "证实")):
        return "confirmed"
    if norm in _PROOF_BAD:
        return "unconfirmed"
    return "other"


def proof_confirmation(row: dict) -> str:
    """综合 proof/proof_status/confirmed/verified/result/status 判断证明强度。"""
    strength = "unspecified"
    for key in ("proof", "proof_status", "confirmation", "confirmed"):
        if key in row:
            value = row[key]
            current = proof_strength(value)
            if isinstance(value, bool):
                return current
            if current == "confirmed":
                return "confirmed"
            if current in {"unconfirmed", "other"}:
                strength = "unconfirmed" if current == "unconfirmed" else strength
    if row.get("verified") is True or row.get("independently_verified") is True:
        return "confirmed"
    for key in ("result", "status", "state"):
        if row.get(key) is not None:
            current = proof_strength(row[key])
            if current == "confirmed":
                return "confirmed"
            if current == "unconfirmed":
                strength = "unconfirmed"
    return strength


def detect_report_action(row: dict) -> tuple[str, bool]:
    """区分清除类回报与隐藏类回报。返回 (erasure|hiding|unknown, 是否推断)。"""
    explicit = None
    for key in ("action", "kind", "type", "report_type", "method", "operation", "result_type"):
        if row.get(key) is not None:
            explicit = token_text(row[key])
            break
    blob_parts = [explicit or ""]
    blob_parts.append(token_text(row.get("proof", "")))
    rid = token_text(row.get("id", ""))
    blob_parts.append(rid)
    blob = " ".join(blob_parts)
    raw_blob = " ".join(str(row.get(k, "")) for k in ("action", "kind", "type", "report_type", "method"))
    if _contains_any(blob, _HIDING_TOKENS) or _contains_any(raw_blob, ("隐藏", "遮蔽")):
        return "hiding", explicit is None
    if _contains_any(blob, _ERASURE_TOKENS) or _contains_any(raw_blob, ("清除", "清理", "删除", "销毁")):
        return "erasure", explicit is None
    return "unknown", explicit is None


def _first_present(row: dict, fields: Iterable[str]) -> Any:
    for field in fields:
        if field in row and row[field] is not None:
            return row[field]
    return None


def _day_value(row: dict) -> int | None:
    for field in _DAY_FIELDS:
        value = row.get(field)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return int(value)
    return None


# ---------------------------------------------------------------------------
# 来源装载
# ---------------------------------------------------------------------------

def coerce_sources(target: Any = None) -> dict[str, list[dict]]:
    """接受 records 目录、已装载的 sources 字典或 None（默认目录）。"""
    if target is None:
        return load_sources(DEFAULT_RECORDS)
    if isinstance(target, dict):
        # 既可能是 {source: [rows]}，也可能包了一层 sources。
        if "sources" in target and isinstance(target["sources"], dict):
            return target["sources"]
        return target
    path = Path(target)
    return load_sources(path)


def _rows(sources: dict, name: str) -> list[dict]:
    rows = sources.get(name, [])
    return rows if isinstance(rows, list) else []


# ---------------------------------------------------------------------------
# 台账：更正合并 + 按 item 归并
# ---------------------------------------------------------------------------

def prepare_retention(rows: list[dict]) -> tuple[dict[str, dict], list[dict], list[dict]]:
    """返回 item -> 合并后的台账事实、更正记录、冲突列表。"""
    by_id = {r.get("id"): r for r in rows if isinstance(r, dict)}
    corrections: list[dict] = []
    effective: list[dict] = []
    corrected_ids: set[str] = set()

    for row in rows:
        link_field = next((f for f in _CORRECTION_FIELDS if row.get(f) is not None), None)
        target_id = row.get(link_field) if link_field else None
        target = by_id.get(target_id) if target_id is not None else None
        if link_field and target is not None:
            merged = dict(target)
            for key, value in row.items():
                if key in ("id", link_field) or value is None:
                    continue
                merged[key] = value
            merged["id"] = target.get("id")
            merged.setdefault("corrections", []).append(row.get("id"))
            idx = next((i for i, r in enumerate(effective) if r.get("id") == target.get("id")), None)
            if idx is None:
                effective.append(merged)
            else:
                effective[idx] = merged
            corrected_ids.add(row.get("id"))
            corrections.append({"id": row.get("id"), "field": link_field,
                                "corrects": target_id, "item": merged.get("item")})
        elif link_field and target is None:
            corrections.append({"id": row.get("id"), "field": link_field,
                                "corrects": target_id, "unresolved": True})

    for row in rows:
        if row.get("id") in corrected_ids:
            continue
        if any(c.get("corrects") == row.get("id") and not c.get("unresolved") for c in corrections):
            continue
        if not any(r.get("id") == row.get("id") for r in effective):
            effective.append(dict(row))

    items: dict[str, dict] = {}
    conflicts: list[dict] = []
    for row in effective:
        item = row.get("item")
        if not isinstance(item, str) or not item:
            continue
        bucket = items.setdefault(item, {
            "item": item, "categories": set(), "names": set(),
            "expires_values": [], "hold_values": [], "measures": [],
            "record_ids": [], "raw": [],
        })
        bucket["record_ids"].append(row.get("id"))
        bucket["raw"].append(row)
        category = _first_present(row, _CATEGORY_FIELDS)
        if category is not None:
            bucket["categories"].add(str(category))
        for field in _NAME_FIELDS:
            if row.get(field) is not None:
                bucket["names"].add(str(row[field]))
        expiry = _first_present(row, _EXPIRY_FIELDS)
        if isinstance(expiry, (int, float)) and not isinstance(expiry, bool):
            bucket["expires_values"].append((int(expiry), row.get("id")))
        hold = _first_present(row, _HOLD_FIELDS)
        if isinstance(hold, (int, float)) and not isinstance(hold, bool):
            bucket["hold_values"].append((int(hold), row.get("id")))
        elif row.get("legal_hold") is True or token_text(row.get("hold")) in ("true", "yes", "active"):
            bucket["hold_values"].append((None, row.get("id")))
        for key in ("measure", "measures", "retention_measure", "legal_basis",
                    "hold_reason", "authority", "basis"):
            if row.get(key) is not None:
                bucket["measures"].append({"field": key, "value": row[key], "record": row.get("id")})

    for item, bucket in items.items():
        exp_values = {v for v, _ in bucket["expires_values"]}
        hold_values = {v for v, _ in bucket["hold_values"]}
        if len(exp_values) > 1:
            conflicts.append({"item": item, "kind": "expiry_conflict",
                              "values": sorted(exp_values),
                              "records": bucket["record_ids"]})
        if len(hold_values) > 1:
            numeric = [v for v in hold_values if v is not None]
            if len(set(numeric)) > 1 or (None in hold_values and numeric):
                conflicts.append({"item": item, "kind": "hold_conflict",
                                  "values": sorted(v for v in hold_values if v is not None),
                                  "indefinite": None in hold_values,
                                  "records": bucket["record_ids"]})
        bucket["category"] = sorted(bucket["categories"])[0] if bucket["categories"] else None
        bucket["expires"] = _conservative_expiry(bucket["expires_values"])
        bucket["hold_until"] = max((v for v, _ in bucket["hold_values"] if v is not None), default=None)
        bucket["indefinite_hold"] = any(v is None for v, _ in bucket["hold_values"])
    return items, corrections, conflicts


def _conservative_expiry(values: list[tuple[int, Any]]) -> int | None:
    """无冲突时即该值；有冲突时取较早到期日（要求更严格的清理口径）。"""
    if not values:
        return None
    return min(v for v, _ in values)


def retention_disposition(item_info: dict | None, as_of: int | None) -> dict:
    """给出 item 在基准日的保留状态。"""
    if item_info is None or not item_info.get("record_ids"):
        return {"disposition": "unclassified", "on_hold": False, "expired": None,
                "reason": "所有来源均未提供该身份的台账分类/到期/保全记录"}
    hold_until = item_info.get("hold_until")
    indefinite = item_info.get("indefinite_hold")
    expires = item_info.get("expires")
    if as_of is None:
        if indefinite or hold_until is not None:
            return {"disposition": "on_hold", "on_hold": True, "expired": None,
                    "hold_until": hold_until,
                    "reason": "台账载明保全措施；缺少观察基准日，保全期间无法按日核对"}
        return {"disposition": "unknown_time", "on_hold": False, "expired": None,
                "expires": expires, "reason": "来源中没有可用于确定基准日的观察日期"}
    if indefinite or (hold_until is not None and as_of <= hold_until):
        return {"disposition": "on_hold", "on_hold": True, "expired": False,
                "hold_until": hold_until,
                "reason": f"合法保留措施覆盖至第 {hold_until if hold_until is not None else '?'} 日（基准第 {as_of} 日）"}
    if expires is not None and as_of > expires:
        return {"disposition": "expired", "on_hold": False, "expired": True,
                "expires": expires,
                "reason": f"第 {expires} 日到期，基准第 {as_of} 日已过清理期，且无有效保全"}
    if expires is not None:
        return {"disposition": "within_retention", "on_hold": False, "expired": False,
                "expires": expires, "reason": f"尚未超过到期日第 {expires} 日"}
    if hold_until is not None and as_of > hold_until:
        return {"disposition": "hold_lapsed", "on_hold": False, "expired": None,
                "hold_until": hold_until,
                "reason": f"保全期间第 {hold_until} 日已经届满，台账未提供续期或后续到期依据，需台账确认"}
    return {"disposition": "within_retention", "on_hold": False, "expired": False,
            "reason": "台账未载明到期日，按正常保留处理"}


# ---------------------------------------------------------------------------
# 快照结构解析（身份 / 分区 / 派生索引）
# ---------------------------------------------------------------------------

def _entry_identity(entry: Any) -> tuple[str | None, dict]:
    """contains/derived 数组元素可能是 ID 字符串，也可能是带分区/来源的对象。"""
    if isinstance(entry, str):
        return entry, {}
    if isinstance(entry, dict):
        ident = (entry.get("id") or entry.get("record") or entry.get("item")
                 or entry.get("identity") or entry.get("source")
                 or entry.get("derives_from") or entry.get("ref"))
        return (str(ident) if ident is not None else None), entry
    return None, {}


def parse_snapshots(rows: list[dict]) -> tuple[dict[str, dict], list[dict]]:
    snapshots: dict[str, dict] = {}
    problems: list[dict] = []
    for row in rows:
        sid = row.get("id")
        contains: list[dict] = []
        for entry in as_list(row.get("contains")):
            ident, extra = _entry_identity(entry)
            if ident is None:
                problems.append({"kind": "unreadable_contains_entry", "snapshot": sid, "entry": entry})
                continue
            contains.append({"item": ident,
                             "partition": extra.get("partition") or extra.get("part"),
                             "disk": extra.get("disk") or extra.get("volume"),
                             "name": _first_present(extra, _NAME_FIELDS)})
        # 显式分区清单：{partitions: {p1: [ids...]}} 或 [{name, items}]
        partitions = (row.get("partitions") or row.get("partitioned")
                      or row.get("parts") or [])
        if isinstance(partitions, dict):
            for pname, entries in partitions.items():
                for entry in as_list(entries):
                    ident, extra = _entry_identity(entry)
                    if ident is None:
                        continue
                    contains.append({"item": ident, "partition": pname,
                                     "disk": extra.get("disk") or extra.get("volume") if isinstance(extra, dict) else None,
                                     "name": _first_present(extra, _NAME_FIELDS) if isinstance(extra, dict) else None})
        elif isinstance(partitions, list):
            for p in partitions:
                if not isinstance(p, dict):
                    continue
                pname = p.get("name") or p.get("partition") or p.get("id")
                for entry in as_list(p.get("items") or p.get("contains") or p.get("records")):
                    ident, extra = _entry_identity(entry)
                    if ident is None:
                        continue
                    contains.append({"item": ident, "partition": pname,
                                     "disk": p.get("disk") or p.get("volume"),
                                     "name": _first_present(extra, _NAME_FIELDS) if isinstance(extra, dict) else None})
        derived: list[dict] = []
        raw_derived = row.get("derived") or row.get("derived_indexes") or row.get("indexes") or {}
        if isinstance(raw_derived, dict):
            for index_name, ref in raw_derived.items():
                if isinstance(ref, dict):
                    refs = [ref.get("item") or ref.get("source")
                            or ref.get("derives_from") or ref.get("id") or ref.get("record")]
                    extra_ref = ref
                else:
                    refs = as_list(ref)
                    extra_ref = {}
                for item in refs:
                    ident, extra = _entry_identity(item) if not isinstance(item, str) else (item, {})
                    merged_extra = {**extra_ref, **(extra or {})}
                    if ident is None:
                        problems.append({"kind": "unreadable_derived_ref", "snapshot": sid,
                                         "scope": str(index_name), "entry": item})
                        continue
                    derived.append({"scope": str(index_name), "item": ident,
                                   "partition": merged_extra.get("partition"),
                                   "kind": merged_extra.get("kind") or "index"})
        elif isinstance(raw_derived, list):
            for d in raw_derived:
                if not isinstance(d, dict):
                    continue
                scope = d.get("name") or d.get("index") or d.get("scope") or d.get("id")
                item = d.get("derives_from") or d.get("source") or d.get("item") or d.get("ref")
                if item is None:
                    problems.append({"kind": "unreadable_derived_ref", "snapshot": sid,
                                     "scope": str(scope), "entry": d})
                    continue
                derived.append({"scope": str(scope) if scope is not None else None,
                                "item": str(item), "partition": d.get("partition"),
                                "kind": d.get("kind") or "index"})
        snapshots[sid] = {
            "id": sid, "parent": row.get("parent"),
            "done_day": _day_value(row),
            "contains": contains, "derived": derived,
            "partition": row.get("partition"), "disk": row.get("disk") or row.get("volume"),
            "raw": row,
        }
    return snapshots, problems


# ---------------------------------------------------------------------------
# 回执索引：清除证明 / 挂接与访问 / 再验证
# ---------------------------------------------------------------------------

def _is_actual_attach(row: dict) -> bool:
    """恢复经办给的是“实际挂接”结果；显式计划/未挂接/失败的记录不生成重建副本结论。"""
    for flag in ("attached", "actually_attached", "actual", "mounted"):
        if flag in row and row[flag] is False:
            return False
    state = token_text(_first_present(row, ("attach_state", "state", "status", "result")) or "")
    if state in {"planned", "requested", "proposed", "not_attached", "unattached",
                 "detached", "failed", "error", "cancelled", "canceled"}:
        return False
    return True


def index_restores(rows: list[dict]) -> dict:
    proofs: list[dict] = []
    access_records: list[dict] = []
    reviews: list[dict] = []
    for row in rows:
        has_proof = row.get("proof") is not None or (
            "item" in row and any(k in row for k in ("scope", "day", "action", "type", "kind"))
            and "target" not in row and "from" not in row and "checked" not in row
            and "pending" not in row)
        if has_proof and row.get("item") is not None:
            action, inferred = detect_report_action(row)
            proofs.append({
                "id": row.get("id"), "item": row.get("item"),
                "scopes": scope_tokens(row.get("scope") if row.get("scope") is not None
                                       else row.get("scopes")),
                "target": _first_present(row, _TARGET_FIELDS),
                "snapshot_bind": _first_present(row, _SNAPSHOT_BIND_FIELDS),
                "strength": proof_confirmation(row),
                "action": action, "action_inferred": inferred,
                "day": _day_value(row), "raw": row,
            })
        access_keys = ("access", "access_state", "access_result", "readiness", "ready", "accessible")
        if row.get("target") is not None and any(k in row for k in access_keys):
            state_value = _first_present(row, access_keys)
            if "ready" in row and "access" not in row and "readiness" not in row:
                state_value = row.get("ready")
            access_records.append({
                "id": row.get("id"), "target": row.get("target"),
                "scopes": scope_tokens(row.get("scope")),
                "state": normalize_access(state_value), "raw_value": state_value,
            })
        if row.get("target") is not None and ("checked" in row or "pending" in row):
            reviews.append({
                "id": row.get("id"), "target": row.get("target"),
                "checked": {entry_token(x) for x in as_list(row.get("checked")) if x is not None},
                "pending": {entry_token(x) for x in as_list(row.get("pending")) if x is not None},
                "day": _day_value(row),
            })
    all_attaches = [r for r in rows if r.get("from") is not None and r.get("target") is not None]
    attaches = [r for r in all_attaches if _is_actual_attach(r)]
    planned = [{"id": r.get("id"), "target": r.get("target"), "from": r.get("from")}
               for r in all_attaches if not _is_actual_attach(r)]
    return {"proofs": proofs, "access": access_records, "reviews": reviews,
            "attaches": attaches, "planned_attaches": planned}


# ---------------------------------------------------------------------------
# 副本图谱
# ---------------------------------------------------------------------------

def _scope_aliases(item: str | None, scope: str | None, partition: Any = None,
                   extra: Iterable[str] = ()) -> set[str]:
    aliases: set[str] = set()
    if item is not None:
        aliases.add(token_text(item))
    if scope is not None:
        aliases.add(token_text(scope))
    if partition is not None:
        aliases.add(token_text(partition))
    for e in extra:
        if e is not None:
            aliases.add(token_text(e))
    return aliases


def build_copies(items: dict, snapshots: dict, indexed: dict) -> list[dict]:
    copies: list[dict] = []
    seen: set[tuple] = set()

    def add_copy(**kwargs):
        key = (kwargs.get("kind"), kwargs.get("item"), kwargs.get("scope"),
               kwargs.get("snapshot"), kwargs.get("target"))
        if key in seen:
            return None
        seen.add(key)
        copy = {"aliases": sorted(kwargs.pop("_aliases", set())), **kwargs}
        copy["copy_id"] = "cp-" + token_text("-".join(str(x) for x in key if x is not None))[:120]
        copies.append(copy)
        return copy

    # 1) 台账中每个身份的线上主副本。
    for item in items:
        add_copy(kind="primary", item=item, scope="primary", snapshot=None, target=None,
                 _aliases=_scope_aliases(item, "primary"))

    # 2) 快照代内的直接记录与派生索引。
    for sid, snap in snapshots.items():
        top_partition = snap.get("partition")
        top_disk = snap.get("disk")
        for entry in snap["contains"]:
            add_copy(kind="snapshot_record", item=entry["item"],
                     scope=entry.get("partition") or top_partition or "contains",
                     snapshot=sid, target=None,
                     partition=entry.get("partition") or top_partition,
                     disk=entry.get("disk") or top_disk,
                     _aliases=_scope_aliases(entry["item"], entry.get("partition") or top_partition,
                                            extra=[sid]))
        for d in snap["derived"]:
            add_copy(kind="derived_index", item=d["item"], scope=d["scope"],
                     snapshot=sid, target=None, partition=d.get("partition"),
                     disk=top_disk, index_kind=d.get("kind"),
                     _aliases=_scope_aliases(d["item"], d["scope"], d.get("partition"), [sid]))

    # 3) 实际挂接到恢复目标后重建出的副本（旧证明不自动覆盖这一层）。
    for attach in indexed["attaches"]:
        target = attach.get("target")
        sid = attach.get("from")
        snap = snapshots.get(sid)
        raw_scopes = as_list(attach.get("scope"))
        if snap is None:
            for scope in raw_scopes or ["unknown"]:
                add_copy(kind="unknown_scope", item=None, scope=scope,
                         snapshot=sid, target=target, unresolved_snapshot=True,
                         _aliases={token_text(scope), token_text(target)})
            continue
        for entry in snap["contains"]:
            add_copy(kind="restored_record", item=entry["item"],
                     scope=entry.get("partition") or snap.get("partition") or "contains",
                     snapshot=sid, target=target, restore_id=attach.get("id"),
                     partition=entry.get("partition") or snap.get("partition"),
                     disk=entry.get("disk") or snap.get("disk"),
                     _aliases=_scope_aliases(entry["item"],
                                             entry.get("partition") or snap.get("partition"),
                                             extra=[sid, target]))
        for d in snap["derived"]:
            add_copy(kind="restored_index", item=d["item"], scope=d["scope"],
                     snapshot=sid, target=target, restore_id=attach.get("id"),
                     partition=d.get("partition"), disk=snap.get("disk"),
                     index_kind=d.get("kind"),
                     _aliases=_scope_aliases(d["item"], d["scope"], d.get("partition"),
                                             [sid, target]))
        # 挂接回报声明、但快照清单里没有的范围：保留为待查，不丢弃。
        known_scopes = {token_text(d["scope"]) for d in snap["derived"] if d.get("scope")}
        known_scopes |= {token_text(e["item"]) for e in snap["contains"]}
        for scope in raw_scopes:
            if token_text(scope) in known_scopes:
                continue
            add_copy(kind="unknown_scope", item=None, scope=scope,
                     snapshot=sid, target=target, restore_id=attach.get("id"),
                     _aliases={token_text(scope), token_text(target)})

    # 4) 清理证明提到、但结构清单中不存在的范围：仍作为证据范围登记。
    structural_scopes = set()
    for c in copies:
        structural_scopes.update(c.get("aliases", []))
    for p in indexed["proofs"]:
        for scope in p["scopes"] or ["primary"]:
            aliases = _scope_aliases(p["item"], scope, extra=[p["target"], p["snapshot_bind"]])
            if aliases & structural_scopes:
                continue
            add_copy(kind="reported_scope", item=p["item"], scope=scope,
                     snapshot=p["snapshot_bind"], target=p["target"],
                     evidence_only=True,
                     _aliases=aliases)
    return copies


# ---------------------------------------------------------------------------
# 单副本证据评估
# ---------------------------------------------------------------------------

def _proof_applies(proof: dict, copy: dict) -> tuple[bool, str]:
    if proof["item"] != copy.get("item"):
        return False, "item_mismatch"
    if proof["target"] is not None and copy.get("target") is not None \
            and token_text(proof["target"]) != token_text(copy["target"]):
        return False, "target_mismatch"
    if proof["snapshot_bind"] is not None and copy.get("snapshot") is not None \
            and token_text(proof["snapshot_bind"]) != token_text(copy["snapshot"]):
        return False, "snapshot_mismatch"
    copy_aliases = set(copy.get("aliases", []))
    if proof["scopes"]:
        if not (set(proof["scopes"]) & copy_aliases):
            return False, "scope_mismatch"
    else:
        # 无范围的旧式证明默认只覆盖线上主副本，绝不自动延伸到派生/重建副本。
        if copy.get("kind") != "primary" and not proof["target"] and not proof["snapshot_bind"]:
            return False, "scope_absent_primary_only"
    return True, "matches"


def _review_state(copy: dict, indexed: dict) -> dict:
    target = copy.get("target")
    if target is None:
        return {"state": "not_a_restore_copy", "review_ids": [], "matched": []}
    aliases = set(copy.get("aliases", []))
    checked_by, pending_by, hit = [], [], set()
    for rev in indexed["reviews"]:
        if token_text(rev["target"]) != token_text(target):
            continue
        c_hit = aliases & rev["checked"]
        p_hit = aliases & rev["pending"]
        if c_hit:
            checked_by.append(rev["id"])
            hit |= c_hit
        if p_hit:
            pending_by.append(rev["id"])
            hit |= p_hit
    if pending_by and checked_by:
        return {"state": "conflict", "review_ids": sorted(set(pending_by + checked_by)),
                "matched": sorted(hit)}
    if pending_by:
        return {"state": "pending", "review_ids": pending_by, "matched": sorted(hit)}
    if checked_by:
        return {"state": "checked", "review_ids": checked_by, "matched": sorted(hit)}
    return {"state": "not_listed", "review_ids": [], "matched": []}


def _access_state(copy: dict, indexed: dict) -> dict:
    target = copy.get("target")
    aliases = set(copy.get("aliases", []))
    best = None
    for rec in indexed["access"]:
        if target is None or token_text(rec["target"]) != token_text(target):
            continue
        if rec["scopes"] and not (set(rec["scopes"]) & aliases):
            continue
        # 范围精确匹配优先于整目标记录。
        precise = bool(rec["scopes"])
        candidate = {"state": rec["state"], "record_id": rec["id"],
                     "raw_value": rec["raw_value"], "scope_specific": precise}
        if best is None or (precise and not best["scope_specific"]):
            best = candidate
    return best or {"state": "unknown", "record_id": None, "raw_value": None,
                    "scope_specific": False}


def evaluate_copies(copies: list[dict], items: dict, indexed: dict, as_of: int | None) -> list[dict]:
    evaluated = []
    for copy in copies:
        item_id = copy.get("item")
        info = items.get(item_id) if item_id else None
        retention = retention_disposition(info, as_of)

        matching = []
        for proof in indexed["proofs"]:
            applies, why = _proof_applies(proof, copy)
            if applies:
                matching.append({"id": proof["id"], "strength": proof["strength"],
                                 "action": proof["action"], "day": proof["day"]})
        erasure_proofs = [p for p in matching if p["action"] == "erasure" and p["strength"] == "confirmed"]
        hiding_proofs = [p for p in matching if p["action"] == "hiding"]
        weak_proofs = [p for p in matching if p not in erasure_proofs and p not in hiding_proofs]

        review = _review_state(copy, indexed)
        access = _access_state(copy, indexed)

        is_restore_copy = copy.get("target") is not None
        status, conclusion, reasons = _decide_status(
            copy, retention, erasure_proofs, hiding_proofs, weak_proofs, review, access)

        flags = {
            "cleaned": status == "cleaned_verified",
            "held": retention["disposition"] == "on_hold",
            "pending": status in {"pending_reverification", "held_verification_pending",
                                  "expired_accessible"} or review["state"] in {"pending", "conflict"},
            "residual": status in {"expired_residual_copy", "expired_uncleaned_primary"},
            "blocks_approval": False,
            "restorable_reappearance_risk": False,
        }
        if is_restore_copy:
            flags["blocks_approval"] = status in {
                "pending_reverification", "reverification_missing", "expired_accessible",
                "evidence_conflict", "classification_gap", "held_verification_pending",
                "held_not_reverified", "unresolved_reference", "timing_indeterminate",
                "cleanup_unconfirmed", "hidden_not_erased", "expired_uncleaned_primary",
                "hold_period_ended",
            }
        else:
            flags["restorable_reappearance_risk"] = (
                retention["expired"] is True and not flags["cleaned"]) or status == "expired_residual_copy"

        evaluated.append({
            **{k: v for k, v in copy.items() if k != "aliases"},
            "aliases": copy.get("aliases", []),
            "kind_label": KIND_LABELS.get(copy.get("kind"), str(copy.get("kind"))),
            "retention": retention,
            "evidence": {
                "applicable_proofs": matching,
                "erasure_proof_ids": [p["id"] for p in erasure_proofs],
                "hiding_proof_ids": [p["id"] for p in hiding_proofs],
                "other_proof_ids": [p["id"] for p in weak_proofs],
                "review": review,
                "access": access,
            },
            "status": status,
            "status_label": STATUS_LABELS.get(status, status),
            "conclusion": conclusion,
            "reasons": reasons,
            **flags,
        })
    return evaluated


def _decide_status(copy, retention, erasure_proofs, hiding_proofs, weak_proofs, review, access):
    reasons: list[str] = []
    if copy.get("unresolved_snapshot") or copy.get("item") is None and copy.get("kind") == "unknown_scope":
        return "unresolved_reference", "挂接回执引用了无法核对的快照/范围，列入采集缺口与待查范围", ["unresolved"]

    disp = retention["disposition"]
    is_restore = copy.get("target") is not None

    if disp == "unclassified":
        return "classification_gap", "台账没有该身份的分类、到期或保全记录，不能跳过，需先补台账", ["unclassified"]
    if disp == "unknown_time":
        reasons.append(retention["reason"])
        return "timing_indeterminate", "缺少可核对的观察日期，无法判断是否已到期，保留待查", reasons

    if disp == "on_hold":
        basis = retention["reason"]
        if is_restore:
            if review["state"] in ("pending", "conflict"):
                return "held_verification_pending", f"{basis}；但恢复目标的独立核验为 {review['state']}，保全在位情况待验证", [basis, "review_" + review["state"]]
            if review["state"] == "checked":
                return "held_verified", f"{basis}；恢复目标已经独立核验在位，不得删除该历史凭证", [basis, "review_checked"]
            return "held_not_reverified", f"{basis}；但恢复目标上没有核验记录，整代不能判为通过", [basis, "review_not_listed"]
        return "held_lawfully", f"{basis}；该副本有合法保留依据，禁止清理/删除", [basis]

    # 保全期间已过：不能再主张保全依据，也不能在台账确认前直接清理。
    if disp == "hold_lapsed":
        suffix = "；恢复目标上的该副本因此不能随整代判为通过" if is_restore else ""
        return "hold_period_ended", retention["reason"] + suffix, ["hold_lapsed"]

    # 已到期（或正常保留期内）的记录
    if disp == "within_retention":
        return "within_retention", retention["reason"] + "，当前不构成清理事项", [retention["reason"]]

    # disp == expired
    if access["state"] == "accessible":
        if erasure_proofs and review["state"] == "checked":
            return "evidence_conflict", "既有已清除核实，又有“可访问”就绪回报，证据矛盾，必须现场复查", ["access_accessible", "clean_evidence"]
        return "expired_accessible", "已到期副本在恢复目标上被回报为可访问，恢复审批将重现到期副本，应阻断", ["access_accessible"]

    if is_restore:
        if review["state"] in ("pending", "conflict"):
            old = f"；旧清理证明 {','.join(p['id'] for p in erasure_proofs)} 不自动覆盖重建副本" if erasure_proofs else ""
            return "pending_reverification", (
                f"重建副本的独立清理验证为 {review['state']}，必须实际再验证后才能继续确认"
                "（旧清理证明不能自动覆盖新重建副本）" + old), ["review_" + review["state"]]
        if review["state"] == "checked":
            return "cleaned_verified", "恢复经办已在重建目标上实际再验证（checked），到期副本的清除得到确认", ["review_checked"]
        # not_listed
        if hiding_proofs:
            return "hidden_not_erased", "只有隐藏类回报且没有恢复后的清除再验证，线上不可见不等于已清除", ["hiding_only"]
        if erasure_proofs:
            return "reverification_missing", "虽有旧清除证明，但缺少针对新重建目标的独立再验证，旧证明不能自动覆盖", ["old_proof_not_transferable"]
        if weak_proofs:
            return "cleanup_unconfirmed", "清除证明未达到 confirmed/verified，且恢复后未再验证", ["weak_proof"]
        return "reverification_missing", "恢复目标的核验清单未列出该范围，无法核对清理结果，保留待查", ["review_not_listed"]

    # 非恢复副本：主副本 / 快照代内副本 / 证据范围
    if erasure_proofs:
        p = erasure_proofs[0]
        when = f"（第 {p['day']} 日）" if p.get("day") is not None else ""
        return "cleaned_verified", f"清除证明 {p['id']} {when} 为已证实的清除类回报，范围匹配", ["proof_confirmed_erasure"]
    if hiding_proofs:
        return "hidden_not_erased", "回报仅证明“隐藏/不可见”，不证明副本已清除", ["hiding_only"]
    if weak_proofs:
        return "cleanup_unconfirmed", "存在清理回报但证明状态未证实，不能计为已清理", ["weak_proof"]
    if copy.get("kind") == "primary":
        return "expired_uncleaned_primary", "已到期主副本没有匹配的已证实清除证明", ["no_erasure_proof"]
    return "expired_residual_copy", "已到期身份仍出现在快照/派生清单中且无匹配清除证明，恢复该代将重现此副本", ["manifest_still_lists_identity"]


# ---------------------------------------------------------------------------
# 恢复审批
# ---------------------------------------------------------------------------

def build_restore_approvals(attaches: list[dict], evaluated: list[dict],
                            snapshots: dict, indexed: dict) -> list[dict]:
    approvals = []
    for attach in attaches:
        target = attach.get("target")
        sid = attach.get("from")
        mine = [c for c in evaluated if c.get("target") == target]
        # 同一 target 可能有多条挂接记录；副本只建一次，审批按挂接记录分别给结论。
        expired_bad = [c for c in mine if c["retention"].get("expired") is True
                       and c["status"] in {"pending_reverification", "reverification_missing",
                                           "expired_accessible", "hidden_not_erased",
                                           "cleanup_unconfirmed", "evidence_conflict",
                                           "expired_uncleaned_primary"}]
        accessible = [c for c in mine if c["status"] == "expired_accessible"
                      or (c["retention"].get("expired") is True and c["evidence"]["access"]["state"] == "accessible")]
        other_block = [c for c in mine if c["blocks_approval"] and c not in expired_bad]
        pending = [c for c in mine if c["status"] == "pending_reverification"]
        missing = [c for c in mine if c["status"] == "reverification_missing"]
        verified = [c for c in mine if c["status"] in {"cleaned_verified", "held_verified"}]

        if accessible:
            decision = "blocked_reappearance"
            approved = False
            reasons = ["恢复后存在已到期且可访问的副本，审批必须阻断："
                        + "、".join(_copy_ref(c) for c in accessible)]
        elif sid not in snapshots or any(c["status"] == "unresolved_reference" for c in mine):
            decision = "evidence_gap"
            approved = False
            reasons = ["实际挂接快照无法与备份清单核对，或存在无法读取的范围；"
                       "已保留采集缺口与待查范围，不能批准整代恢复"]
        elif expired_bad or other_block:
            decision = "pending_verification"
            approved = False
            bits = []
            if expired_bad:
                bits.append("少量受影响的到期副本尚待实际再验证：" + "、".join(_copy_ref(c) for c in expired_bad))
            if other_block:
                bits.append("另有保全在位/分类/完整性事项未核实：" + "、".join(_copy_ref(c) for c in other_block))
            reasons = bits + ["结论为局部副本待验证，不能表述为整代恢复通过"]
        elif not mine:
            decision = "evidence_gap"
            approved = False
            reasons = ["挂接范围在备份清单中没有对应副本，保留采集缺口，不能批准整代恢复"]
        else:
            decision = "generation_verified"
            approved = True
            reasons = ["该代全部副本均有匹配的清除再验证或有效保全+在位核验，可判为整代恢复通过"]

        affected = sorted({_scope_ref(c) for c in expired_bad})
        approval = {
            "restore_id": attach.get("id"),
            "target": target,
            "from_snapshot": sid,
            "snapshot_found": sid in snapshots,
            "attached_scope": as_list(attach.get("scope")),
            "access_raw": attach.get("access"),
            "copies_total": len(mine),
            "verified_copies": sorted({_scope_ref(c) for c in verified}),
            "affected_copies": affected,
            "affected_copy_count": len(affected),
            "pending_scopes": sorted({_scope_ref(c) for c in pending}),
            "reverification_missing_scopes": sorted({_scope_ref(c) for c in missing}),
            "accessible_expired_scopes": sorted({_scope_ref(c) for c in accessible}),
            "other_blocking_scopes": sorted({_scope_ref(c) for c in other_block}),
            "decision": decision,
            "verdict": decision,
            "status": decision,
            "result": decision,
            "approved": approved,
            "passed": decision == "generation_verified",
            "generation_passed": decision == "generation_verified",
            "whole_generation_verified": decision == "generation_verified",
            "partial": decision == "pending_verification",
            "blocked": decision == "blocked_reappearance",
            "blocking_reasons": reasons,
            "decision_label": _DECISION_LABELS.get(decision, decision),
        }
        approvals.append(approval)
    return approvals


_DECISION_LABELS = {
    "generation_verified": "整代恢复通过",
    "pending_verification": "少量受影响副本待验证（不是整代恢复通过）",
    "blocked_reappearance": "阻断：已到期可访问副本将重现",
    "evidence_gap": "证据缺口：挂接快照无法核对，保留采集缺口与待查范围",
    "no_restore_records": "没有恢复挂接回执",
}


def _copy_ref(c: dict) -> str:
    parts = [f"{c.get('kind_label')} {_scope_ref(c)}"]
    if c.get("target"):
        parts.append(f"@ {c['target']}")
    return "".join(parts)


def _scope_ref(c: dict) -> str:
    scope = c.get("scope")
    if c.get("kind") in {"snapshot_record", "restored_record", "primary"} or scope in (None, "contains"):
        return str(c.get("item") or scope or c.get("copy_id"))
    return str(scope or c.get("item") or c.get("copy_id"))


# ---------------------------------------------------------------------------
# 防御验证清单
# ---------------------------------------------------------------------------

def build_defensive_checks(evaluated: list[dict], approvals: list[dict],
                           gaps: list[dict], sources_present: dict) -> list[dict]:
    checks: list[dict] = []
    seq = 0

    def add(code, priority, title, instruction, basis, target=None, scope=None, item=None):
        nonlocal seq
        seq += 1
        checks.append({
            "id": f"DC-{seq:02d}", "code": code, "priority": priority,
            "phase": "after_restore", "target": target, "scope": scope, "item": item,
            "title": title, "instruction": instruction, "basis_records": basis,
        })

    targets = {a["target"]: a for a in approvals}
    for target, approval in targets.items():
        tc = [c for c in evaluated if c.get("target") == target]
        snap = approval.get("from_snapshot")

        pending_like = [c for c in tc if c["status"] in
                        {"pending_reverification", "reverification_missing", "cleanup_unconfirmed",
                         "hidden_not_erased", "expired_uncleaned_primary", "evidence_conflict"}]
        for c in pending_like:
            add("reverify_erasure_on_rebuilt_copy", "high",
                f"对 {target} 的 {_scope_ref(c)} 重新执行清除后验证",
                "在实际挂接的恢复目标上，用与攻击者相同的读取/检索路径验证该派生范围不再解析出"
                f" {c.get('item')} 的任何内容或索引项；留存新的独立验证回执。"
                "旧的 primary 范围证明或重建前证明不得作为通过依据。",
                c["evidence"]["review"].get("review_ids", []) + c["evidence"].get("erasure_proof_ids", []),
                target=target, scope=_scope_ref(c), item=c.get("item"))

        accessible = [c for c in tc if c["evidence"]["access"]["state"] == "accessible"
                      or c["status"] == "expired_accessible"]
        if accessible:
            add("revoke_and_probe_access", "critical",
                f"立即阻断并复查 {target} 上已到期副本的访问路径",
                "冻结恢复目标对外访问，回收授权；从列表、搜索、详情、预览、下载、导出、API 与缓存/"
                "全文索引等通道探测，确认到期附件不可访问后再重新走审批。",
                [c["evidence"]["access"].get("record_id") for c in accessible if c["evidence"]["access"].get("record_id")],
                target=target, scope=[_scope_ref(c) for c in accessible])
        else:
            blocked_scope = [c for c in tc if c["evidence"]["access"]["state"] == "blocked"]
            add("verify_access_restriction_enforced", "high",
                f"核实 {target} 的“不批准访问”在重建后仍然生效",
                "open/访问回执中的 not_approved 只是结论之一；恢复服务可能重建默认授权。"
                "应以未授权身份实际探测对应范围，确认认证、授权与分区隔离均拦截，并保存探测证据。",
                [c["evidence"]["access"].get("record_id") for c in blocked_scope if c["evidence"]["access"].get("record_id")],
                target=target, scope=[_scope_ref(c) for c in blocked_scope] or None)

        add("reconcile_attached_snapshot_manifest", "high",
            f"核对实际挂接的 {snap} 与备份清单、血缘和范围一致",
            f"确认挂接卷/快照身份确为 {snap}（含 parent 血缘），contains 身份、partitions 分区与 "
            "derived 派生索引逐项对平；任何多出/缺失/无法读取的范围都登记为采集缺口与待查范围。",
            [snap] if snap else [], target=target)

        add("rebuild_indexes_and_confirm_purge", "high",
            "重建派生索引并确认到期身份的索引项消失",
            "清除后触发索引/缩略图/全文/缓存重建，再检索到期 item 标识、文件名与内容指纹，"
            "确认主库、派生索引和只读副本中均无命中；防止重建服务后派生索引令附件重现。",
            [], target=target)

        held = [c for c in tc if c["retention"]["disposition"] == "on_hold"]
        if held:
            add("verify_held_records_intact_and_policy", "high",
                "验证保全记录在位且保全策略随恢复重新生效",
                "逐项确认保全范围内的租赁凭证可读取、完整且未被清理；确认 hold 标签/保留策略在"
                "恢复后重新挂载，任何清理作业都会跳过这些历史凭证。保全仅限台账指定 item 与期间。",
                [],
                target=target, scope=[_scope_ref(c) for c in held])

        add("sweep_colocated_attachments", "medium",
            "对同分区/同盘其他附件执行同等清点，禁止搭车跳过",
            "列出该目标同一 partition/disk/volume 上的全部附件，逐个匹配台账分类与到期/保全状态；"
            "一个记录有保全依据不构成跳过同盘其他附件的理由。",
            [], target=target)

        add("close_pending_scope_with_new_receipt", "medium",
            "用新的回执关闭待查范围",
            "把 pending/未列出的范围全部转为 checked 且无矛盾，或补登合法保全；"
            "更新恢复/清理回执后审批才可继续确认。旧清理证明的日期与范围不得覆盖新重建副本。",
            [], target=target)

    # 全局/完整性检查
    if not targets:
        add("sweep_colocated_attachments", "medium",
            "清点快照同分区/同盘的全部附件",
            "当前没有恢复挂接回执，仍应按备份清单的 partition/disk/volume 分组清点全部附件，"
            "逐个匹配台账分类、到期与保全状态；一个记录有保全依据不构成跳过同盘其他附件的理由。",
            [])
    if any(g["code"] == "no_integrity_material" for g in gaps):
        add("establish_integrity_evidence", "medium",
            "补采快照与回执的完整性材料",
            "现有合成清单不含哈希/签名，工具无法核对完整性，也不会读取真实资料。"
            "应在备份时采集清单与派生索引的校验值，恢复后比对；当前先保留采集缺口和待查范围。",
            [])
    else:
        add("verify_checksums_and_signatures", "high",
            "按清单校验值核对恢复字节与派生索引完整性",
            "比对快照清单哈希、分区校验值与回执签名；不一致即保留缺口并扩大待查范围。",
            [])

    add("deletion_guard_for_hold", "high",
        "执行删除前保全拦截",
        "任何物理删除/清理脚本运行前，以台账 hold_until 为准做一次拦截校验：保全期内 item 一律阻断；"
        "保全只覆盖指定记录和期间，不得扩大为整盘保留而跳过其他到期附件的清理。",
        [])
    return checks


# ---------------------------------------------------------------------------
# 缺口 / 同名冲突 / 完整性材料
# ---------------------------------------------------------------------------

def find_name_conflicts(sources: dict, items: dict, evaluated: list[dict]) -> list[dict]:
    name_to_items: dict[str, set[str]] = {}
    provenance: dict[str, list[str]] = {}

    def consider(name: Any, item: Any, record_id: Any):
        if name is None or item is None:
            return
        key = str(name)
        name_to_items.setdefault(key, set()).add(str(item))
        provenance.setdefault(f"{key}@{item}", []).append(str(record_id))

    for row in _rows(sources, "retention"):
        for f in _NAME_FIELDS:
            if row.get(f) is not None:
                consider(row[f], row.get("item"), row.get("id"))
    for row in _rows(sources, "snapshots"):
        for e in as_list(row.get("contains")):
            if isinstance(e, dict):
                ident, extra = _entry_identity(e)
                for f in _NAME_FIELDS:
                    if isinstance(extra, dict) and extra.get(f) is not None:
                        consider(extra[f], ident, row.get("id"))

    # 每个身份在多少个相互独立的来源中出现：用于“以可核实来源为准”。
    item_sources: dict[str, set[str]] = {}

    def mark(source_name: str, item_id: Any):
        if item_id is not None:
            item_sources.setdefault(str(item_id), set()).add(source_name)

    for row in _rows(sources, "retention"):
        mark("retention", row.get("item"))
    for row in _rows(sources, "snapshots"):
        for e in as_list(row.get("contains")):
            ident, _ = _entry_identity(e)
            mark("snapshots", ident)
        for ref in (row.get("derived") or {}).values() if isinstance(row.get("derived"), dict) else []:
            for it in as_list(ref):
                ident = it if isinstance(it, str) else (it or {}).get("source") if isinstance(it, dict) else None
                mark("snapshots", ident)
    for row in _rows(sources, "restores"):
        mark("restores", row.get("item"))

    conflicts = []
    for name, ids in name_to_items.items():
        if len(ids) > 1:
            scores = {i: len(item_sources.get(i, set())) for i in ids}
            best = max(scores.values())
            winners = sorted(i for i, score in scores.items() if score == best and best >= 2)
            preferred = winners[0] if len(winners) == 1 else None
            conflicts.append({
                "name": name, "attributed_items": sorted(ids),
                "source_corroboration": {i: sorted(item_sources.get(i, [])) for i in sorted(ids)},
                "preferred_verifiable_item": preferred,
                "rule": "同名不合并；以跨来源 ID 可核实的归属为准，其余归属保留待查",
                "provenance": {i: provenance.get(f"{name}@{i}", []) for i in sorted(ids)},
            })
    return conflicts


def collect_gaps(sources: dict, items: dict, snapshots_problems: list[dict],
                 evaluated: list[dict], corrections: list[dict],
                 ledger_conflicts: list[dict], approvals: list[dict]) -> list[dict]:
    gaps: list[dict] = []
    for name in EXPECTED_SOURCES:
        if name not in sources:
            gaps.append({"code": "source_absent", "severity": "high",
                         "message": f"缺少独立来源 {name}.json，相关结论只能保留为待查"})
    for p in snapshots_problems:
        kind = p.get("kind", "unreadable_contains_entry")
        where = "派生引用" if kind == "unreadable_derived_ref" else "contains 条目"
        gap = {"code": "unreadable_manifest_entry", "severity": "medium",
               "message": f"快照 {p.get('snapshot')} 存在无法核对的{where}：{p.get('entry')!r}"}
        if p.get("scope") is not None:
            gap["pending_scope"] = [p["scope"]]
        gaps.append(gap)
    for c in corrections:
        if c.get("unresolved"):
            gaps.append({"code": "correction_target_missing", "severity": "high",
                         "message": f"更正记录 {c['id']} 指向不存在的 {c['corrects']}，更正无法应用"})
    for c in ledger_conflicts:
        gaps.append({"code": "ledger_value_conflict", "severity": "high",
                     "message": f"台账对 {c['item']} 的 {c['kind']} 记载不一致：{c.get('values')}（记录 {c['records']}）"})

    for c in evaluated:
        if c["status"] == "unresolved_reference":
            gaps.append({"code": "unresolved_reference", "severity": "high",
                         "message": f"{c.get('restore_id') or ''} 引用的快照 {c.get('snapshot')} 无法核对",
                         "pending_scope": [c.get("scope")]})
        if c["status"] == "classification_gap":
            gaps.append({"code": "unclassified_identity", "severity": "high",
                         "message": f"身份 {c.get('item')} 出现在来源中但没有台账分类/到期/保全记录",
                         "pending_scope": [c.get("item")]})

    # 引用悬空的挂接由 evaluated 副本统一登记为 unresolved_reference 缺口。
    has_hash = False
    for name in EXPECTED_SOURCES:
        for row in _rows(sources, name):
            if any(any(h in k.lower() for h in _HASH_KEY_HINTS) for k in row):
                has_hash = True
    if not has_hash:
        gaps.append({
            "code": "no_integrity_material", "severity": "medium",
            "message": "合成清单与回执不含哈希/签名等完整性材料，且本工具按设计不读取真实资料，"
                       "因此无法核对实际字节完整性；该采集缺口需由备份校验值与恢复后比对补齐",
        })
    return gaps


# ---------------------------------------------------------------------------
# 删除保全拦截
# ---------------------------------------------------------------------------

def evaluate_deletion(report_or_items: dict | Any, item_ids: Iterable[str] | None = None) -> dict:
    """给定一批拟删除 item，返回保全拦截结论。

    第一个参数可以是 :func:`audit` 的报告，也可以是 sources 字典。
    """
    if isinstance(report_or_items, dict) and "items" in report_or_items and "copies" in report_or_items:
        report = report_or_items
        held = {i["item"]: {"item": i["item"], "hold_until": i.get("hold_until"),
                            "ledger_record_ids": i.get("ledger_record_ids")}
                for i in report["items"] if i["retention"].get("on_hold")}
        expired = {i["item"]: i for i in report["items"] if i["retention"].get("expired") is True}
    else:
        sources = coerce_sources(report_or_items)
        items, _, _ = prepare_retention(_rows(sources, "retention"))
        as_of = infer_as_of(sources)
        held, expired = {}, {}
        for iid, info in items.items():
            d = retention_disposition(info, as_of)
            if d.get("on_hold"):
                held[iid] = {"item": iid, "hold_until": d.get("hold_until")}
            if d.get("expired"):
                expired[iid] = {"item": iid}
    requested = list(item_ids or [])
    blocked = [held[i] if i in held else {"item": i, "reason": "保全期内"} for i in requested if i in held]
    unknown = [i for i in requested if i not in held and i not in expired]
    allowed = [i for i in requested if i in expired and i not in held]
    return {
        "requested": requested,
        "blocked_held": blocked,
        "allowed_after_scope_and_reverification": allowed,
        "indeterminate_requires_ledger": unknown,
        "rule": "保全只覆盖台账指定记录与期间；保全 item 禁止删除，同盘其他到期附件仍须照常核验清理",
        "all_blocked": bool(blocked) and not allowed and not unknown,
    }


# ---------------------------------------------------------------------------
# 基准日
# ---------------------------------------------------------------------------

def infer_as_of(sources: dict) -> int | None:
    days = []
    for name in EXPECTED_SOURCES:
        for row in _rows(sources, name):
            d = _day_value(row)
            if d is not None:
                days.append(d)
    return max(days) if days else None


def describe_generations(snapshots: dict) -> list[dict]:
    """每一代快照的身份/分区/派生索引，以及派生来源是否由父代携带的血缘提示。"""
    generations = []
    for sid in sorted(snapshots, key=lambda x: str(x)):
        snap = snapshots[sid]
        contained = {e["item"] for e in snap["contains"]}
        lineage_notes = []
        parent = snap.get("parent")
        parent_ids = set()
        cursor = parent
        seen_chain = set()
        while cursor and cursor in snapshots and cursor not in seen_chain:
            seen_chain.add(cursor)
            parent_ids |= {e["item"] for e in snapshots[cursor]["contains"]}
            cursor = snapshots[cursor].get("parent")
        for d in snap["derived"]:
            item = d.get("item")
            if item and item not in contained and item in parent_ids:
                lineage_notes.append(
                    f"派生范围 {d.get('scope')} 引用 {item}；本代 contains 未直接列出，"
                    f"但祖先代（自 {parent} 血缘上）含有该身份，恢复/挂载时仍可能经派生索引重现")
        generations.append({
            "id": sid, "parent": parent, "done_day": snap.get("done_day"),
            "contains": sorted(i for i in contained if i is not None),
            "partitions": sorted({str(e.get("partition")) for e in snap["contains"]
                                  if e.get("partition") is not None}),
            "derived": [{"scope": d.get("scope"), "item": d.get("item")} for d in snap["derived"]],
            "lineage_notes": lineage_notes,
        })
    return generations


# ---------------------------------------------------------------------------
# 主报告
# ---------------------------------------------------------------------------

def build_report(sources: dict, as_of: int | None = None) -> dict:
    sources_present = {name: (name in sources) for name in EXPECTED_SOURCES}
    inferred_day = infer_as_of(sources)
    as_of = inferred_day if as_of is None else as_of

    retention_rows = _rows(sources, "retention")
    items, corrections, ledger_conflicts = prepare_retention(retention_rows)
    snapshots, snap_problems = parse_snapshots(_rows(sources, "snapshots"))
    indexed = index_restores(_rows(sources, "restores"))

    # 让只在快照/回执中出现的身份也进入台账视野（标记 unclassified）。
    known_ids = set(items)
    for sid, snap in snapshots.items():
        for e in snap["contains"]:
            if e["item"]:
                known_ids.add(e["item"])
        for d in snap["derived"]:
            if d["item"]:
                known_ids.add(d["item"])
    for p in indexed["proofs"]:
        known_ids.add(p["item"])
    for cid in known_ids:
        items.setdefault(cid, {"item": cid, "categories": set(), "names": set(),
                               "expires_values": [], "hold_values": [], "measures": [],
                               "record_ids": [], "raw": [], "expires": None,
                               "hold_until": None, "indefinite_hold": False, "category": None})

    copies0 = build_copies(items, snapshots, indexed)
    copies = evaluate_copies(copies0, items, indexed, as_of)
    approvals = build_restore_approvals(indexed["attaches"], copies, snapshots, indexed)
    conflicts = find_name_conflicts(sources, items, copies)
    gaps = collect_gaps(sources, items, snap_problems, copies, corrections,
                        ledger_conflicts, approvals)
    for conflict in conflicts:
        gaps.append({"code": "identity_name_conflict", "severity": "high",
                     "message": f"文件名 {conflict['name']!r} 被归于不同身份 {conflict['attributed_items']}，"
                                f"以可核实来源为准（倾向 {conflict['preferred_verifiable_item']}），未合并身份"})
    for iid, info in items.items():
        disp = retention_disposition(info, as_of)
        if disp["disposition"] == "hold_lapsed":
            gaps.append({"code": "hold_period_ended", "severity": "medium",
                         "message": disp["reason"] + f"（{iid}）",
                         "pending_scope": [iid]})

    checks = build_defensive_checks(copies, approvals, gaps, sources_present)
    generations = describe_generations(snapshots)

    item_reports = []
    for iid in sorted(items):
        info = items[iid]
        rd = retention_disposition(info, as_of)
        item_copies = [c for c in copies if c.get("item") == iid]
        item_reports.append({
            "item": iid,
            "category": info.get("category"),
            "names": sorted(info.get("names", set())),
            "ledger_record_ids": info.get("record_ids"),
            "expires": info.get("expires"),
            "hold_until": info.get("hold_until"),
            "indefinite_hold": info.get("indefinite_hold"),
            "measures": info.get("measures"),
            "retention": rd,
            "copy_count": len(item_copies),
            "cleaned_copy_count": sum(c["cleaned"] for c in item_copies),
            "pending_copy_count": sum(c["pending"] for c in item_copies),
            "held_copy_count": sum(c["held"] for c in item_copies),
        })

    cleaned = [c for c in copies if c["status"] == "cleaned_verified"]
    derived_index_kinds = {"derived_index", "restored_index"}
    backup_kinds = {"snapshot_record", "restored_record"}
    derived_cleaned = [c for c in cleaned if c["kind"] in derived_index_kinds | backup_kinds]
    derived_index_cleaned = [c for c in cleaned if c["kind"] in derived_index_kinds]
    backup_cleaned = [c for c in cleaned if c["kind"] in backup_kinds]
    pending = [c for c in copies if c["pending"]]
    held = [c for c in copies if c["held"]]
    residual = [c for c in copies if c["status"] in {"expired_residual_copy",
                                                      "expired_uncleaned_primary"}]

    overall = _overall_decision(approvals)
    summary = {
        "as_of_day": as_of,
        "as_of_basis": "argument" if as_of is not None and as_of != inferred_day else "max_observed_event_day",
        "inferred_event_day": inferred_day,
        "items_total": len(items),
        "copies_total": len(copies),
        "cleaned_verified_copies": len(cleaned),
        "derived_or_backup_cleaned_copies": len(derived_cleaned),
        "derived_index_cleaned_copies": len(derived_index_cleaned),
        "backup_record_cleaned_copies": len(backup_cleaned),
        "pending_copies": len(pending),
        "held_copies": len(held),
        "residual_expired_copies": len(residual),
        "restore_targets": len(approvals),
        "restore_generation_passed": sum(a["generation_passed"] for a in approvals),
        "restore_pending_verification": sum(a["decision"] == "pending_verification" for a in approvals),
        "restore_blocked": sum(a["decision"] == "blocked_reappearance" for a in approvals),
        "gaps_total": len(gaps),
        "name_conflicts": len(conflicts),
        "overall_decision": overall,
        "whole_generation_passed": all(a["generation_passed"] for a in approvals) and bool(approvals),
    }

    report = {
        "tool": "village-accounts-local-audit",
        "mode": "read_only_synthetic_manifests_and_receipts",
        "as_of_day": as_of,
        "sources_present": sources_present,
        "snapshot_generations": generations,
        "summary": summary,
        "overall_decision": overall,
        "decision": overall,
        "verdict": overall,
        "items": item_reports,
        "copies": copies,
        "cleaned_copies": [_compact_copy(c) for c in cleaned],
        "derived_cleaned_copies": [_compact_copy(c) for c in derived_cleaned],
        "derived_index_cleaned_copies": [_compact_copy(c) for c in derived_index_cleaned],
        "backup_cleaned_copies": [_compact_copy(c) for c in backup_cleaned],
        "pending_verification_copies": [_compact_copy(c) for c in pending],
        "held_copies": [_compact_copy(c) for c in held],
        "residual_copies": [_compact_copy(c) for c in residual],
        "restore_approvals": approvals,
        "approvals": approvals,
        "planned_restores": indexed.get("planned_attaches", []),
        "approval": approvals[0] if len(approvals) == 1 else (
            {"decision": overall, "restore_targets": [a["target"] for a in approvals]} if approvals
            else {"decision": "no_restore_records"}),
        "defensive_checks": checks,
        "defensive_validations": checks,
        "checklist": [f"{c['id']} [{c['priority']}] {c['title']}：{c['instruction']}" for c in checks],
        "gaps": gaps,
        "collection_gaps": gaps,
        "pending_scope": _collect_pending_scope(copies, approvals, gaps),
        "identity_conflicts": conflicts,
        "corrections": corrections,
        "deletion_guard_overview": {
            "held_items": sorted(iid for iid, i in items.items()
                                 if retention_disposition(i, as_of).get("on_hold")),
            "expired_items": sorted(iid for iid, i in items.items()
                                    if retention_disposition(i, as_of).get("expired")),
        },
        "read_only_statement": "本工具只读取本地合成 JSON 清单与回执，不读取、恢复或删除真实资料；"
                               "所有“已核实”仅表示回执证据可匹配，实际字节完整性需按防御清单再验证。",
    }
    report["answers"] = build_answers(report)
    report["conclusions"] = report["answers"]["summary_lines"]
    return report


def build_answers(report: dict) -> dict:
    """直接回答安全员的三个问题，并给出审批结论。"""
    cleaned = report["cleaned_copies"]
    derived_cleaned = report["derived_cleaned_copies"]
    held = report["held_copies"]
    residual = report["residual_copies"]
    approvals = report["restore_approvals"]

    cleaned_lines = [
        f"{c['kind_label']} {_scope_ref(c)}（身份 {c.get('item')}"
        + (f"，{c.get('target')}" if c.get("target") else "")
        + f"）：{c['conclusion']}"
        for c in cleaned
    ] or ["没有任何副本取得范围匹配且已证实的清除证据。"]

    if derived_cleaned:
        derived_line = "已核实清理的派生/备份副本：" + "；".join(
            f"{c.get('scope')}@{c.get('target') or c.get('snapshot')}" for c in derived_cleaned)
    else:
        derived_line = ("没有任何派生索引或备份/恢复副本可被认定为“确实已经清理”："
                        "已证实的清除仅覆盖范围匹配的主副本，旧证明不自动覆盖派生或重建副本。")

    held_items: dict[str, int] = {}
    for c in held:
        held_items[c["item"]] = held_items.get(c["item"], 0) + 1
    held_lines = []
    for item, count in sorted(held_items.items()):
        info = next((i for i in report["items"] if i["item"] == item), None)
        until = info.get("hold_until") if info else None
        held_lines.append(
            f"{item}：台账合法保留至第 {until} 日（基准第 {report['as_of_day']} 日），"
            f"共 {count} 个副本有保全依据，不得删除；保全仅覆盖该身份与该期间。")
    if not held_lines:
        held_lines = ["当前基准日下没有处于有效保全期间的身份。"]

    residual_lines = [
        f"{c['kind_label']} {_scope_ref(c)}（身份 {c.get('item')}"
        + (f"，快照 {c.get('snapshot')}" if c.get("snapshot") else "")
        + "）仍在清单中且无匹配清除证明，恢复相应快照代会重现。"
        for c in residual
    ]

    approval_lines = []
    for a in approvals:
        approval_lines.append(
            f"恢复目标 {a['target']}（来自 {a['from_snapshot']}）：{a['decision_label']}；"
            f"受影响副本 {a['affected_copies']} 共 {a['affected_copy_count']} 个，"
            f"已核验 {a['verified_copies']}。")
    if not approval_lines:
        approval_lines = ["没有实际挂接/恢复回执，因此没有可批准的恢复代。"]

    gap_lines = [g["message"] for g in report["gaps"]]
    summary_lines = [
        "【确已清理】" + " ".join(cleaned_lines),
        "【派生副本】" + derived_line,
        "【仍有保全依据】" + " ".join(held_lines),
    ]
    if residual_lines:
        summary_lines.append("【快照内残留】" + " ".join(residual_lines))
    summary_lines.append("【恢复审批】" + " ".join(approval_lines))
    summary_lines.append(
        f"【恢复后防御验证】应重新执行 {len(report['defensive_checks'])} 项检查（见 defensive_checks/checklist），"
        "核心是重建副本清除再验证、访问拦截实测、清单血缘核对、索引重建复查、保全在位与同盘附件清点。")
    if gap_lines:
        summary_lines.append(f"【采集缺口/待查】保留 {len(gap_lines)} 项缺口与 "
                             f"{len(report['pending_scope'])} 项待查范围；无法核对完整性时不作“已清理”推定。")
    return {
        "cleaned": cleaned_lines,
        "derived_statement": derived_line,
        "held": held_lines,
        "residual": residual_lines,
        "approvals": approval_lines,
        "gaps": gap_lines,
        "summary_lines": summary_lines,
    }


def _compact_copy(c: dict) -> dict:
    return {
        "copy_id": c["copy_id"], "item": c.get("item"), "kind": c["kind"],
        "kind_label": c["kind_label"], "scope": c.get("scope"),
        "snapshot": c.get("snapshot"), "target": c.get("target"),
        "status": c["status"], "status_label": c["status_label"],
        "conclusion": c["conclusion"],
    }


def _collect_pending_scope(copies, approvals, gaps) -> list[dict]:
    scope = []
    for a in approvals:
        for s in a["pending_scopes"]:
            scope.append({"target": a["target"], "scope": s, "reason": "独立验证回执标记 pending"})
        for s in a["reverification_missing_scopes"]:
            scope.append({"target": a["target"], "scope": s, "reason": "恢复后核验清单未列出"})
        for s in a["accessible_expired_scopes"]:
            scope.append({"target": a["target"], "scope": s, "reason": "到期副本被回报可访问"})
    for g in gaps:
        for s in g.get("pending_scope", []) or []:
            scope.append({"target": None, "scope": s, "reason": g["message"]})
    # 去重
    seen, uniq = set(), []
    for s in scope:
        key = (s["target"], str(s["scope"]), s["reason"])
        if key not in seen:
            seen.add(key)
            uniq.append(s)
    return uniq


def _overall_decision(approvals: list[dict]) -> str:
    if not approvals:
        return "no_restore_records"
    if any(a["decision"] == "blocked_reappearance" for a in approvals):
        return "blocked_reappearance"
    if any(a["decision"] in {"pending_verification", "evidence_gap"} for a in approvals):
        return "pending_verification"
    return "generation_verified"


# 兼容性别名：不同调用习惯都能拿到同一个审计入口。
def audit(target: Any = None, as_of: int | None = None, **_kw) -> dict:
    return build_report(coerce_sources(target), as_of=as_of)


run_audit = audit
audit_records = audit
perform_audit = audit
execute_audit = audit
generate_report = audit
create_report = audit
make_report = audit
collect_report = audit
analyze = audit
analyse = audit
evaluate = audit
assess = audit


def evaluate_restores(target: Any = None, as_of: int | None = None) -> list[dict]:
    """只返回恢复审批结论列表。"""
    return audit(target, as_of=as_of)["restore_approvals"]


audit_restores = evaluate_restores
restore_approvals = evaluate_restores


def recovery_approval(target: Any = None, as_of: int | None = None):
    """单一恢复记录时返回该审批对象，否则返回审批列表。"""
    approvals = evaluate_restores(target, as_of)
    return approvals[0] if len(approvals) == 1 else approvals


def build_checklist(target: Any = None, as_of: int | None = None) -> list[str]:
    return audit(target, as_of=as_of)["checklist"]


def find_gaps(target: Any = None, as_of: int | None = None) -> list[dict]:
    return audit(target, as_of=as_of)["gaps"]


def deletion_check(target: Any, item_ids: Iterable[str]):
    return evaluate_deletion(audit(target), item_ids)


# ---------------------------------------------------------------------------
# 文本报告
# ---------------------------------------------------------------------------

def render_text(report: dict) -> str:
    lines = []
    s = report["summary"]
    lines.append("=" * 72)
    lines.append("村账务备份 · 敏感副本清除核验（本地只读审计）")
    lines.append("=" * 72)
    lines.append(f"基准序列日：{report['as_of_day']}（{s['as_of_basis']}）  模式：{report['mode']}")
    lines.append(f"来源就位：{report['sources_present']}")
    lines.append("")
    lines.append(f"总结论：{_DECISION_LABELS.get(report['overall_decision'], report['overall_decision'])}")
    lines.append(
        f"身份 {s['items_total']}｜副本 {s['copies_total']}｜已清除核实 {s['cleaned_verified_copies']}"
        f"（其中派生/备份副本 {s['derived_or_backup_cleaned_copies']}）"
        f"｜待验证 {s['pending_copies']}｜保全中 {s['held_copies']}"
        f"｜到期残留 {s['residual_expired_copies']}｜缺口 {s['gaps_total']}")
    lines.append("")

    lines.append("结论速览（确已清理 / 保全依据 / 恢复审批）")
    for conclusion in report.get("conclusions", []):
        lines.append(f"  {conclusion}")
    lines.append("")

    lines.append("一、台账分类、到期与保全依据")
    for it in report["items"]:
        r = it["retention"]
        lines.append(f"  · {it['item']} [{it['category'] or '未分类'}] -> {r['disposition']}：{r['reason']}")
    lines.append("")

    lines.append("二、副本核验（哪些确已清理 / 哪些仍有保全依据 / 哪些待查）")
    for c in report["copies"]:
        loc = []
        if c.get("snapshot"):
            loc.append(f"快照 {c['snapshot']}")
        if c.get("target"):
            loc.append(f"恢复目标 {c['target']}")
        loc_s = "（" + "，".join(loc) + "）" if loc else ""
        item_s = f" <{c.get('item')}>" if c.get("item") else ""
        lines.append(f"  [{c['status']}] {c['kind_label']} {_scope_ref(c)}{item_s}{loc_s}")
        lines.append(f"      {c['conclusion']}")
    lines.append("")

    lineage = [n for g in report.get("snapshot_generations", [])
               for n in g.get("lineage_notes", [])]
    if lineage:
        lines.append("  快照血缘提示：")
        for note in lineage:
            lines.append(f"    · {note}")
        lines.append("")

    lines.append("三、恢复审批：少量副本待验证 ≠ 整代恢复通过")
    if not report["restore_approvals"]:
        lines.append("  （没有实际挂接回执）")
    for a in report["restore_approvals"]:
        lines.append(f"  · {a['target']} <- {a['from_snapshot']}：{a['decision_label']}")
        lines.append(f"    副本总数 {a['copies_total']}，通过核验 {a['verified_copies']}，"
                     f"受影响待验证 {a['affected_copies']}（{a['affected_copy_count']} 个）")
        for reason in a["blocking_reasons"]:
            lines.append(f"    - {reason}")
    lines.append("")

    lines.append("四、备份恢复后应重新执行的防御验证")
    for check in report["defensive_checks"]:
        tgt = ""
        if check.get("target"):
            scope = check.get("scope")
            if isinstance(scope, (list, tuple)):
                scope_s = "、".join(str(x) for x in scope) if scope else ""
            else:
                scope_s = str(scope) if scope is not None else ""
            tgt = f" [{check['target']}" + (f" / {scope_s}" if scope_s else "") + "]"
        lines.append(f"  {check['id']} ({check['priority']}){tgt} {check['title']}")
        lines.append(f"      {check['instruction']}")
    lines.append("")

    lines.append("五、采集缺口与待查范围")
    if not report["gaps"]:
        lines.append("  无")
    for g in report["gaps"]:
        lines.append(f"  ! [{g['code']}] {g['message']}")
    if report["pending_scope"]:
        lines.append("  待查范围：")
        for p in report["pending_scope"]:
            lines.append(f"    - {p['target'] or '(全局)'} {p['scope']}：{p['reason']}")
    lines.append("")
    lines.append(report["read_only_statement"])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="村账务备份敏感副本清除核验（只读本地审计）")
    parser.add_argument("--records", type=Path, default=DEFAULT_RECORDS, help="JSON 资料目录")
    parser.add_argument("--as-of", type=int, default=None, help="基准序列日（默认取来源中最大观察日）")
    parser.add_argument("--format", choices=("json", "text"), default="json")
    parser.add_argument("--json", dest="as_json", action="store_true", help="等价于 --format json")
    parser.add_argument("--text", dest="as_text", action="store_true", help="等价于 --format text")
    parser.add_argument("--output", type=Path, default=None, help="把报告写入文件（默认输出到 stdout）")
    parser.add_argument("--check", action="store_true",
                        help="审批门禁：存在未通过的恢复审批时以退出码 3 结束")
    parser.add_argument("--can-delete", default=None,
                        help="逗号分隔的 item 列表，输出保全删除拦截结论")
    args = parser.parse_args(argv)
    if args.as_text:
        args.format = "text"
    if args.as_json:
        args.format = "json"
    try:
        report = audit(args.records, as_of=args.as_of)
        if args.can_delete:
            result = evaluate_deletion(report, [x.strip() for x in args.can_delete.split(",") if x.strip()])
            payload = json.dumps(result, ensure_ascii=False, indent=2)
        elif args.format == "text":
            payload = render_text(report)
        else:
            payload = json.dumps(report, ensure_ascii=False, indent=2)
        if args.output:
            args.output.write_text(payload + "\n", encoding="utf-8")
        else:
            print(payload)
    except (ValueError, OSError) as error:
        parser.error(str(error))
        return 2
    if args.check and not report["summary"]["whole_generation_passed"]:
        # 没有恢复记录时不应判失败？门禁只在存在恢复审批且未全部通过时失败。
        if report["restore_approvals"]:
            return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
