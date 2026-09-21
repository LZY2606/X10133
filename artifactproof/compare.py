"""比较两份规范化清单。

输出明确区分“真实内容差异”与“可忽略差异”（后者由策略声明）。
比较不修改原始清单。
"""

from __future__ import annotations

from typing import Any, Dict, List

from .models import ArchiveManifest
from .policy import Policy
from . import canonical

# 最终结论
VERDICT_REPRODUCIBLE = "reproducible"
VERDICT_EQUIVALENT = "equivalent_under_policy"
VERDICT_DIFFERENT = "content_differs"
VERDICT_QUARANTINED = "quarantined"


def _field_diff(field, left, right, ignored):
    return {
        "field": field,
        "left": left,
        "right": right,
        "ignored": bool(ignored),
    }


def _compare_entries(left, right, policy):
    """返回 (real_diffs, ignored_diffs)。"""
    real: List[Dict[str, Any]] = []
    ignored: List[Dict[str, Any]] = []

    def push(field, lv, rv, is_ignored):
        if lv == rv:
            return
        diff = _field_diff(field, lv, rv, is_ignored)
        (ignored if is_ignored else real).append(diff)

    if left.type != right.type:
        push("type", left.type, right.type, False)

    if left.link_target != right.link_target:
        # 链接目标即其全部“内容”，属于真实内容差异
        push("link_target", left.link_target, right.link_target, False)

    if left.type == "file" or right.type == "file":
        push("content_hash", left.content_hash, right.content_hash, False)

    push("size", left.size, right.size, False)

    if policy.effective_mode(left.mode) != policy.effective_mode(right.mode):
        ignored_by_mask = bool(
            (int(left.mode or "0", 8) ^ int(right.mode or "0", 8))
            & policy.mode_mask
        )
        push("mode", left.mode, right.mode, ignored_by_mask)

    if left.mtime != right.mtime:
        push("mtime", left.mtime, right.mtime, policy.ignore_mtime)

    if (left.uid, left.gid) != (right.uid, right.gid):
        push(
            "uid_gid",
            [left.uid, left.gid],
            [right.uid, right.gid],
            policy.ignore_uidgid,
        )

    if left.order != right.order:
        push("order", left.order, right.order, policy.ignore_order)

    return real, ignored


def _archive_level(manifest_a, manifest_b, policy):
    real: List[Dict[str, Any]] = []
    ignored: List[Dict[str, Any]] = []

    def push(diff):
        (ignored if diff["ignored"] else real).append(diff)

    if manifest_a.format != manifest_b.format:
        push(_field_diff(
            "format", manifest_a.format, manifest_b.format, False
        ))
    if manifest_a.compression != manifest_b.compression:
        push(_field_diff(
            "compression", manifest_a.compression, manifest_b.compression,
            policy.ignore_compression_params,
        ))
    if manifest_a.compression_params != manifest_b.compression_params:
        push(_field_diff(
            "compression_params",
            manifest_a.compression_params, manifest_b.compression_params,
            policy.ignore_compression_params,
        ))
    return real, ignored


def compare_manifests(manifest_a, manifest_b, policy=None):
    """比较两份清单，返回结构化比较结果（dict）。"""
    if policy is None:
        policy = Policy()

    result: Dict[str, Any] = {
        "verdict": None,
        "real_differences": [],
        "ignorable_differences": [],
        "member_diffs": [],
        "only_in_a": [],
        "only_in_b": [],
        "quarantine_notes": [],
        "policy": policy.to_dict(),
    }

    for tag, manifest in (("a", manifest_a), ("b", manifest_b)):
        if manifest.quarantined:
            result["quarantine_notes"].append({
                "side": tag,
                "code": manifest.quarantine.get("code"),
                "reason": manifest.quarantine.get("reason"),
                "prefix_length": manifest.quarantine.get("prefix_length"),
            })

    if manifest_a.quarantined or manifest_b.quarantined:
        result["verdict"] = VERDICT_QUARANTINED
        return result

    real_arch, ign_arch = _archive_level(manifest_a, manifest_b, policy)
    result["real_differences"].extend(real_arch)
    result["ignorable_differences"].extend(ign_arch)

    map_a = {e.path: e for e in manifest_a.entries}
    map_b = {e.path: e for e in manifest_b.entries}
    paths_a = [e.path for e in manifest_a.entries]
    paths_b = [e.path for e in manifest_b.entries]

    result["only_in_a"] = [p for p in paths_a if p not in map_b]
    result["only_in_b"] = [p for p in paths_b if p not in map_a]
    for p in result["only_in_a"]:
        result["real_differences"].append(_field_diff(
            "member_present", p, None, False
        ))
    for p in result["only_in_b"]:
        result["real_differences"].append(_field_diff(
            "member_present", None, p, False
        ))

    for path in paths_a:
        if path not in map_b:
            continue
        real, ignored = _compare_entries(map_a[path], map_b[path], policy)
        if real or ignored:
            result["member_diffs"].append({
                "path": path,
                "real": real,
                "ignorable": ignored,
            })

    has_real = bool(result["real_differences"]) or any(
        md["real"] for md in result["member_diffs"]
    )
    has_ignored = bool(result["ignorable_differences"]) or any(
        md["ignorable"] for md in result["member_diffs"]
    )

    if has_real:
        result["verdict"] = VERDICT_DIFFERENT
    elif has_ignored:
        result["verdict"] = VERDICT_EQUIVALENT
    else:
        result["verdict"] = VERDICT_REPRODUCIBLE
    return result


def build_proof(archive_a, archive_b, manifest_a, manifest_b,
                policy, comparison, file_name=None):
    """构造字节稳定的 JSON 证明对象（不含易变时间戳/数据库 id）。"""
    proof = {
        "artifactproof_version": 1,
        "archives": {
            "a": {
                "content_hash": archive_a["content_hash"],
                "manifest_hash": archive_a["manifest_hash"],
                "format": manifest_a.format,
                "compression": manifest_a.compression,
            },
            "b": {
                "content_hash": archive_b["content_hash"],
                "manifest_hash": archive_b["manifest_hash"],
                "format": manifest_b.format,
                "compression": manifest_b.compression,
            },
        },
        "manifests": {
            "a": manifest_a.to_dict(),
            "b": manifest_b.to_dict(),
        },
        "policy": policy.to_dict(),
        "comparison": {
            "verdict": comparison["verdict"],
            "real_differences": comparison["real_differences"],
            "ignorable_differences": comparison["ignorable_differences"],
            "member_diffs": comparison["member_diffs"],
            "only_in_a": comparison["only_in_a"],
            "only_in_b": comparison["only_in_b"],
            "quarantine_notes": comparison["quarantine_notes"],
        },
    }
    proof["proof_hash"] = canonical.digest(
        {k: v for k, v in proof.items() if k != "proof_hash"}
    )
    return proof
