"""规范化清单。

清单是扫描结果的不可变快照。策略永远只改变比较视图，不会改写清单。
"""

from __future__ import annotations

from .canonical import canonical_hash
from .models import T_HARDLINK

MANIFEST_VERSION = 1


def _resolve_hardlinks(members):
    """为硬链接解析其指向的常规文件内容哈希（不跟随符号链接）。

    * 目标必须在此前已出现，并且本身是常规文件或已解析的硬链接；
    * 目标是符号链接时绝不跟随（安全要求），返回 None；
    * 找不到目标（悬空）时返回 None，并在 ``hardlink_resolved`` 标注。
    """
    by_path = {}
    out = []
    for member in members:
        item = dict(member)
        if member["type"] == T_HARDLINK:
            target = member["link_target"]
            target_entry = by_path.get(target)
            resolved = None
            if target_entry is not None and target_entry["type"] == T_HARDLINK:
                resolved = target_entry.get("sha256")
            elif target_entry is not None and target_entry.get("sha256") is not None:
                # 只有常规文件才继承内容；符号链接（也有 sha256）不跟随
                from .models import T_FILE

                if target_entry["type"] == T_FILE:
                    resolved = target_entry["sha256"]
            item["sha256"] = resolved
            item["hardlink_resolved"] = resolved is not None
        else:
            item["hardlink_resolved"] = None
        by_path[member["path"]] = item
        out.append(item)
    return out


def build_manifest(scan: dict, archive_filename: str, blob_sha256: str, blob_size: int):
    """根据扫描结果构建规范化清单 dict（不做任何 I/O 落盘）。

    隔离归档同样生成清单，便于持久化查看安全前缀与原因，
    但 ``quarantined`` 为真，不允许参与正式比较结论。
    """
    members = _resolve_hardlinks(scan.get("members", []))
    members = sorted(members, key=lambda m: m["order"])

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "archive_filename": archive_filename,
        "archive_family": scan.get("family"),
        "archive_compression": scan.get("compression"),
        "archive_gzip_mtime": scan.get("gzip_mtime"),
        "blob_sha256": blob_sha256,
        "blob_size": blob_size,
        "quarantined": bool(scan.get("quarantined")),
        "quarantine_reason": scan.get("quarantine_reason"),
        "quarantine_path": scan.get("quarantine_path"),
        "safe_prefix": list(scan.get("safe_prefix", [])),
        "member_count": len(members),
        "members": members,
    }
    # 清单自身内容哈希：覆盖除该字段外的全部规范内容，便于证明引用。
    manifest["manifest_sha256"] = canonical_hash(
        {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    )
    return manifest

