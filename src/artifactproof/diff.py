"""逐成员比较引擎。

差异分两层：

* **真实内容差异（content）**：成员缺失/新增、类型不同、内容哈希不同、
  符号链接目标不同、硬链接解析到的内容不同。任何一条都会导致“不可复现”。
* **元数据差异（metadata）**：时间戳、uid/gid、权限（受掩码过滤）、
  压缩方式、sparse extent、打包顺序。其中被策略声明为可忽略的因素，
  归入 ``ignorable``；未被忽略的因素归入 ``effective``（同样阻断复现结论）。

策略只影响这些视图的分类，不会修改原始清单。
"""

from __future__ import annotations

VERDICT_REPRODUCIBLE = "reproducible"
VERDICT_DIFFERS = "differs"
VERDICT_QUARANTINED = "quarantined"

VERDICT_TEXT = {
    VERDICT_REPRODUCIBLE: "可复现：在所选策略下两份归档内容与生效元数据完全一致",
    VERDICT_DIFFERS: "不可复现：存在真实内容差异或策略未忽略的元数据差异",
    VERDICT_QUARANTINED: "无法判定：至少一份归档处于隔离状态",
}


def _content_key(member):
    """用于“真实内容”比较的稳定键。"""
    typ = member["type"]
    if typ == "symlink":
        return ("symlink", member.get("link_target"))
    if typ == "hardlink":
        return ("hardlink", member.get("sha256"), member.get("hardlink_resolved"))
    if typ == "file":
        return ("file", member.get("sha256"))
    if typ == "dir":
        return ("dir",)
    return ("special",)


def _metadata_factors(a, b, policy):
    """返回 (effective, ignorable) 两类元数据因素列表。"""
    effective = []
    ignorable = []

    def push(ignore, factor, detail):
        (ignorable if ignore else effective).append(
            {"factor": factor, "a": detail[0], "b": detail[1]}
        )

    if a.get("mtime") != b.get("mtime"):
        push(policy["ignore_mtime"], "mtime", (a.get("mtime"), b.get("mtime")))

    if (a.get("uid"), a.get("gid")) != (b.get("uid"), b.get("gid")):
        push(
            policy["ignore_uid_gid"],
            "uid_gid",
            (
                {"uid": a.get("uid"), "gid": a.get("gid")},
                {"uid": b.get("uid"), "gid": b.get("gid")},
            ),
        )

    ma = a.get("mode")
    mb = b.get("mode")
    mask = policy["mode_mask"]
    if ma is not None and mb is not None and (ma & mask) != (mb & mask):
        # 走到这里说明在掩码保留的权限位上存在差异：属于生效元数据差异
        push(False, "mode", (ma, mb))
    elif (ma is None) != (mb is None):
        push(False, "mode", (ma, mb))

    if a.get("storage") != b.get("storage"):
        push(policy["ignore_compression"], "compression", (a.get("storage"), b.get("storage")))

    if a.get("sparse") != b.get("sparse"):
        # sparse extent 反映的是物理排布，属于可忽略的打包差异；
        # 但它不会影响逻辑内容哈希（空洞已补零）。
        push(True, "sparse_layout", (a.get("sparse"), b.get("sparse")))

    if a.get("order") != b.get("order"):
        push(policy["ignore_order"], "order", (a.get("order"), b.get("order")))

    return effective, ignorable


def compare_manifests(manifest_a, manifest_b, policy):
    """比较两份（非隔离）清单，返回结构化差异与会话结论。"""
    entries = []
    members_a = {m["path"]: m for m in manifest_a["members"]}
    members_b = {m["path"]: m for m in manifest_b["members"]}
    all_paths = sorted(set(members_a) | set(members_b))

    # 顺序差异（打包顺序）：比较同路径集合下的有序序列
    order_a = [m["path"] for m in sorted(manifest_a["members"], key=lambda x: x["order"])]
    order_b = [m["path"] for m in sorted(manifest_b["members"], key=lambda x: x["order"])]

    for path in all_paths:
        a = members_a.get(path)
        b = members_b.get(path)
        if a is None:
            entries.append(
                {
                    "path": path,
                    "status": "added_in_b",
                    "content_diffs": ["member_missing_in_a"],
                    "effective_metadata": [],
                    "ignorable_metadata": [],
                }
            )
            continue
        if b is None:
            entries.append(
                {
                    "path": path,
                    "status": "removed_in_b",
                    "content_diffs": ["member_missing_in_b"],
                    "effective_metadata": [],
                    "ignorable_metadata": [],
                }
            )
            continue

        content_diffs = []
        if _content_key(a) != _content_key(b):
            if a["type"] != b["type"]:
                content_diffs.append("type")
            else:
                if a.get("link_target") != b.get("link_target"):
                    content_diffs.append("link_target")
                if a.get("sha256") != b.get("sha256"):
                    content_diffs.append("sha256")
                if a.get("size") != b.get("size"):
                    content_diffs.append("size")

        effective_meta, ignorable_meta = _metadata_factors(a, b, policy)
        status = "same"
        if content_diffs:
            status = "content_differs"
        elif effective_meta:
            status = "metadata_differs"
        elif ignorable_meta:
            status = "ignorable_only"
        entries.append(
            {
                "path": path,
                "status": status,
                "a": _brief(a),
                "b": _brief(b),
                "content_diffs": content_diffs,
                "effective_metadata": effective_meta,
                "ignorable_metadata": ignorable_meta,
            }
        )

    # 归档级因素（容器压缩、gzip mtime）
    archive_factors = []
    if not policy["ignore_compression"]:
        if manifest_a.get("archive_compression") != manifest_b.get("archive_compression"):
            archive_factors.append(
                {
                    "factor": "archive_compression",
                    "a": manifest_a.get("archive_compression"),
                    "b": manifest_b.get("archive_compression"),
                    "ignored": False,
                }
            )
        if manifest_a.get("archive_gzip_mtime") != manifest_b.get("archive_gzip_mtime"):
            archive_factors.append(
                {
                    "factor": "gzip_mtime",
                    "a": manifest_a.get("archive_gzip_mtime"),
                    "b": manifest_b.get("archive_gzip_mtime"),
                    "ignored": False,
                }
            )

    order_is_permutation = sorted(order_a) == sorted(order_b) and order_a != order_b
    order_factor = None
    if order_is_permutation:
        order_factor = {
            "factor": "member_order",
            "ignored": bool(policy["ignore_order"]),
        }

    content_diff_paths = [e["path"] for e in entries if e["content_diffs"]]
    effective_meta_paths = [e["path"] for e in entries if e["effective_metadata"]]
    ignorable_meta_paths = [e["path"] for e in entries if e["ignorable_metadata"]]

    blocking_archive = [f for f in archive_factors if not f["ignored"]]

    reproducible = (
        not content_diff_paths
        and not effective_meta_paths
        and not blocking_archive
        and not (order_factor and not order_factor["ignored"])
    )

    return {
        "entries": entries,
        "archive_factors": archive_factors,
        "order_factor": order_factor,
        "order_a": order_a,
        "order_b": order_b,
        "summary": {
            "content_diff_count": len(content_diff_paths),
            "effective_metadata_diff_count": len(effective_meta_paths),
            "ignorable_metadata_diff_count": len(ignorable_meta_paths),
            "archive_factor_diff_count": len(blocking_archive),
            "order_differs": bool(order_factor),
            "order_diff_ignored": bool(order_factor and order_factor["ignored"]),
        },
        "verdict": VERDICT_REPRODUCIBLE if reproducible else VERDICT_DIFFERS,
        "verdict_text": VERDICT_TEXT[VERDICT_REPRODUCIBLE if reproducible else VERDICT_DIFFERS],
    }


def _brief(member):
    return {
        "type": member["type"],
        "mode": member.get("mode"),
        "uid": member.get("uid"),
        "gid": member.get("gid"),
        "mtime": member.get("mtime"),
        "size": member.get("size"),
        "sha256": member.get("sha256"),
        "link_target": member.get("link_target"),
        "storage": member.get("storage"),
        "order": member.get("order"),
        "sparse": member.get("sparse"),
        "hardlink_resolved": member.get("hardlink_resolved"),
    }
