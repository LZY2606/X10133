"""版本化比较策略。

策略声明“哪些因素可忽略”，只影响比较视图，绝不改写原始清单。

可忽略因素：
* ``ignore_mtime``      成员时间戳（以及 tar.gz 的 gzip 容器 mtime）
* ``ignore_uid_gid``    成员 uid/gid
* ``mode_mask``         权限掩码；比较时只比较 ``mode & mask`` 的位，
                        默认 ``0o7777`` 表示全部权限位都参与比较；
                        设为 0 表示忽略全部权限位
* ``ignore_compression`` 压缩参数（zip 每成员压缩方式 / tar 容器压缩与 gzip mtime）
* ``ignore_order``      成员在归档中的打包顺序

策略本身不可变；每次修改都会产生新的 version，并保留全部历史版本。
"""

from __future__ import annotations

from .canonical import canonical_hash

POLICY_VERSION_KIND = "policy/v1"


def normalize_policy(data: dict) -> dict:
    """补齐并校验策略字段，返回规范化（不含版本号）的策略体。"""
    ignore_mtime = bool(data.get("ignore_mtime", True))
    ignore_uid_gid = bool(data.get("ignore_uid_gid", True))
    ignore_compression = bool(data.get("ignore_compression", True))
    ignore_order = bool(data.get("ignore_order", False))

    mode_mask = data.get("mode_mask", 0o7777)
    if isinstance(mode_mask, str):
        mode_mask = int(mode_mask, 8) if mode_mask.strip().startswith(("o", "0o")) else int(mode_mask)
    mode_mask = int(mode_mask)
    if mode_mask < 0 or mode_mask > 0o7777:
        raise ValueError("mode_mask 必须在 0..0o7777 之间")

    name = str(data.get("name", "default"))
    return {
        "name": name,
        "ignore_mtime": ignore_mtime,
        "ignore_uid_gid": ignore_uid_gid,
        "ignore_compression": ignore_compression,
        "ignore_order": ignore_order,
        "mode_mask": mode_mask,
    }


def policy_body_hash(body: dict) -> str:
    return canonical_hash(body)


def default_policy() -> dict:
    """默认策略：时间戳、uid/gid、压缩参数可忽略；权限与顺序仍参与比较。"""
    return normalize_policy(
        {
            "name": "默认（忽略时间戳/属主/压缩）",
            "ignore_mtime": True,
            "ignore_uid_gid": True,
            "ignore_compression": True,
            "ignore_order": False,
            "mode_mask": 0o7777,
        }
    )

