"""字节稳定的 JSON 序列化与哈希。

键排序、固定分隔符、无多余空白；相同逻辑对象在任何机器上
都产生完全相同的字节序列。
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

ENCODING = "utf-8"


def canonical_bytes(obj: Any) -> bytes:
    text = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode(ENCODING)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any) -> str:
    """返回规范化 JSON 字节的 sha256 hex。"""
    return sha256_hex(canonical_bytes(obj))
