"""字节稳定（canonical）JSON。

规则：
- dict 按键的 UTF-8 字节序排序；
- 不输出无意义空白；
- ``"``、``\\``、``/`` 一律转义，非 ASCII 原样输出 UTF-8；
- 不允许 NaN/Infinity；
- 末尾固定一个换行符，便于命令行比较。

同一份逻辑文档在任何机器、任何 Python 字典插入顺序下都得到完全相同的字节。
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Tuple

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "/": "\\/",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _encode_string(s: str) -> bytes:
    out = ['"']
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out).encode("utf-8")


def _encode(obj: Any) -> bytes:
    if obj is None:
        return b"null"
    if obj is True:
        return b"true"
    if obj is False:
        return b"false"
    if isinstance(obj, str):
        return _encode_string(obj)
    if isinstance(obj, int):
        return str(obj).encode("ascii")
    if isinstance(obj, float):
        if obj != obj or obj in (float("inf"), float("-inf")):
            raise ValueError("canonical JSON 不支持 NaN/Infinity")
        return repr(obj).encode("ascii")
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: kv[0].encode("utf-8"))
        parts: List[bytes] = [b"{"]
        first = True
        for key, value in items:
            if not isinstance(key, str):
                raise ValueError("canonical JSON 只支持字符串键")
            if not first:
                parts.append(b",")
            first = False
            parts.append(_encode_string(key))
            parts.append(b":")
            parts.append(_encode(value))
        parts.append(b"}")
        return b"".join(parts)
    if isinstance(obj, (list, tuple)):
        parts = [b"["]
        first = True
        for value in obj:
            if not first:
                parts.append(b",")
            first = False
            parts.append(_encode(value))
        parts.append(b"]")
        return b"".join(parts)
    raise TypeError("不支持 canonical JSON 编码的类型: %r" % type(obj))


def canonical_bytes(obj: Any) -> bytes:
    """把 JSON 兼容对象编码为确定字节（UTF-8，末尾一个换行）。"""
    return _encode(obj) + b"\n"


def canonical_hash(obj: Any) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()
