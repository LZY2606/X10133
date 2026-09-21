"""数据模型：规范化清单成员、扫描结果等。

这些 dict 结构同时是 canonical JSON 证明的组成部分，字段名保持稳定。
"""

from __future__ import annotations

# 成员类型常量
T_FILE = "file"
T_HARDLINK = "hardlink"
T_SYMLINK = "symlink"
T_DIR = "dir"
T_SPECIAL = "special"

ALL_TYPES = (T_FILE, T_HARDLINK, T_SYMLINK, T_DIR, T_SPECIAL)

