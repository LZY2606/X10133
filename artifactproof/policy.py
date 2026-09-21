"""版本化比较策略。

策略声明哪些差异“可忽略”，只作用于比较视图与结论，
原始清单一经生成永不改写。
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict

DEFAULT_MODE_MASK = 0o0000
FULL_MODE_MASK = 0o7777


@dataclass
class Policy:
    name: str = "strict"
    version: int = 1
    ignore_mtime: bool = False
    ignore_uidgid: bool = False
    # 权限按位掩码后比较：0o7777 表示完全忽略权限
    mode_mask: int = DEFAULT_MODE_MASK
    ignore_compression_params: bool = False
    ignore_order: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "ignore_mtime": self.ignore_mtime,
            "ignore_uidgid": self.ignore_uidgid,
            "mode_mask": int(self.mode_mask) & FULL_MODE_MASK,
            "ignore_compression_params": self.ignore_compression_params,
            "ignore_order": self.ignore_order,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Policy":
        return cls(
            name=data.get("name", "strict"),
            version=int(data.get("version", 1)),
            ignore_mtime=bool(data.get("ignore_mtime", False)),
            ignore_uidgid=bool(data.get("ignore_uidgid", False)),
            mode_mask=int(data.get("mode_mask", 0)) & FULL_MODE_MASK,
            ignore_compression_params=bool(
                data.get("ignore_compression_params", False)
            ),
            ignore_order=bool(data.get("ignore_order", False)),
        )

    def effective_mode(self, mode_text):
        """八进制权限经掩码后的有效值；掩码位为 1 表示该位可忽略。"""
        if mode_text is None:
            return None
        return int(mode_text, 8) & (~self.mode_mask) & FULL_MODE_MASK
