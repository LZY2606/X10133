"""规范化清单的数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any

# 归档成员类型
TYPE_FILE = "file"
TYPE_DIR = "dir"
TYPE_SYMLINK = "symlink"
TYPE_HARDLINK = "hardlink"
TYPE_OTHER = "other"

VALID_TYPES = {TYPE_FILE, TYPE_DIR, TYPE_SYMLINK, TYPE_HARDLINK, TYPE_OTHER}


@dataclass
class Entry:
    """规范化清单中的单个成员。

    所有字段均为可 JSON 序列化的简单类型，保证字节稳定导出。
    """

    order: int
    path: str
    type: str
    mode: Optional[str] = None          # 八进制权限字符串，如 "0755"
    size: int = 0                       # 逻辑大小（字节）
    content_hash: Optional[str] = None  # "sha256:<hex>"，链接/目录为 None
    link_target: Optional[str] = None   # 符号链接/硬链接目标
    mtime: Optional[int] = None         # epoch 秒
    uid: Optional[int] = None
    gid: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Entry":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class ArchiveManifest:
    """整份归档的规范化清单。"""

    format: str                                    # "zip" | "tar"
    compression: str = "none"                      # none|gzip|bzip2|xz
    compression_params: Dict[str, Any] = field(default_factory=dict)
    entries: List[Entry] = field(default_factory=list)
    quarantine: Optional[Dict[str, Any]] = None
    size_bytes: int = 0

    @property
    def quarantined(self) -> bool:
        return self.quarantine is not None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": self.format,
            "compression": self.compression,
            "compression_params": dict(self.compression_params),
            "entries": [e.to_dict() for e in self.entries],
            "quarantine": self.quarantine,
            "size_bytes": self.size_bytes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ArchiveManifest":
        return cls(
            format=data["format"],
            compression=data.get("compression", "none"),
            compression_params=dict(data.get("compression_params", {})),
            entries=[Entry.from_dict(e) for e in data.get("entries", [])],
            quarantine=data.get("quarantine"),
            size_bytes=data.get("size_bytes", 0),
        )
