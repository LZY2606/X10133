"""artifactproof：可复现产物核验站。

只依赖标准库；所有扫描与比较均离线完成，绝不把归档解到工作目录，
也不跟随归档内的符号链接。
"""

from .errors import QuarantineError
from .models import Entry, ArchiveManifest
from .scanner import scan_archive, DEFAULT_BOMB_BUDGET
from .policy import Policy
from .compare import compare_manifests
from . import canonical

__all__ = [
    "QuarantineError",
    "Entry",
    "ArchiveManifest",
    "Policy",
    "scan_archive",
    "compare_manifests",
    "canonical",
    "DEFAULT_BOMB_BUDGET",
]
