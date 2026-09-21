"""归档安全扫描器。

设计约束：
- 绝不把成员解到工作目录或任何临时目录：数据只流经内存并在读取时计数。
- 不跟随符号链接：链接仅做词法解析，逃逸/成环即整份隔离。
- 单遍流式扫描，保留成员在归档中的原始顺序。
- 任何违规（重复路径、绝对路径、上跳路径、链接逃逸、稀疏异常、
  解压体积超限、归档损坏）都让整份归档进入隔离状态，
  仅保留已确认安全的成员前缀与明确原因。
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import posixpath
import tarfile
import zipfile

from .errors import QuarantineError
from .models import (
    ArchiveManifest,
    Entry,
    TYPE_DIR,
    TYPE_FILE,
    TYPE_HARDLINK,
    TYPE_OTHER,
    TYPE_SYMLINK,
)

DEFAULT_BOMB_BUDGET = 100 * 1024 * 1024  # 解压体积上限：100 MiB
DEFAULT_MAX_MEMBERS = 200_000


def detect_format(path):
    """按魔数识别归档格式，回退按扩展名判断。"""
    with open(path, "rb") as fh:
        magic = fh.read(512)
    if magic.startswith(b"PK\x03\x04") or magic.startswith(b"PK\x05\x06"):
        return ("zip", "none")
    if magic[:2] == b"\x1f\x8b":
        return ("tar", "gzip")
    if magic[:3] == b"BZh":
        return ("tar", "bzip2")
    if magic[:6] == b"\xfd7zXZ\x00":
        return ("tar", "xz")
    if len(magic) >= 265 and b"ustar" in (magic[257:265]):
        return ("tar", "none")
    name = path.lower()
    if name.endswith(".zip") or name.endswith(".jar") or name.endswith(".apk"):
        return ("zip", "none")
    if name.endswith((".tar.gz", ".tgz")):
        return ("tar", "gzip")
    if name.endswith((".tar.bz2", ".tbz2", ".tbz")):
        return ("tar", "bzip2")
    if name.endswith((".tar.xz", ".txz")):
        return ("tar", "xz")
    if name.endswith(".tar"):
        return ("tar", "none")
    raise QuarantineError("unknown_format", "无法识别的归档格式（非 zip/tar）")


def _gzip_params(path):
    """从 gzip 成员头读取压缩参数（mtime、XFL）。"""
    params = {}
    try:
        with open(path, "rb") as fh:
            header = fh.read(10)
            if len(header) >= 10 and header[:2] == b"\x1f\x8b":
                params["mtime"] = int.from_bytes(header[4:8], "little")
                params["xfl"] = header[8]
    except OSError:
        pass
    return params


def _xz_params(path):
    """读取 xz 流标志（check 类型）。不同压缩等级在 xz 中没有显式字段。"""
    params = {}
    try:
        with open(path, "rb") as fh:
            header = fh.read(8)
            if header[:6] == b"\xfd7zXZ\x00":
                params["stream_flags"] = "xz-stream-v1"
                params["check"] = header[7] if len(header) > 7 else None
    except OSError:
        pass
    return params


def _normalize_path(raw, member):
    """把成员路径转成 posix 风格并校验。

    zip 中反斜杠也视为分隔符。返回清理后的相对路径；
    绝对路径或含上跳分量即触发隔离。
    """
    if raw is None:
        raise QuarantineError("bad_path", "空成员路径", member=member)
    display = raw.replace("\\", "/")
    is_absolute = display.startswith("/") or (len(display) > 1 and display[1] == ":")
    cleaned = posixpath.normpath(display)
    parts = [p for p in cleaned.split("/") if p not in ("", ".")]
    if not parts:
        # 根、"." 或纯斜杠条目：忽略，不产生成员
        return None
    if is_absolute:
        raise QuarantineError(
            "absolute_path", f"归档内出现绝对路径: {raw!r}", member=raw
        )
    if parts[0] == "..":
        raise QuarantineError(
            "path_traversal", f"路径逃逸出归档根: {raw!r}", member=raw
        )
    if cleaned.startswith("../") or "/../" in cleaned or cleaned.endswith("/.."):
        raise QuarantineError(
            "path_traversal", f"路径含上跳分量: {raw!r}", member=raw
        )
    return "/".join(parts)


def _resolve_link(name, target, symlinks):
    """纯词法解析链接，绝不访问文件系统。

    目标逃逸归档根或解析成环即隔离。返回解析后的相对路径。
    """
    display = target.replace("\\", "/")
    if len(display) > 1 and display[1] == ":":
        raise QuarantineError(
            "link_escape", f"链接 {name!r} 指向绝对路径: {target!r}", member=name
        )
    base = posixpath.dirname(name)
    if display.startswith("/"):
        current = display.lstrip("/")
        absolute = True
    else:
        current = posixpath.normpath(posixpath.join(base, display)) if base else display
        absolute = False
    hops = 0
    seen = {name}
    while True:
        if current in ("", "."):
            if absolute:
                raise QuarantineError(
                    "link_escape",
                    f"链接 {name!r} 解析到归档根之外: {target!r}",
                    member=name,
                )
            raise QuarantineError(
                "link_loop", f"链接 {name!r} 解析到自身/根: {target!r}",
                member=name,
            )
        if current.startswith("../") or current == "..":
            raise QuarantineError(
                "link_escape", f"链接 {name!r} 逃逸出归档根: {target!r}",
                member=name,
            )
        if current in seen:
            raise QuarantineError(
                "link_loop", f"链接 {name!r} 构成链接环: {target!r}", member=name
            )
        if current not in symlinks:
            return current
        seen.add(current)
        hops += 1
        if hops > 40:
            raise QuarantineError(
                "link_loop", f"链接 {name!r} 链接链过长（疑似环）", member=name
            )
        next_target = symlinks[current]
        nd = next_target.replace("\\", "/")
        if nd.startswith("/") or (len(nd) > 1 and nd[1] == ":"):
            current = nd.lstrip("/")
            absolute = True
        else:
            current = posixpath.normpath(posixpath.join(
                posixpath.dirname(current), nd
            ))


def _parse_sparse(pax_headers):
    """解析 GNU/POSIX pax 稀疏元数据。

    返回 (realsize, ranges)；不是稀疏成员返回 None。
    ranges 为 (offset, numbytes) 列表。
    """
    if not pax_headers:
        return None
    real = pax_headers.get("GNU.sparse.realsize") or pax_headers.get("size")
    map_text = pax_headers.get("GNU.sparse.map") or pax_headers.get("GNU.sparse.size")
    ranges = []
    if map_text is not None:
        tokens = map_text.replace(",", "\n").split()
        nums = []
        for tok in tokens:
            try:
                nums.append(int(tok))
            except ValueError:
                raise QuarantineError(
                    "sparse_anomaly", f"无法解析稀疏映射: {map_text!r}"
                )
        if len(nums) % 2 != 0:
            raise QuarantineError(
                "sparse_anomaly", f"稀疏映射偏移/长度不成对: {map_text!r}"
            )
        ranges = [(nums[i], nums[i + 1]) for i in range(0, len(nums), 2)]
    idx = 0
    while f"GNU.sparse.offset.{idx}" in pax_headers:
        try:
            off = int(pax_headers[f"GNU.sparse.offset.{idx}"])
            num = int(pax_headers[f"GNU.sparse.numbytes.{idx}"])
        except (ValueError, KeyError):
            raise QuarantineError("sparse_anomaly", "稀疏区段声明损坏")
        ranges.append((off, num))
        idx += 1
    if "GNU.sparse.offset" in pax_headers:
        try:
            ranges.append((
                int(pax_headers["GNU.sparse.offset"]),
                int(pax_headers["GNU.sparse.numbytes"]),
            ))
        except (ValueError, KeyError):
            raise QuarantineError("sparse_anomaly", "稀疏区段声明损坏")
    if real is None and not ranges:
        return None
    try:
        realsize = int(real) if real is not None else None
    except (TypeError, ValueError):
        raise QuarantineError("sparse_anomaly", f"稀疏 realsize 损坏: {real!r}")
    # 结构校验：负数、越界、重叠区间都属于稀疏异常
    if realsize is not None and realsize < 0:
        raise QuarantineError("sparse_anomaly", "稀疏 realsize 为负")
    ordered = sorted(ranges)
    prev_end = 0
    for off, num in ordered:
        if off < 0 or num < 0:
            raise QuarantineError("sparse_anomaly", "稀疏区段偏移/长度为负")
        if realsize is not None and off + num > realsize:
            raise QuarantineError(
                "sparse_anomaly", "稀疏区段超出 realsize 声明的范围"
            )
        if off < prev_end:
            raise QuarantineError("sparse_anomaly", "稀疏区段相互重叠")
        prev_end = off + num
    return (realsize, ranges)


class _Scanner:
    def __init__(self, path, budget, max_members):
        self.path = path
        self.budget = budget
        self.max_members = max_members
        self.used = 0
        self.entries = []
        self.seen_paths = set()
        self.symlinks = {}
        self.order = 0

    def _charge(self, amount):
        if amount < 0:
            raise QuarantineError("sparse_anomaly", "成员大小声明为负")
        if self.used + amount > self.budget:
            raise QuarantineError(
                "bomb_budget_exceeded",
                f"解压体积 {self.used + amount} 字节超过预算 {self.budget} 字节",
            )
        self.used += amount

    def _register(self, path):
        if path is None:
            return None
        if path in self.seen_paths:
            raise QuarantineError(
                "duplicate_path", f"归档内出现重复路径: {path!r}", member=path
            )
        self.seen_paths.add(path)
        idx = self.order
        self.order += 1
        if self.order > self.max_members:
            raise QuarantineError("too_many_members", "成员数量超过上限")
        return idx

    def _read_member(self, src, declared):
        """带计数上限地读取成员数据，防止 zip 类压缩炸弹在展开阶段超量。"""
        self._charge(declared)
        hasher = hashlib.sha256()
        remaining = declared
        while remaining > 0:
            chunk = src.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            hasher.update(chunk)
            remaining -= len(chunk)
        if remaining != 0:
            raise QuarantineError(
                "bomb_budget_exceeded",
                "成员声明大小与实际展开数据不一致，疑似压缩炸弹",
            )
        return "sha256:" + hasher.hexdigest()

    # ---- zip ----
    def scan_zip(self):
        try:
            zf = zipfile.ZipFile(self.path)
        except (zipfile.BadZipFile, OSError) as exc:
            raise QuarantineError("malformed_archive", f"zip 已损坏: {exc}")
        with zf:
            for info in zf.infolist():
                raw_name = info.filename
                path = _normalize_path(raw_name, raw_name)
                if path is None:
                    continue
                idx = self._register(path)
                mode = None
                create_system = getattr(info, "create_system", 0)
                unix_attr = (info.external_attr >> 16) & 0xFFFF
                if info.external_attr & 0xFFFF0000:
                    mode = "%04o" % (unix_attr & 0o7777)
                entry_type = TYPE_DIR if raw_name.endswith("/") else TYPE_FILE
                link_target = None
                if create_system == 3 and (unix_attr & 0o170000) == 0o120000:
                    entry_type = TYPE_SYMLINK
                size = int(info.file_size)
                content_hash = None
                mtime = None
                try:
                    import calendar as _calendar
                    mtime = int(_calendar.timegm(info.date_time))
                except (ValueError, TypeError, OverflowError):
                    mtime = None
                if entry_type == TYPE_DIR:
                    pass
                elif entry_type == TYPE_SYMLINK:
                    with zf.open(info) as src:
                        data = src.read(size)
                    link_target = data.decode("utf-8", "surrogateescape")
                    resolved = _resolve_link(path, link_target, self.symlinks)
                    self.symlinks[path] = link_target
                else:
                    with zf.open(info) as src:
                        content_hash = self._read_member(src, size)
                entry = Entry(
                    order=idx,
                    path=path,
                    type=entry_type,
                    mode=mode,
                    size=size,
                    content_hash=content_hash,
                    link_target=link_target,
                    mtime=mtime,
                    uid=None,
                    gid=None,
                )
                self.entries.append(entry)

    # ---- tar ----
    def scan_tar(self):
        try:
            tf = tarfile.open(self.path, mode="r:*")
        except (tarfile.TarError, OSError) as exc:
            raise QuarantineError("malformed_archive", f"tar 已损坏: {exc}")
        with tf:
            for member in tf:
                if not member.name or member.type in (
                    tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME,
                    tarfile.GNUTYPE_LONGLINK, tarfile.SOLARIS_XHDTYPE,
                ):
                    continue
                raw_name = member.name
                path = _normalize_path(raw_name, raw_name)
                if path is None:
                    continue
                idx = self._register(path)
                mode = "%04o" % (member.mode & 0o7777) if member.mode is not None else None
                mtype = member.type
                pax = getattr(member, "pax_headers", None) or {}
                sparse = None
                if any(k.startswith("GNU.sparse") for k in pax) or mtype == tarfile.GNUTYPE_SPARSE:
                    sparse = _parse_sparse(pax)
                if mtype in (tarfile.SYMTYPE,):
                    entry_type = TYPE_SYMLINK
                elif mtype in (tarfile.LNKTYPE,):
                    entry_type = TYPE_HARDLINK
                elif mtype == tarfile.DIRTYPE or raw_name.endswith("/"):
                    entry_type = TYPE_DIR
                elif mtype == tarfile.REGTYPE or mtype == tarfile.AREGTYPE:
                    entry_type = TYPE_FILE
                else:
                    entry_type = TYPE_OTHER

                logical_size = int(member.size)
                if sparse and sparse[0] is not None:
                    logical_size = sparse[0]

                content_hash = None
                link_target = None
                if entry_type == TYPE_SYMLINK:
                    link_target = member.linkname
                    _resolve_link(path, link_target, self.symlinks)
                    self.symlinks[path] = link_target
                elif entry_type == TYPE_HARDLINK:
                    link_target = member.linkname
                    resolved = _resolve_link(path, link_target, self.symlinks)
                    if resolved not in self.seen_paths:
                        raise QuarantineError(
                            "hardlink_dangling",
                            f"硬链接 {path!r} 指向归档中不存在的成员: {link_target!r}",
                            member=path,
                        )
                    target_entry = next(
                        (e for e in self.entries if e.path == resolved), None
                    )
                    content_hash = target_entry.content_hash if target_entry else None
                elif entry_type == TYPE_FILE:
                    src = tf.extractfile(member)
                    if src is None:
                        raise QuarantineError(
                            "malformed_archive", f"无法读取成员数据: {path!r}",
                            member=path,
                        )
                    # tarfile 已按稀疏映射把空洞补 0；member.size 即逻辑 realsize
                    content_hash = self._read_member(src, logical_size)
                elif entry_type == TYPE_DIR:
                    pass
                # TYPE_OTHER：设备/fifo 等，记录元数据但不读取数据

                self.entries.append(Entry(
                    order=idx,
                    path=path,
                    type=entry_type,
                    mode=mode,
                    size=logical_size,
                    content_hash=content_hash,
                    link_target=link_target,
                    mtime=int(member.mtime) if member.mtime is not None else None,
                    uid=member.uid if member.uid is not None else None,
                    gid=member.gid if member.gid is not None else None,
                ))


def scan_archive(path, budget=DEFAULT_BOMB_BUDGET,
                 max_members=DEFAULT_MAX_MEMBERS):
    """安全扫描归档，返回 :class:`ArchiveManifest`。

    出问题时不抛异常，而是返回带 ``quarantine`` 的清单，
    其中保留已扫描到的安全前缀和明确原因。
    """
    size_bytes = os.path.getsize(path) if os.path.exists(path) else 0
    try:
        fmt, compression = detect_format(path)
    except QuarantineError as exc:
        return ArchiveManifest(
            format="unknown",
            compression="none",
            size_bytes=size_bytes,
            quarantine={
                "code": exc.code,
                "reason": exc.message,
                "member": exc.member,
                "prefix_length": 0,
            },
        )
    params = {}
    if compression == "gzip":
        params = _gzip_params(path)
    elif compression == "xz":
        params = _xz_params(path)

    manifest = ArchiveManifest(
        format=fmt,
        compression=compression,
        compression_params=params,
        size_bytes=size_bytes,
    )
    scanner = _Scanner(path, budget, max_members)
    try:
        if fmt == "zip":
            scanner.scan_zip()
        else:
            scanner.scan_tar()
    except QuarantineError as exc:
        prefix = [e.to_dict() for e in scanner.entries]
        # 出错成员若尚未入列（绝大多数情况），前缀就是已安全确认的部分
        manifest.entries = scanner.entries
        manifest.quarantine = {
            "code": exc.code,
            "reason": exc.message,
            "member": exc.member,
            "prefix_length": len(prefix),
        }
        return manifest
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError, gzip.BadGzipFile) as exc:
        manifest.entries = scanner.entries
        manifest.quarantine = {
            "code": "malformed_archive",
            "reason": f"归档数据流损坏: {exc}",
            "member": None,
            "prefix_length": len(manifest.entries),
        }
        return manifest
    manifest.entries = scanner.entries
    return manifest
