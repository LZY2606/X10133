"""安全归档扫描器。

设计原则（对应需求）：

* **从不解压到工作目录**：所有成员数据只通过流读取并增量计算哈希，
  不会把任何成员写到文件系统，因此异常时也不会留下部分解压文件。
* **不跟随符号链接**：链接只记录其字面目标，绝不读取目标内容。
* **危险路径整份隔离**：重复路径、绝对路径、上跳路径、链接逃逸、
  sparse 异常、解压体积超限任一发生，整份归档标记为隔离，
  同时保留“安全扫描到的前缀”和明确原因。
* 支持 zip 与 tar 系列（tar / tar.gz / tar.bz2 / tar.xz）。
"""

from __future__ import annotations

import hashlib
import io
import struct
import tarfile
import time
import zipfile

from .models import T_DIR, T_FILE, T_HARDLINK, T_SPECIAL, T_SYMLINK

DEFAULT_BUDGET = 100 * 1024 * 1024  # 解压逻辑体积预算，默认 100 MiB
CHUNK = 1024 * 1024


class QuarantineError(Exception):
    """扫描期间触发的、必须整份隔离的安全问题。"""

    def __init__(self, reason: str, path: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.path = path


def detect_format(blob: bytes):
    """根据魔数判断归档格式。返回 ``(family, compression)``。"""
    if blob[:4] == b"PK\x03\x04" or blob[:4] == b"PK\x05\x06" or blob[:4] == b"PK\x07\x08":
        return "zip", "zip"
    if blob[:2] == b"\x1f\x8b":
        return "tar", "gzip"
    if blob[:3] == b"BZh":
        return "tar", "bzip2"
    if blob[:6] == b"\xfd7zXZ\x00":
        return "tar", "xz"
    # 未压缩 ustar（POSIX: "ustar\x00" + "00"；GNU: "ustar  \x00"）
    if len(blob) >= 265 and blob[257:262] == b"ustar":
        return "tar", "none"
    # 老式无 magic 的 tar：至少一个 512 字节块，且首块校验和合法
    if len(blob) >= 512 and len(blob) % 512 == 0 and _looks_like_plain_tar(blob):
        return "tar", "none"
    raise QuarantineError("无法识别的归档格式（既非 zip 也非 tar 系列）")


def _looks_like_plain_tar(blob):
    """通过首块 tar 校验和判断是否为无 magic 的老式 tar，避免误判普通文本。"""
    block = blob[:512]
    if block == b"\x00" * 512:
        return False
    stored = block[148:156].rstrip(b"\x00 ").strip()
    try:
        expected = int(stored, 8)
    except (ValueError, TypeError):
        return False
    actual = sum(block[:148]) + sum(b"        ") + sum(block[156:])
    return actual == expected


def normalize_member_path(raw: str):
    """规范化成员路径，返回 ``(clean, is_dir)`` 或在危险时抛异常。

    规则：
    * 反斜杠统一为 POSIX 分隔符（zip 常见）；
    * 拒绝绝对路径与盘符；
    * 逐段规范化，任一段上跳（``..``）即隔离；
    * 去掉首尾空白段；目录以结尾 ``/`` 判定。
    """
    if raw is None:
        raise QuarantineError("成员缺少路径名")
    name = raw.replace("\\", "/")
    is_dir = name.endswith("/")
    # 拒绝 Windows 盘符（如 C:）
    if len(name) >= 2 and name[1] == ":":
        raise QuarantineError("绝对路径（盘符）", name)
    if name.startswith("/"):
        raise QuarantineError("绝对路径", name)
    parts = []
    for part in name.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise QuarantineError("上跳路径（..）", name)
        # NUL 字节不允许出现在路径里
        if "\x00" in part:
            raise QuarantineError("路径包含 NUL 字节", name)
        parts.append(part)
    clean = "/".join(parts)
    if not clean:
        if is_dir:
            return "", True
        raise QuarantineError("空路径成员", name)
    return clean, is_dir


def check_link_target(target: str):
    """检查符号/硬链接目标是否会逃逸归档根。

    绝对目标一律拒绝；相对目标解析后若跳出根目录则拒绝。
    返回规范化后的目标字符串（仅用于展示，永不被跟随）。
    """
    if target is None or target == "":
        raise QuarantineError("链接缺少目标")
    t = target.replace("\\", "/")
    if t.startswith("/"):
        raise QuarantineError("链接逃逸：绝对目标", target)
    if len(t) >= 2 and t[1] == ":":
        raise QuarantineError("链接逃逸：盘符目标", target)
    depth = 0
    for part in t.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                raise QuarantineError("链接逃逸：目标跳出归档根", target)
        else:
            depth += 1
    return t


def _hash_stream(fp, size, budget_state, quarantine_on_limit=True):
    """增量读取并哈希成员内容，同时累计解压预算。"""
    h = hashlib.sha256()
    remaining = size
    total = budget_state["total"]
    while remaining > 0:
        chunk = fp.read(min(CHUNK, remaining))
        if not chunk:
            raise QuarantineError("成员数据被截断（声明大小大于实际数据）")
        h.update(chunk)
        remaining -= len(chunk)
        total += len(chunk)
        budget_state["total"] = total
        if total > budget_state["limit"]:
            if quarantine_on_limit:
                raise QuarantineError(
                    "解压体积超限：累计 %d 字节，预算 %d 字节"
                    % (total, budget_state["limit"])
                )
    return h.hexdigest()


_ZIP_COMPRESSION = {
    zipfile.ZIP_STORED: "stored",
    zipfile.ZIP_DEFLATED: "deflate",
    zipfile.ZIP_BZIP2: "bzip2",
    zipfile.ZIP_LZMA: "lzma",
}


def _scan_zip(blob: bytes, budget: int, members):
    seen = set()
    budget_state = {"total": 0, "limit": budget}
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except (zipfile.BadZipFile, Exception) as exc:
        raise QuarantineError("损坏的 zip 归档：%s" % exc)
    # 以中央目录顺序为“归档中的原始顺序”
    infos = zf.infolist()
    zf.testzip = None  # 不触发任何解压到磁盘的行为
    for index, info in enumerate(infos):
        clean, is_dir = normalize_member_path(info.filename)
        if clean == "" and is_dir:
            # 裸根目录条目没有实际意义，跳过但保留原始顺序编号
            continue
        if clean in seen:
            raise QuarantineError("重复路径成员", clean)
        seen.add(clean)

        mode = (info.external_attr >> 16) & 0xFFFF
        is_unix = bool(info.external_attr & 0xFFFF0000) and ((info.create_system == 3) or mode != 0)
        if not is_unix:
            mode = 0o755 if is_dir else 0o644

        # zip 里符号链接：Unix 模式为符号链接（0120000），内容是目标字符串
        is_symlink_mode = (mode & 0o170000) == 0o120000
        comp = _ZIP_COMPRESSION.get(info.compress_type, str(info.compress_type))

        member = {
            "order": index,
            "path": clean,
            "mode": mode & 0o7777,
            "uid": None,
            "gid": None,
            "mtime": int(time.mktime(info.date_time + (0, 0, -1)))
            if _valid_zip_date(info.date_time)
            else None,
            "size": 0,
            "sha256": None,
            "link_target": None,
            "storage": comp,
            "sparse": None,
        }

        if is_dir or info.is_dir():
            member["type"] = T_DIR
            members.append(member)
            continue

        if is_symlink_mode:
            with zf.open(info, "r") as fp:
                raw_target = fp.read()
            target = raw_target.decode("utf-8", "surrogateescape")
            member["type"] = T_SYMLINK
            member["link_target"] = check_link_target(target)
            member["size"] = len(raw_target)
            member["sha256"] = hashlib.sha256(raw_target).hexdigest()
            members.append(member)
            continue

        # 普通文件：流式读取，绝不落盘
        member["type"] = T_FILE
        try:
            with zf.open(info, "r") as fp:
                member["sha256"] = _hash_stream(fp, info.file_size, budget_state)
        except QuarantineError:
            raise
        except Exception as exc:
            raise QuarantineError("成员数据损坏：%s" % exc, clean)
        member["size"] = info.file_size
        members.append(member)

    return {
        "family": "zip",
        "compression": "zip",
        "members": members,
    }


def _valid_zip_date(dt):
    try:
        return dt[0] >= 1980
    except Exception:
        return False


_TAR_COMPRESSION = {"none": "none", "gzip": "gzip", "bzip2": "bzip2", "xz": "xz"}


def validate_sparse(sparse, logical_size, path):
    """校验 GNU/PAX sparse extent 表。

    合法条件：非空、每个 extent 非零长度、偏移非负、按偏移升序、
    不重叠、不超过逻辑文件大小。任何异常都构成 sparse 异常并隔离。
    """
    if not sparse:
        raise QuarantineError("sparse 成员缺少 extent 表", path)
    normalized = []
    last_end = 0
    last_offset = None
    for entry in sparse:
        try:
            offset, numbytes = int(entry[0]), int(entry[1])
        except (TypeError, ValueError, IndexError):
            raise QuarantineError("sparse extent 无法解析", path)
        # tarfile 会把未使用的 GNU sparse 槽位解析为 (0, 0)，忽略
        if offset == 0 and numbytes == 0:
            continue
        if offset < 0 or numbytes <= 0:
            raise QuarantineError("sparse extent 偏移/长度非法", path)
        if last_offset is not None and offset < last_end:
            raise QuarantineError("sparse extent 重叠或乱序", path)
        if offset + numbytes > logical_size:
            raise QuarantineError("sparse extent 超出逻辑文件大小", path)
        normalized.append([offset, numbytes])
        last_end = offset + numbytes
        last_offset = offset
    if not normalized:
        raise QuarantineError("sparse 成员缺少有效 extent", path)
    return normalized


def _scan_tar(blob: bytes, compression: str, budget: int, members):
    seen = set()
    budget_state = {"total": 0, "limit": budget}
    try:
        read_mode = {"none": "r:", "gzip": "r:gz", "bzip2": "r:bz2", "xz": "r:xz"}
        mode = read_mode.get(compression)
        if mode is None:
            raise QuarantineError("未知 tar 压缩类型: %s" % compression)
        tf = tarfile.open(fileobj=io.BytesIO(blob), mode=mode)
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise QuarantineError("损坏的 tar 归档：%s" % exc)

    index = 0
    try:
        for info in tf:
            order = index
            index += 1
            clean, is_dir_flag = normalize_member_path(info.name)
            if clean == "":
                continue
            if clean in seen:
                raise QuarantineError("重复路径成员", clean)
            seen.add(clean)

            member = {
                "order": order,
                "path": clean,
                "mode": int(info.mode) & 0o7777 if info.mode is not None else None,
                "uid": int(info.uid) if info.uid is not None else None,
                "gid": int(info.gid) if info.gid is not None else None,
                "mtime": int(info.mtime) if info.mtime is not None else None,
                "size": 0,
                "sha256": None,
                "link_target": None,
                "storage": "tar",
                "sparse": None,
            }

            if info.isdir():
                member["type"] = T_DIR
                member["size"] = 0
                members.append(member)
                continue

            if info.issym():
                member["type"] = T_SYMLINK
                target = info.linkname.decode("utf-8", "surrogateescape") if isinstance(info.linkname, bytes) else info.linkname
                member["link_target"] = check_link_target(target)
                target_bytes = target.encode("utf-8", "surrogateescape")
                member["size"] = len(target_bytes)
                member["sha256"] = hashlib.sha256(target_bytes).hexdigest()
                members.append(member)
                continue

            if info.islnk():
                member["type"] = T_HARDLINK
                target = info.linkname.decode("utf-8", "surrogateescape") if isinstance(info.linkname, bytes) else info.linkname
                member["link_target"] = check_link_target(target)
                members.append(member)
                continue

            if info.ischr() or info.isblk() or info.isfifo() or info.isdev():
                member["type"] = T_SPECIAL
                member["size"] = 0
                members.append(member)
                continue

            if info.type == tarfile.GNUTYPE_SPARSE or info.sparse:
                # 读取 tarfile 已还原空洞（补零）后的逻辑内容
                extents = validate_sparse(info.sparse, int(info.size), clean)
                member["type"] = T_FILE
                member["sparse"] = extents
                fp = tf.extractfile(info)
                if fp is None:
                    raise QuarantineError("sparse 成员无法读取", clean)
                member["sha256"] = _hash_stream(fp, int(info.size), budget_state)
                member["size"] = int(info.size)
                members.append(member)
                continue

            if info.isfile():
                member["type"] = T_FILE
                fp = tf.extractfile(info)
                if fp is None:
                    raise QuarantineError("普通成员无法读取", clean)
                member["sha256"] = _hash_stream(fp, int(info.size), budget_state)
                member["size"] = int(info.size)
                members.append(member)
                continue

            # 未知类型也记录为 special，避免悄悄吞掉成员
            member["type"] = T_SPECIAL
            members.append(member)
    except QuarantineError:
        raise
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise QuarantineError("读取 tar 成员时失败：%s" % exc)

    return {
        "family": "tar",
        "compression": _TAR_COMPRESSION.get(compression, compression),
        "members": members,
    }


def scan_archive(blob: bytes, budget: int = DEFAULT_BUDGET):
    """扫描归档字节，返回结果 dict。

    成功结果::

        {"quarantined": False, "family": ..., "compression": ...,
         "members": [...], "quarantine_reason": None, "safe_prefix": [...]}

    隔离结果结构相同，但 ``quarantined`` 为真，并带上原因与已安全扫描到的
    成员前缀。整个过程不向文件系统写出任何成员。
    """
    safe_prefix = []
    gzip_mtime = None
    family = compression = None
    try:
        family, compression = detect_format(blob)
        if family == "tar" and compression == "gzip" and len(blob) >= 8:
            # gzip 头部第 4..8 字节是小端 mtime（gzip -n 会置 0）
            gzip_mtime = struct.unpack("<I", blob[4:8])[0]
        if family == "zip":
            result = _scan_zip(blob, budget, safe_prefix)
        else:
            result = _scan_tar(blob, compression, budget, safe_prefix)
    except QuarantineError as exc:
        return {
            "quarantined": True,
            "family": family,
            "compression": (compression if family == "tar" else "zip") if family else None,
            "gzip_mtime": gzip_mtime,
            "members": safe_prefix,
            "quarantine_reason": exc.reason,
            "quarantine_path": exc.path,
            "safe_prefix": [m["path"] for m in safe_prefix],
        }

    # 成功路径下 safe_prefix 收集需要扫描器配合，这里简单返回全部
    result["quarantined"] = False
    result["quarantine_reason"] = None
    result["quarantine_path"] = None
    result["gzip_mtime"] = gzip_mtime
    result["safe_prefix"] = [m["path"] for m in result["members"]]
    return result
