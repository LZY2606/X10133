"""测试辅助：用 Python 标准库手工构造小归档，不依赖系统 tar 文本。"""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from datetime import datetime


def make_zip(files, mtime=1_000_000_000):
    """files: [(path, data_bytes, mode|None)]，按给定顺序写入。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for item in files:
            path, data = item[0], item[1]
            mode = item[2] if len(item) > 2 else None
            info = zipfile.ZipInfo(path)
            dt = datetime.utcfromtimestamp(mtime)
            info.date_time = (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)
            if mode is not None:
                info.external_attr = (mode & 0xFFFF) << 16
                info.create_version = 20
                info.create_system = 3
            zf.writestr(info, data)
    return buf.getvalue()


def add_tar_member(tf, path, kind="file", data=b"", mode=0o644,
                   mtime=1_000_000_000, uid=1000, gid=1000, link_target=None,
                   pax_headers=None, gnu_sparse=False):
    info = tarfile.TarInfo(path)
    info.mtime = mtime
    info.uid = uid
    info.gid = gid
    info.mode = mode
    info.uname = ""
    info.gname = ""
    if kind == "dir":
        info.type = tarfile.DIRTYPE
        tf.addfile(info)
    elif kind == "symlink":
        info.type = tarfile.SYMTYPE
        info.linkname = link_target or ""
        tf.addfile(info)
    elif kind == "hardlink":
        info.type = tarfile.LNKTYPE
        info.linkname = link_target or ""
        tf.addfile(info)
    elif kind == "pax-sparse":
        info.type = tarfile.REGTYPE
        info.size = len(data)
        info.pax_headers = pax_headers or {}
        tf.addfile(info, io.BytesIO(data))
    else:
        info.type = tarfile.REGTYPE
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))


def make_tar(members, compression="none", gzip_mtime=0):
    """members: 由 add_tar_member 使用的 kwargs 字典列表。"""
    buf = io.BytesIO()
    mode = {"none": "w", "gzip": "w:gz", "bzip2": "w:bz2", "xz": "w:xz"}[
        compression
    ]
    if compression == "gzip":
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as tf:
            for kwargs in members:
                add_tar_member(tf, **kwargs)
        compressed = gzip.compress(raw.getvalue(), mtime=gzip_mtime)
        return compressed
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for kwargs in members:
            add_tar_member(tf, **kwargs)
    return buf.getvalue()


def make_raw_tar(entries):
    """直接拼 512 字节 tar 头与数据块，用于注入畸形成员。"""
    blocks = []

    def header(name, size=0, mode=0o644, typeflag=b"0", linkname=""):
        name_b = name.encode()
        prefix = b""
        if len(name_b) > 100:
            idx = name_b.rfind(b"/", 0, 155 - 100)
            prefix = name_b[:idx]
            name_b = name_b[idx + 1:]
        link_b = linkname.encode()[:100].ljust(100, b"\x00")
        h = b""
        h += name_b[:100].ljust(100, b"\x00")
        h += ("%07o" % mode).encode() + b"\x00"
        h += b"0000000\x00"  # uid
        h += b"0000000\x00"  # gid
        h += ("%011o" % size).encode() + b"\x00"
        h += b"00000000000\x00"  # mtime
        h += b"        "  # checksum placeholder
        h += typeflag
        h += link_b
        h += b"ustar\x0000"
        h += b"".ljust(32, b"\x00")  # uname/gname
        h += b"".ljust(8, b"\x00")   # devmajor/devminor
        h += prefix[:155].ljust(155, b"\x00")
        h = h.ljust(512, b"\x00")
        chk = sum(h)
        chk_field = ("%06o\x00 " % chk).encode()
        h = h[:148] + chk_field + h[156:]
        return h

    for e in entries:
        data = e.get("data", b"")
        h = header(
            e["name"], size=len(data), mode=e.get("mode", 0o644),
            typeflag=e.get("typeflag", b"0"),
            linkname=e.get("linkname", ""),
        )
        blocks.append(h)
        blocks.append(data)
        pad = (-len(data)) % 512
        if pad:
            blocks.append(b"\x00" * pad)
    blocks.append(b"\x00" * 1024)
    return b"".join(blocks)
