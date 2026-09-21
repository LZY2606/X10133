"""测试用小归档构造器（直接按格式手写/用标准库，不依赖系统 tar 文本）。"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import struct
import tarfile
import time
import zipfile


# ---------------- zip ----------------
def make_zip(entries, compression=zipfile.ZIP_STORED, fixed_mtime=(1980, 1, 1, 0, 0, 0)):
    """entries: [(path, data, {'mode':0o644,'is_symlink':False})]，按给定顺序写入。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as zf:
        for item in entries:
            path, data = item[0], item[1]
            opts = item[2] if len(item) > 2 else {}
            if path.endswith("/"):
                zi = zipfile.ZipInfo(path, fixed_mtime)
                zi.compress_type = compression
                zi.external_attr = (0o040755 << 16)
                zi.create_system = 3
                zf.writestr(zi, b"")
                continue
            zi = zipfile.ZipInfo(path, opts.get("mtime", fixed_mtime))
            zi.compress_type = opts.get("compression", compression)
            zi.create_system = 3
            if opts.get("is_symlink"):
                zi.external_attr = (0o120777 << 16)
                zf.writestr(zi, data)
            else:
                zi.external_attr = ((opts.get("mode", 0o644) & 0xFFFF) << 16)
                zf.writestr(zi, data)
    return buf.getvalue()


# ---------------- tar（标准库） ----------------
def make_tar(entries, mtime=1000, compression="none"):
    """entries: dict 列表。

    支持 type=file/dir/sym/hardlink，可覆盖 mode/uid/gid/mtime/name/data/link。
    压缩: none/gzip/bzip2/xz。
    """
    buf = io.BytesIO()
    write_mode = {"none": "w:", "gzip": "w:gz", "bzip2": "w:bz2", "xz": "w:xz"}
    mode = write_mode[compression]
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for e in entries:
            typ = e["type"]
            ti = tarfile.TarInfo(e["name"])
            ti.mtime = e.get("mtime", mtime)
            ti.uid = e.get("uid", 0)
            ti.gid = e.get("gid", 0)
            ti.mode = e.get("mode", 0o755 if typ == "dir" else 0o644)
            if typ == "file":
                data = e["data"]
                ti.type = tarfile.REGTYPE
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
            elif typ == "dir":
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            elif typ == "sym":
                ti.type = tarfile.SYMTYPE
                ti.linkname = e["link"]
                tf.addfile(ti)
            elif typ == "hardlink":
                ti.type = tarfile.LNKTYPE
                ti.linkname = e["link"]
                tf.addfile(ti)
    return buf.getvalue()


def _gzip_with_mtime(data, mtime_arg=0):
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=mtime_arg) as gz:
        gz.write(data)
    return out.getvalue()


def gzip_bytes(data, mtime=0):
    return _gzip_with_mtime(data, mtime)


def bzip2_bytes(data):
    return bz2.compress(data)


def xz_bytes(data):
    return lzma.compress(data)


# ---------------- 手写 GNU old sparse tar ----------------
def _octal(value, width):
    if value is None:
        return b"\x00" * width
    s = ("%0" + str(width - 1) + "o") % value
    return (s + "\x00").encode()


def _tar_header(name, size, mode, typeflag, linkname=b"", sparse=None, magic=b"ustar  \x00"):
    """构造一个 512 字节 tar 头。sparse: [(offset,numbytes)*<=4]。"""
    buf = bytearray(512)
    buf[0:100] = name.encode().ljust(100, b"\x00")
    buf[100:108] = _octal(mode, 8)
    buf[108:116] = _octal(0, 8)
    buf[116:124] = _octal(0, 8)
    buf[124:136] = _octal(size, 12)
    buf[136:148] = _octal(1000, 12)
    # checksum 先用空格
    buf[148:156] = b"        "
    buf[156:157] = typeflag
    buf[157:257] = linkname.ljust(100, b"\x00")
    buf[257:265] = magic
    if sparse:
        pos = 386
        structs = list(sparse)
        for i in range(4):
            if i < len(structs):
                off, num = structs[i]
                buf[pos : pos + 12] = _octal(off, 12)
                buf[pos + 12 : pos + 24] = _octal(num, 12)
            # 未使用的槽位保持全 NUL（tarfile 会忽略 0/0 之外的空槽）
            pos += 24
        # 482 是“是否还有扩展头”标志：NUL=无，'1'=有。
        buf[482:483] = b"\x00"
        # origsize 在 483:495
        buf[483:495] = _octal(size, 12)
    chksum = sum(buf)
    buf[148:156] = ("%06o\x00 " % chksum).encode()
    return bytes(buf)


def make_gnu_sparse_tar(name, logical_size, extents, stored_data, malformed=None):
    """构造 old GNU sparse（0.0，<=4 extents）单成员 tar。

    extents: [(offset, numbytes)...]，stored_data 为 extent 数据拼接。
    malformed: 可选 'overlap' / 'beyond' / 'zero-length'，用于制造 sparse 异常。
    """
    ext = list(extents)
    if malformed == "overlap" and len(ext) >= 2:
        o0, n0 = ext[0]
        ext[1] = (o0, n0)  # 与第一个 extent 完全重叠
    elif malformed == "beyond":
        ext[0] = (0, logical_size + 10)
    elif malformed == "zero-length":
        ext[1] = (ext[1][0], 0)

    header = _tar_header(
        name, logical_size, 0o644, tarfile.GNUTYPE_SPARSE, sparse=ext,
        magic=b"ustar  \x00",
    )
    body = stored_data
    pad = b"\x00" * ((512 - len(body) % 512) % 512)
    return header + body + pad + b"\x00" * 1024


def make_raw_tar_with_header(header, data=b""):
    pad = b"\x00" * ((512 - len(data) % 512) % 512)
    return header + data + pad + b"\x00" * 1024
