"""安全扫描与路径/隔离测试。"""

import io

import pytest
import tarfile
import zipfile

from archive_builders import (
    make_gnu_sparse_tar,
    make_tar,
    make_zip,
)
from artifactproof.scanner import QuarantineError, detect_format, normalize_member_path, scan_archive


def test_zip_basic_members_and_order():
    blob = make_zip(
        [
            ("dir/", b""),
            ("dir/a.txt", b"alpha"),
            ("dir/b.txt", b"bravo"),
        ]
    )
    r = scan_archive(blob)
    assert r["quarantined"] is False
    paths = [m["path"] for m in r["members"]]
    assert paths == ["dir", "dir/a.txt", "dir/b.txt"]
    orders = [m["order"] for m in r["members"]]
    assert orders == sorted(orders)
    f = next(m for m in r["members"] if m["path"] == "dir/a.txt")
    assert f["type"] == "file"
    assert f["mode"] == 0o644
    import hashlib

    assert f["sha256"] == hashlib.sha256(b"alpha").hexdigest()


def test_tar_hardlink_resolves_and_symlink_not_followed():
    blob = make_tar(
        [
            {"type": "file", "name": "a.txt", "data": b"hello", "mode": 0o644},
            {"type": "hardlink", "name": "h", "link": "a.txt"},
            {"type": "sym", "name": "s", "link": "a.txt"},
        ]
    )
    r = scan_archive(blob)
    assert r["quarantined"] is False
    by = {m["path"]: m for m in r["members"]}
    assert by["h"]["type"] == "hardlink"
    assert by["h"]["link_target"] == "a.txt"
    assert by["h"]["sha256"] is None  # 扫描层不解析硬链接内容
    assert by["s"]["type"] == "symlink"
    assert by["s"]["link_target"] == "a.txt"


@pytest.mark.parametrize(
    "raw",
    ["/abs/path", "../up", "foo/../../bar", "C:/windows", "a/../b"],
)
def test_dangerous_paths_quarantine(raw):
    blob = make_zip([(raw, b"x")])
    r = scan_archive(blob)
    assert r["quarantined"] is True
    assert r["quarantine_reason"]


def test_normalize_member_path_units():
    assert normalize_member_path("a/b/") == ("a/b", True)
    assert normalize_member_path(".//a/./b") == ("a/b", False)
    with pytest.raises(QuarantineError):
        normalize_member_path("../x")
    with pytest.raises(QuarantineError):
        normalize_member_path("/x")


def test_duplicate_path_quarantine_with_prefix():
    blob = make_zip(
        [
            ("good1", b"1"),
            ("good2", b"2"),
            ("dup", b"3"),
            ("dup", b"4"),
        ]
    )
    r = scan_archive(blob)
    assert r["quarantined"] is True
    assert "重复" in r["quarantine_reason"]
    assert r["safe_prefix"] == ["good1", "good2", "dup"]
    # 成员列表保留安全前缀
    assert [m["path"] for m in r["members"]] == ["good1", "good2", "dup"]


def test_tar_duplicate_path_quarantine():
    blob = make_tar(
        [
            {"type": "file", "name": "x", "data": b"1"},
            {"type": "file", "name": "x", "data": b"2"},
        ]
    )
    r = scan_archive(blob)
    assert r["quarantined"] is True
    assert r["safe_prefix"] == ["x"]


@pytest.mark.parametrize("target", ["../escape", "/abs/target", "../../x"])
def test_symlink_escape_quarantine_zip(target):
    blob = make_zip([("lnk", target.encode(), {"is_symlink": True})])
    r = scan_archive(blob)
    assert r["quarantined"] is True
    assert "链接逃逸" in r["quarantine_reason"]


@pytest.mark.parametrize("target", ["../escape", "/abs/target"])
def test_symlink_escape_quarantine_tar(target):
    blob = make_tar([{"type": "sym", "name": "lnk", "link": target}])
    r = scan_archive(blob)
    assert r["quarantined"] is True


def test_hardlink_escape_quarantine():
    blob = make_tar(
        [
            {"type": "file", "name": "a", "data": b"x"},
            {"type": "hardlink", "name": "h", "link": "../a"},
        ]
    )
    r = scan_archive(blob)
    assert r["quarantined"] is True
    assert "链接逃逸" in r["quarantine_reason"]


def test_zip_bomb_budget_quarantine():
    # 压缩炸弹：高度可压缩的大文件
    big = b"0" * (50 * 1024)
    blob = make_zip([("bomb", big)], compression=zipfile.ZIP_DEFLATED)
    assert len(blob) < len(big)  # deflate 后明显更小
    r = scan_archive(blob, budget=1024)
    assert r["quarantined"] is True
    assert "超限" in r["quarantine_reason"]


def test_tar_bomb_budget_quarantine():
    big = b"1" * (40 * 1024)
    blob = make_tar([{"type": "file", "name": "big", "data": big}])
    r = scan_archive(blob, budget=1024)
    assert r["quarantined"] is True
    assert "超限" in r["quarantine_reason"]


def test_sparse_valid_logical_hash_and_extents():
    import hashlib

    stored = b"A" * 4 + b"B" * 4
    blob = make_gnu_sparse_tar("sp", 16, [(0, 4), (8, 4)], stored)
    r = scan_archive(blob, budget=4096)
    assert r["quarantined"] is False
    m = r["members"][0]
    assert m["sparse"] == [[0, 4], [8, 4]]
    assert m["size"] == 16
    logical = b"A" * 4 + b"\x00" * 4 + b"B" * 4 + b"\x00" * 4
    assert m["sha256"] == hashlib.sha256(logical).hexdigest()


@pytest.mark.parametrize("mal", ["overlap", "beyond", "zero-length"])
def test_sparse_anomalies_quarantine(mal):
    stored = b"A" * 4 + b"B" * 4
    blob = make_gnu_sparse_tar("sp", 16, [(0, 4), (8, 4)], stored, malformed=mal)
    r = scan_archive(blob, budget=4096)
    assert r["quarantined"] is True
    assert "sparse" in r["quarantine_reason"]


@pytest.mark.parametrize(
    "compression,magic",
    [
        ("gzip", b"\x1f\x8b"),
        ("bzip2", b"BZh"),
        ("xz", b"\xfd7zXZ\x00"),
    ],
)
def test_tar_formats_detected(compression, magic):
    blob = make_tar([{"type": "file", "name": "f", "data": b"hi"}], compression=compression)
    assert blob[: len(magic)] == magic
    r = scan_archive(blob)
    assert r["quarantined"] is False
    assert r["family"] == "tar"
    assert r["compression"] == compression


def test_garbage_quarantine():
    r = scan_archive(b"this is not an archive at all" * 10)
    assert r["quarantined"] is True
    assert "无法识别" in r["quarantine_reason"]


def test_no_extraction_leaves_no_files(tmp_path, monkeypatch):
    # 扫描绝不应该在文件系统创建成员文件
    blob = make_zip([("evil_name.txt", b"data"), ("d/x", b"y")])
    before = set(_walk(tmp_path))
    monkeypatch.chdir(tmp_path)
    scan_archive(blob)
    after = set(_walk(tmp_path))
    assert before == after


def _walk(root):
    import os

    for dp, _, files in os.walk(root):
        for f in files:
            yield os.path.join(dp, f)
