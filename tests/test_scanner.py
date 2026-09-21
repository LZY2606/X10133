"""安全扫描器测试：顺序、类型、隔离场景，全部离线。"""

from __future__ import annotations

import io
import os
import zipfile

from artifactproof.scanner import scan_archive

from helpers import make_zip, make_tar, make_raw_tar  # noqa: E402


def write_blob(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def entries_by_path(manifest):
    return {e.path: e for e in manifest.entries}


def test_basic_zip_manifest_fields(tmp_path):
    data = make_zip([("a/b.txt", b"hello", 0o644)])
    path = write_blob(tmp_path, "a.zip", data)
    manifest = scan_archive(path)
    assert manifest.format == "zip"
    assert not manifest.quarantined
    entry = manifest.entries[0]
    assert entry.order == 0
    assert entry.path == "a/b.txt"
    assert entry.type == "file"
    assert entry.mode == "0644"
    assert entry.size == 5
    assert entry.content_hash == "sha256:" + __import__("hashlib").sha256(b"hello").hexdigest()


def test_member_order_preserved(tmp_path):
    data = make_zip([
        ("z.txt", b"1", 0o644),
        ("a.txt", b"2", 0o644),
        ("m.txt", b"3", 0o644),
    ])
    manifest = scan_archive(write_blob(tmp_path, "o.zip", data))
    assert [e.path for e in manifest.entries] == ["z.txt", "a.txt", "m.txt"]
    assert [e.order for e in manifest.entries] == [0, 1, 2]


def test_mtime_recorded(tmp_path):
    data = make_zip([("a", b"x", 0o644)], mtime=1_234_567_890)
    manifest = scan_archive(write_blob(tmp_path, "t.zip", data))
    assert manifest.entries[0].mtime == 1_234_567_890


def test_modes_recorded_tar(tmp_path):
    data = make_tar([
        {"path": "exec.sh", "kind": "file", "data": b"#!/bin/sh\n", "mode": 0o755},
        {"path": "plain", "kind": "file", "data": b"x", "mode": 0o600},
        {"path": "d", "kind": "dir", "mode": 0o750},
    ])
    manifest = scan_archive(write_blob(tmp_path, "m.tar", data))
    by = entries_by_path(manifest)
    assert by["exec.sh"].mode == "0755"
    assert by["plain"].mode == "0600"
    assert by["d"].type == "dir"
    assert by["d"].mode == "0750"


def test_uid_gid_recorded(tmp_path):
    data = make_tar([
        {"path": "f", "data": b"1", "uid": 42, "gid": 7},
    ])
    manifest = scan_archive(write_blob(tmp_path, "u.tar", data))
    assert manifest.entries[0].uid == 42
    assert manifest.entries[0].gid == 7


def test_symlink_not_followed_and_recorded(tmp_path):
    data = make_tar([
        {"path": "real", "data": b"payload", "mode": 0o644},
        {"path": "link", "kind": "symlink", "link_target": "real", "mode": 0o777},
    ])
    manifest = scan_archive(write_blob(tmp_path, "s.tar", data))
    by = entries_by_path(manifest)
    assert by["link"].type == "symlink"
    assert by["link"].link_target == "real"
    assert by["link"].content_hash is None
    assert by["real"].content_hash.startswith("sha256:")


def test_symlink_escape_quarantine(tmp_path):
    data = make_tar([
        {"path": "evil", "kind": "symlink", "link_target": "../../etc/passwd"},
        {"path": "safe", "data": b"x"},
    ])
    manifest = scan_archive(write_blob(tmp_path, "e.tar", data))
    assert manifest.quarantined
    assert manifest.quarantine["code"] == "link_escape"
    # 只有链接之前（此处为空）安全前缀；链接本身不入列
    assert [e.path for e in manifest.entries] == []


def test_symlink_chain_escape_quarantine(tmp_path):
    # a -> inside, inside -> ../../../x：词法解析多跳链接时逃逸
    data = make_tar([
        {"path": "d/a", "kind": "symlink", "link_target": "../inside"},
        {"path": "inside", "kind": "symlink", "link_target": "../secret"},
    ])
    manifest = scan_archive(write_blob(tmp_path, "ce.tar", data))
    assert manifest.quarantined
    assert manifest.quarantine["code"] == "link_escape"


def test_symlink_loop_quarantine(tmp_path):
    data = make_tar([
        {"path": "x", "kind": "symlink", "link_target": "y"},
        {"path": "y", "kind": "symlink", "link_target": "x"},
    ])
    manifest = scan_archive(write_blob(tmp_path, "loop.tar", data))
    assert manifest.quarantined
    assert manifest.quarantine["code"] == "link_loop"


def test_hardlink_inherits_content_hash(tmp_path):
    data = make_tar([
        {"path": "orig", "data": b"same bytes", "mode": 0o644},
        {"path": "hl", "kind": "hardlink", "link_target": "orig", "mode": 0o644},
    ])
    manifest = scan_archive(write_blob(tmp_path, "hl.tar", data))
    by = entries_by_path(manifest)
    assert by["hl"].type == "hardlink"
    assert by["hl"].content_hash == by["orig"].content_hash


def test_hardlink_forward_target_quarantine(tmp_path):
    data = make_tar([
        {"path": "hl", "kind": "hardlink", "link_target": "ghost"},
    ])
    manifest = scan_archive(write_blob(tmp_path, "ghost.tar", data))
    assert manifest.quarantined
    assert manifest.quarantine["code"] == "hardlink_dangling"


def test_duplicate_path_quarantine_with_prefix(tmp_path):
    # zip 允许重复条目
    buf = io.BytesIO()
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("first", b"1")
            zf.writestr("dup", b"2")
            zf.writestr("dup", b"3")
    manifest = scan_archive(write_blob(tmp_path, "d.zip", buf.getvalue()))
    assert manifest.quarantined
    assert manifest.quarantine["code"] == "duplicate_path"
    assert [e.path for e in manifest.entries] == ["first", "dup"]
    assert manifest.quarantine["prefix_length"] == 2


def test_absolute_path_quarantine(tmp_path):
    data = make_raw_tar([{"name": "/etc/evil", "data": b"x"}])
    manifest = scan_archive(write_blob(tmp_path, "abs.tar", data))
    assert manifest.quarantined
    assert manifest.quarantine["code"] == "absolute_path"


def test_traversal_path_quarantine(tmp_path):
    data = make_raw_tar([{"name": "../escape", "data": b"x"}])
    manifest = scan_archive(write_blob(tmp_path, "up.tar", data))
    assert manifest.quarantined
    assert manifest.quarantine["code"] == "path_traversal"


def test_nested_traversal_path_quarantine(tmp_path):
    data = make_raw_tar([{"name": "a/../../escape", "data": b"x"}])
    manifest = scan_archive(write_blob(tmp_path, "nup.tar", data))
    assert manifest.quarantined
    assert manifest.quarantine["code"] == "path_traversal"


def test_zip_bomb_budget_quarantine(tmp_path):
    # 高压缩比的全零数据；给一个很小的预算即超限
    big = b"\x00" * (2 * 1024 * 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb", big)
    path = write_blob(tmp_path, "b.zip", buf.getvalue())
    manifest = scan_archive(path, budget=1024)
    assert manifest.quarantined
    assert manifest.quarantine["code"] == "bomb_budget_exceeded"


def test_declared_oversize_sparse_member_quarantine(tmp_path):
    # 用 pax 稀疏声明超大 realsize 来测声明预算
    sparse = make_tar([
        {"path": "sp", "kind": "pax-sparse", "data": b"x",
         "pax_headers": {
             "GNU.sparse.major": "1", "GNU.sparse.minor": "0",
             "GNU.sparse.realsize": str(10 * 1024 * 1024),
             "GNU.sparse.map": "0,1",
         }},
    ])
    manifest = scan_archive(write_blob(tmp_path, "sp.tar", sparse), budget=4096)
    assert manifest.quarantined
    assert manifest.quarantine["code"] == "bomb_budget_exceeded"


def test_sparse_overlap_quarantine(tmp_path):
    sparse = make_tar([
        {"path": "sp", "kind": "pax-sparse", "data": b"0123456789",
         "pax_headers": {
             "GNU.sparse.realsize": "100",
             "GNU.sparse.map": "0,10,5,10",
         }},
    ])
    manifest = scan_archive(write_blob(tmp_path, "ov.tar", sparse))
    assert manifest.quarantined
    assert manifest.quarantine["code"] == "sparse_anomaly"


def test_valid_sparse_member_ok(tmp_path):
    sparse = make_tar([
        {"path": "sp", "kind": "pax-sparse", "data": b"abc",
         "pax_headers": {
             "GNU.sparse.realsize": "100",
             "GNU.sparse.map": "0,3",
         }},
    ])
    manifest = scan_archive(write_blob(tmp_path, "ok.tar", sparse))
    assert not manifest.quarantined
    entry = manifest.entries[0]
    assert entry.size == 100
    assert entry.content_hash == "sha256:" + __import__("hashlib").sha256(b"abc" + b"\x00" * 97).hexdigest()


def test_gzip_compression_params_captured(tmp_path):
    data = make_tar(
        [{"path": "f", "data": b"x"}],
        compression="gzip", gzip_mtime=1_700_000_000,
    )
    manifest = scan_archive(write_blob(tmp_path, "a.tar.gz", data))
    assert manifest.compression == "gzip"
    assert manifest.compression_params["mtime"] == 1_700_000_000


def test_unknown_format_quarantine(tmp_path):
    path = write_blob(tmp_path, "x.bin", b"definitely not an archive")
    manifest = scan_archive(path)
    assert manifest.quarantined
    assert manifest.quarantine["code"] == "unknown_format"


def test_corrupt_gzip_quarantine(tmp_path):
    path = write_blob(tmp_path, "c.tar.gz", b"\x1f\x8b\x08garbagegarbage")
    manifest = scan_archive(path)
    assert manifest.quarantined
    assert manifest.quarantine["code"] == "malformed_archive"


def test_no_files_left_in_workdir(tmp_path):
    data = make_tar([{"path": "f", "data": b"payload"}])
    path = write_blob(tmp_path, "a.tar", data)
    start = set(os.listdir(tmp_path))
    scan_archive(path)
    # 扫描不允许产生任何额外文件/目录（绝不向工作目录解包）
    assert set(os.listdir(tmp_path)) == start


def test_zip_symlink_escape_quarantine(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("evil")
        info.external_attr = 0o120777 << 16
        info.create_system = 3
        zf.writestr(info, "../../escape")
    manifest = scan_archive(write_blob(tmp_path, "zs.zip", buf.getvalue()))
    assert manifest.quarantine
    assert manifest.quarantine["code"] == "link_escape"


def test_xz_and_bzip2_params(tmp_path):
    xz_data = make_tar([{"path": "f", "data": b"x"}], compression="xz")
    manifest = scan_archive(write_blob(tmp_path, "a.tar.xz", xz_data))
    assert manifest.compression == "xz"
    assert manifest.compression_params.get("stream_flags") == "xz-stream-v1"

    bz_data = make_tar([{"path": "f", "data": b"x"}], compression="bzip2")
    manifest_b = scan_archive(write_blob(tmp_path, "a.tar.bz2", bz_data))
    assert manifest_b.compression == "bzip2"


def test_traversal_prefix_is_viewable(tmp_path):
    data = make_tar([
        {"path": "safe1", "data": b"1"},
        {"path": "d/safe2", "data": b"2"},
        {"path": "../escape", "data": b"3"},
        {"path": "never", "data": b"4"},
    ])
    manifest = scan_archive(write_blob(tmp_path, "p.tar", data))
    assert manifest.quarantine["code"] == "path_traversal"
    assert [e.path for e in manifest.entries] == ["safe1", "d/safe2"]
    assert manifest.quarantine["prefix_length"] == 2
