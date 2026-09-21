"""blob 去重、引用保护、持久化重启、策略版本化、硬链接清单解析。"""

import json

import pytest

from archive_builders import make_tar, make_zip
from artifactproof.policy import normalize_policy
from artifactproof.service import Service
from artifactproof.storage import Storage


def make_store(tmp_path, budget=10 * 1024 * 1024):
    return Storage(str(tmp_path / "data"), budget=budget)


def test_identical_bytes_reuse_blob(tmp_path):
    st = make_store(tmp_path)
    blob = make_zip([("a", b"hello")])
    r1 = st.upload_blob("one.zip", blob)
    r2 = st.upload_blob("two.zip", blob)
    assert r1["blob_sha256"] == r2["blob_sha256"]
    assert r1["blob_reused"] is False
    assert r2["blob_reused"] is True
    assert r1["id"] != r2["id"]


def test_blob_delete_blocked_while_referenced(tmp_path):
    st = make_store(tmp_path)
    r = st.upload_blob("a.zip", make_zip([("a", b"x")]))
    digest = r["blob_sha256"]
    assert st.delete_blob_allowed(digest) is False
    with pytest.raises(RuntimeError):
        st.delete_blob(digest)


def test_blob_delete_allowed_after_archive_removed(tmp_path):
    st = make_store(tmp_path)
    r = st.upload_blob("a.zip", make_zip([("a", b"x")]))
    digest = r["blob_sha256"]
    st.delete_archive(r["id"])
    assert st.delete_blob_allowed(digest) is True
    st.delete_blob(digest)


def test_archive_delete_blocked_by_session(tmp_path):
    st = make_store(tmp_path)
    svc = Service(st)
    a = st.upload_blob("a.zip", make_zip([("f", b"1")]))
    b = st.upload_blob("b.zip", make_zip([("f", b"1")]))
    svc.compare(a["id"], b["id"], "default", 1)
    with pytest.raises(RuntimeError):
        st.delete_archive(a["id"])
    # 删除会话后才能删除归档
    sess = st.list_sessions()[0]
    st.delete_session(sess["id"])
    st.delete_archive(a["id"])


def test_persistence_across_restart(tmp_path):
    root = str(tmp_path / "data")
    st = Storage(root)
    a = st.upload_blob("a.zip", make_zip([("f", b"1")]))
    b = st.upload_blob("b.zip", make_zip([("f", b"2")]))
    st.create_policy("strict", normalize_policy({"name": "strict", "ignore_mtime": False}))
    Service(st).compare(a["id"], b["id"], "strict", 1)

    # “重启”：重新实例化存储
    st2 = Storage(root)
    assert len(st2.list_archives()) == 2
    pol = st2.get_policy("strict")
    assert pol is not None and pol["versions"][0]["version"] == 1
    assert len(st2.list_sessions()) == 1
    # 上传与清单仍可查
    assert st2.get_archive(a["id"])["manifest"]["members"][0]["path"] == "f"


def test_policy_versioning_immutable_history(tmp_path):
    st = make_store(tmp_path)
    st.create_policy("p", normalize_policy({"name": "p", "ignore_mtime": True}))
    _, v2 = st.add_policy_version("p", normalize_policy({"name": "p", "ignore_mtime": False}))
    assert v2["version"] == 2
    rec = st.get_policy("p")
    assert len(rec["versions"]) == 2
    # v1 内容保持不变
    assert rec["versions"][0]["body"]["ignore_mtime"] is True
    # 相同策略体幂等复用，不新增版本
    _, v3 = st.add_policy_version("p", normalize_policy({"name": "p", "ignore_mtime": False}))
    assert v3["version"] == 2
    assert len(st.get_policy("p")["versions"]) == 2


def test_hardlink_manifest_resolves_content_hash(tmp_path):
    st = make_store(tmp_path)
    blob = make_tar(
        [
            {"type": "file", "name": "orig", "data": b"shared-bytes"},
            {"type": "hardlink", "name": "link", "link": "orig"},
        ]
    )
    rec = st.upload_blob("h.tar", blob)
    members = {m["path"]: m for m in rec["manifest"]["members"]}
    import hashlib

    expected = hashlib.sha256(b"shared-bytes").hexdigest()
    assert members["orig"]["sha256"] == expected
    assert members["link"]["sha256"] == expected
    assert members["link"]["hardlink_resolved"] is True


def test_dangling_hardlink_marked_unresolved(tmp_path):
    st = make_store(tmp_path)
    blob = make_tar([{"type": "hardlink", "name": "link", "link": "missing"}])
    rec = st.upload_blob("d.tar", blob)
    m = rec["manifest"]["members"][0]
    assert m["sha256"] is None
    assert m["hardlink_resolved"] is False


def test_sessions_independent_even_for_same_blobs(tmp_path):
    st = make_store(tmp_path)
    svc = Service(st)
    blob = make_zip([("f", b"1")])
    a = st.upload_blob("a.zip", blob)
    b = st.upload_blob("b.zip", blob)
    r1 = svc.compare(a["id"], b["id"], "default", 1)
    r2 = svc.compare(a["id"], b["id"], "default", 1)
    assert r1["session"]["id"] != r2["session"]["id"]
    assert len(st.list_sessions()) == 2


def test_quarantine_record_persisted_with_prefix(tmp_path):
    st = make_store(tmp_path)
    blob = make_zip([("ok", b"1"), ("../bad", b"2")])
    rec = st.upload_blob("evil.zip", blob)
    man = rec["manifest"]
    assert man["quarantined"] is True
    assert man["safe_prefix"] == ["ok"]
    assert "上跳" in man["quarantine_reason"]
    # 重启后仍可见
    st2 = Storage(str(tmp_path / "data"))
    man2 = st2.get_archive(rec["id"])["manifest"]
    assert man2["quarantined"] is True
    assert man2["safe_prefix"] == ["ok"]

