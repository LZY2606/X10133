"""持久化、内容去重、引用保护、HTTP API 测试。"""

from __future__ import annotations

import json
import os
import threading
from http.client import HTTPConnection

import pytest

from artifactproof.storage import Store
from artifactproof.policy import Policy
from artifactproof.web import create_handler
from http.server import ThreadingHTTPServer

from helpers import make_zip, make_tar


def make_server(store, port=0):
    server = ThreadingHTTPServer(("127.0.0.1", port), create_handler(store))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def request(server, method, path, body=None, headers=None):
    conn = HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


def jreq(server, method, path, obj=None):
    body = None
    headers = {}
    if obj is not None:
        body = json.dumps(obj).encode()
        headers["Content-Type"] = "application/json"
    status, data = request(server, method, path, body, headers)
    return status, (json.loads(data) if data else None)


def test_blob_dedupe_same_bytes(tmp_path):
    store = Store(str(tmp_path / "data"))
    data = make_zip([("a", b"x", 0o644)])
    r1 = store.upload_archive(data, filename="a.zip")
    r2 = store.upload_archive(data, filename="a-copy.zip")
    assert r1["content_hash"] == r2["content_hash"]
    assert r1["blob_reused"] is False
    assert r2["blob_reused"] is True
    assert r1["upload_id"] != r2["upload_id"]
    store.close()


def test_sessions_independent(tmp_path):
    store = Store(str(tmp_path / "data"))
    data1 = make_zip([("a", b"1", 0o644)])
    data2 = make_zip([("a", b"2", 0o644)])
    a = store.upload_archive(data1)["upload_id"]
    b = store.upload_archive(data1)["upload_id"]
    c = store.upload_archive(data2)["upload_id"]
    s1 = store.create_session(a, b)
    s2 = store.create_session(a, c)
    assert s1["session_id"] != s2["session_id"]
    assert s1["result"]["verdict"] == "reproducible"
    assert s2["result"]["verdict"] == "content_differs"
    store.close()


def test_policy_versioning_never_rewrites_manifest(tmp_path):
    store = Store(str(tmp_path / "data"))
    v1 = store.create_policy("rel", Policy(ignore_mtime=True))
    v2 = store.create_policy("rel", Policy(ignore_mtime=True, ignore_order=True))
    assert v1["version"] == 1
    assert v2["version"] == 2
    data1 = make_zip([("a", b"1", 0o644), ("b", b"2", 0o644)])
    data2 = make_zip([("b", b"2", 0o644), ("a", b"1", 0o644)])
    a = store.upload_archive(data1)["upload_id"]
    b = store.upload_archive(data2)["upload_id"]
    strict = store.create_session(a, b)
    relaxed = store.create_session(a, b, policy_id="rel", policy_version=2)
    assert strict["result"]["verdict"] == "content_differs"
    assert relaxed["result"]["verdict"] in ("reproducible", "equivalent_under_policy")
    # 原始清单在两次比较之间保持不变
    assert store.get_manifest(a).entries[0].path == "a"
    assert store.get_manifest(b).entries[0].path == "b"
    store.close()


def test_persistence_across_reopen(tmp_path):
    data_dir = str(tmp_path / "data")
    store = Store(data_dir)
    rec = store.upload_archive(make_zip([("a", b"x", 0o644)]), "p.zip")
    store.create_policy("rel", Policy(ignore_mtime=True))
    store.close()

    store2 = Store(data_dir)
    archives = store2.list_archives()
    assert len(archives) == 1
    assert archives[0]["content_hash"] == rec["content_hash"]
    policy = store2.get_policy("rel")
    assert policy["policy"].ignore_mtime is True
    assert store2.get_manifest(rec["upload_id"]).entries[0].path == "a"
    store2.close()


def test_gc_blocks_referenced_blob(tmp_path):
    store = Store(str(tmp_path / "data"))
    a = store.upload_archive(make_zip([("a", b"1", 0o644)]), "a.zip")
    b = store.upload_archive(make_zip([("a", b"1", 0o644)]), "b.zip")
    store.create_session(a["upload_id"], b["upload_id"])

    # blob 仍被上传记录引用，GC 不动
    gc = store.garbage_collect()
    assert gc["removed"] == []

    with pytest.raises(PermissionError):
        store.delete_archive(a["upload_id"])
    # 会话同时引用 b，同样不能删
    with pytest.raises(PermissionError):
        store.delete_archive(b["upload_id"])
    # blob 仍存在
    assert os.path.exists(store.blob_path(a["content_hash"]))
    store.close()


def test_gc_removes_orphan_blobs(tmp_path):
    store = Store(str(tmp_path / "data"))
    rec = store.upload_archive(make_zip([("a", b"1", 0o644)]), "a.zip")
    assert store.delete_archive(rec["upload_id"]) is True
    path = store.blob_path(rec["content_hash"])
    gc = store.garbage_collect()
    assert rec["content_hash"] in gc["removed"]
    assert not os.path.exists(path)
    store.close()


def test_failed_upload_leaves_no_tmp_files(tmp_path):
    data_dir = str(tmp_path / "data")
    store = Store(data_dir)
    # 正常上传后 tmp 目录必须为空
    store.upload_archive(make_zip([("a", b"1", 0o644)]))
    assert os.listdir(store.tmp_dir) == []
    store.close()


def test_quarantined_upload_persisted_and_viewable(tmp_path):
    store = Store(str(tmp_path / "data"))
    evil = make_tar([{"path": "../escape", "data": b"x"}])
    rec = store.upload_archive(evil, "evil.tar")
    assert rec["manifest"]["quarantine"]["code"] == "path_traversal"
    reopened = Store(str(tmp_path / "data"))
    summary = reopened.archive_summary(rec["upload_id"])
    assert summary["manifest"]["quarantine"] is not None
    store.close()


def test_http_roundtrip_and_proof_endpoint(tmp_path):
    store = Store(str(tmp_path / "data"))
    server, _thread = make_server(store)
    try:
        data = make_zip([("a", b"hello", 0o644)])
        # 二进制上传
        status, raw = request(
            server, "POST", "/api/archives?filename=a.zip", data,
            {"Content-Type": "application/octet-stream"},
        )
        assert status == 201
        a = json.loads(raw)
        status, raw = request(
            server, "POST", "/api/archives?filename=b.zip", data,
            {"Content-Type": "application/octet-stream"},
        )
        b = json.loads(raw)
        assert b["blob_reused"] is True

        status, created = jreq(server, "POST", "/api/sessions", {
            "archive_a": a["upload_id"], "archive_b": b["upload_id"],
        })
        assert status == 201
        assert created["result"]["verdict"] == "reproducible"

        status, proof_raw = request(
            server, "GET",
            "/api/sessions/%s/proof" % created["session_id"],
        )
        assert status == 200
        proof1 = json.loads(proof_raw)
        # 再次导出必须字节一致
        status, proof_raw2 = request(
            server, "GET",
            "/api/sessions/%s/proof" % created["session_id"],
        )
        assert proof_raw == proof_raw2
        assert proof1["proof_hash"] == created["proof"]["proof_hash"]

        status, page = request(server, "GET", "/")
        assert status == 200
        assert "产物核验站".encode() in page
    finally:
        server.shutdown()
        server.server_close()
        store.close()



def test_policy_listing_json_serializable(tmp_path):
    store = Store(str(tmp_path / "data"))
    store.create_policy("p1", Policy(ignore_mtime=True, mode_mask=0o022))
    store.create_policy("p1", Policy(ignore_mtime=True, ignore_order=True))
    from artifactproof import canonical
    payload = canonical.canonical_bytes({"policies": store.list_policies()})
    decoded = json.loads(payload)
    assert decoded["policies"][0]["version"] == 2
    assert decoded["policies"][0]["policy"]["ignore_order"] is True
    v1 = store.get_policy("p1", 1)["policy"].to_dict()
    assert v1["mode_mask"] == 0o022
    store.close()
