"""字节稳定证明 + 隔离会话结论。"""

import json

from archive_builders import make_zip
from artifactproof.canonical import canonical_bytes
from artifactproof.diff import VERDICT_DIFFERS, VERDICT_QUARANTINED, VERDICT_REPRODUCIBLE
from artifactproof.proof import build_proof, proof_bytes
from artifactproof.service import Service
from artifactproof.storage import Storage


def _svc(tmp_path):
    return Service(Storage(str(tmp_path / "data")))


def test_proof_byte_stable_across_runs(tmp_path):
    svc = _svc(tmp_path)
    a = svc.storage.upload_blob("a.zip", make_zip([("f", b"same")]))
    b = svc.storage.upload_blob("b.zip", make_zip([("f", b"same")]))
    r1 = svc.compare(a["id"], b["id"], "default", 1)

    svc2 = _svc(tmp_path)
    # 用同一批持久化归档再比一次（新会话）
    a2 = svc2.storage.get_archive(a["id"])
    b2 = svc2.storage.get_archive(b["id"])
    r2 = svc2.compare(a2["id"], b2["id"], "default", 1)

    assert r1["proof_bytes"] == r2["proof_bytes"]
    assert r1["proof_sha256"] == r2["proof_sha256"]
    # 证明是合法 JSON 且字节以换行结尾
    assert r1["proof_bytes"].endswith("\n")
    parsed = json.loads(r1["proof_bytes"])
    assert parsed["kind"] == "artifactproof.proof/v1"
    assert parsed["result"]["verdict"] == VERDICT_REPRODUCIBLE


def test_proof_changes_when_content_changes(tmp_path):
    svc = _svc(tmp_path)
    a = svc.storage.upload_blob("a.zip", make_zip([("f", b"one")]))
    b = svc.storage.upload_blob("b.zip", make_zip([("f", b"two")]))
    r = svc.compare(a["id"], b["id"], "default", 1)
    parsed = json.loads(r["proof_bytes"])
    assert parsed["result"]["verdict"] == VERDICT_DIFFERS
    assert r["session"]["proof_sha256"] == r["proof_sha256"]


def test_canonical_json_key_order_invariant():
    d1 = {"b": 1, "a": {"z": 2, "y": 3}}
    d2 = {"a": {"y": 3, "z": 2}, "b": 1}
    assert canonical_bytes(d1) == canonical_bytes(d2)


def test_proof_excludes_wall_clock(tmp_path):
    # 同输入连续两次证明字节完全一致，证明里不应含 created_at
    svc = _svc(tmp_path)
    a = svc.storage.upload_blob("a.zip", make_zip([("f", b"x")]))
    b = svc.storage.upload_blob("b.zip", make_zip([("f", b"x")]))
    r1 = svc.compare(a["id"], b["id"], "default", 1)
    r2 = svc.compare(a["id"], b["id"], "default", 1)
    assert r1["proof_bytes"] == r2["proof_bytes"]
    assert b"created_at" not in r1["proof_bytes"].encode()


def test_quarantined_archive_gives_inconclusive(tmp_path):
    svc = _svc(tmp_path)
    good = svc.storage.upload_blob("good.zip", make_zip([("f", b"x")]))
    bad = svc.storage.upload_blob("bad.zip", make_zip([("ok", b"1"), ("../x", b"2")]))
    r = svc.compare(good["id"], bad["id"], "default", 1)
    sess = r["session"]
    assert sess["comparison"]["verdict"] == VERDICT_QUARANTINED
    assert "无法判定" in sess["comparison"]["verdict_text"]
    q = sess["comparison"]["quarantine"]
    assert q["b"]["quarantined"] is True
    assert q["b"]["safe_prefix"] == ["ok"]


def test_proof_endpoint_bytes_match(tmp_path):
    svc = _svc(tmp_path)
    a = svc.storage.upload_blob("a.zip", make_zip([("f", b"x")]))
    b = svc.storage.upload_blob("b.zip", make_zip([("f", b"y")]))
    r = svc.compare(a["id"], b["id"], "default", 1)
    # 从持久化会话重建的 canonical 字节与当时返回一致
    from artifactproof.canonical import canonical_bytes

    sess = svc.storage.get_session(r["session"]["id"])
    assert canonical_bytes(sess["proof"]).decode() == r["proof_bytes"]

