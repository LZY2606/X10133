"""比较引擎与策略测试。"""

from __future__ import annotations

from artifactproof.scanner import scan_archive
from artifactproof.policy import Policy
from artifactproof.compare import (
    compare_manifests,
    build_proof,
    VERDICT_REPRODUCIBLE,
    VERDICT_EQUIVALENT,
    VERDICT_DIFFERENT,
    VERDICT_QUARANTINED,
)
from artifactproof import canonical
from helpers import make_zip, make_tar


def scan_bytes(tmp_path, name, data, budget=None):
    path = tmp_path / name
    path.write_bytes(data)
    kwargs = {} if budget is None else {"budget": budget}
    return scan_archive(str(path), **kwargs)


def test_identical_archives_reproducible(tmp_path):
    data = make_zip([("a", b"hello", 0o644)])
    ma = scan_bytes(tmp_path, "a.zip", data)
    mb = scan_bytes(tmp_path, "b.zip", data)
    result = compare_manifests(ma, mb, Policy())
    assert result["verdict"] == VERDICT_REPRODUCIBLE


def test_content_hash_is_real_difference(tmp_path):
    ma = scan_bytes(tmp_path, "a.zip", make_zip([("a", b"hello", 0o644)]))
    mb = scan_bytes(tmp_path, "b.zip", make_zip([("a", b"HELLO", 0o644)]))
    result = compare_manifests(ma, mb, Policy(ignore_mtime=True,
                                              ignore_uidgid=True,
                                              mode_mask=0o7777,
                                              ignore_order=True,
                                              ignore_compression_params=True))
    assert result["verdict"] == VERDICT_DIFFERENT
    fields = [d["field"] for md in result["member_diffs"] for d in md["real"]]
    assert "content_hash" in fields


def test_member_only_on_one_side_is_real(tmp_path):
    ma = scan_bytes(tmp_path, "a.zip", make_zip([("a", b"1", 0o644), ("b", b"2", 0o644)]))
    mb = scan_bytes(tmp_path, "b.zip", make_zip([("a", b"1", 0o644)]))
    result = compare_manifests(ma, mb, Policy())
    assert result["verdict"] == VERDICT_DIFFERENT
    assert result["only_in_a"] == ["b"]


def test_order_ignorable_under_policy(tmp_path):
    ma = scan_bytes(tmp_path, "a.zip",
                    make_zip([("a", b"1", 0o644), ("b", b"2", 0o644)]))
    mb = scan_bytes(tmp_path, "b.zip",
                    make_zip([("b", b"2", 0o644), ("a", b"1", 0o644)]))
    strict = compare_manifests(ma, mb, Policy())
    assert strict["verdict"] == VERDICT_DIFFERENT
    order_fields = [d for md in strict["member_diffs"]
                    for d in md["real"] if d["field"] == "order"]
    assert order_fields

    relaxed = compare_manifests(ma, mb, Policy(ignore_order=True))
    assert relaxed["verdict"] == VERDICT_EQUIVALENT


def test_mtime_ignorable_under_policy(tmp_path):
    ma = scan_bytes(tmp_path, "a.zip",
                    make_zip([("a", b"1", 0o644)], mtime=1_000_000_000))
    mb = scan_bytes(tmp_path, "b.zip",
                    make_zip([("a", b"1", 0o644)], mtime=2_000_000_000))
    strict = compare_manifests(ma, mb, Policy())
    assert strict["verdict"] == VERDICT_DIFFERENT
    relaxed = compare_manifests(ma, mb, Policy(ignore_mtime=True))
    assert relaxed["verdict"] == VERDICT_EQUIVALENT


def test_mode_mask(tmp_path):
    ma = scan_bytes(tmp_path, "a.tar",
                    make_tar([{"path": "f", "data": b"1", "mode": 0o755}]))
    mb = scan_bytes(tmp_path, "b.tar",
                    make_tar([{"path": "f", "data": b"1", "mode": 0o700}]))
    strict = compare_manifests(ma, mb, Policy())
    assert strict["verdict"] == VERDICT_DIFFERENT
    relaxed = compare_manifests(ma, mb, Policy(mode_mask=0o055))
    assert relaxed["verdict"] == VERDICT_REPRODUCIBLE


def test_uid_gid_ignorable(tmp_path):
    ma = scan_bytes(tmp_path, "a.tar",
                    make_tar([{"path": "f", "data": b"1", "uid": 1, "gid": 1}]))
    mb = scan_bytes(tmp_path, "b.tar",
                    make_tar([{"path": "f", "data": b"1", "uid": 2, "gid": 3}]))
    assert compare_manifests(ma, mb, Policy())["verdict"] == VERDICT_DIFFERENT
    assert compare_manifests(
        ma, mb, Policy(ignore_uidgid=True)
    )["verdict"] == VERDICT_EQUIVALENT


def test_gzip_mtime_ignorable(tmp_path):
    ma = scan_bytes(tmp_path, "a.tar.gz",
                    make_tar([{"path": "f", "data": b"1"}],
                             compression="gzip", gzip_mtime=111))
    mb = scan_bytes(tmp_path, "b.tar.gz",
                    make_tar([{"path": "f", "data": b"1"}],
                             compression="gzip", gzip_mtime=222))
    assert compare_manifests(ma, mb, Policy())["verdict"] == VERDICT_DIFFERENT
    relaxed = compare_manifests(
        ma, mb, Policy(ignore_compression_params=True)
    )
    assert relaxed["verdict"] == VERDICT_REPRODUCIBLE or \
        relaxed["verdict"] == VERDICT_EQUIVALENT


def test_compression_format_difference_real(tmp_path):
    gz = scan_bytes(tmp_path, "a.tar.gz",
                    make_tar([{"path": "f", "data": b"1"}], compression="gzip"))
    plain = scan_bytes(tmp_path, "a.tar",
                       make_tar([{"path": "f", "data": b"1"}]))
    result = compare_manifests(gz, plain, Policy(ignore_compression_params=True))
    assert result["verdict"] == VERDICT_EQUIVALENT
    fields = {d["field"]: d["ignored"]
              for d in result["ignorable_differences"] + result["real_differences"]}
    assert fields.get("compression") is True


def test_symlink_target_is_real_difference(tmp_path):
    ma = scan_bytes(tmp_path, "a.tar", make_tar([
        {"path": "r1", "data": b"a"},
        {"path": "l", "kind": "symlink", "link_target": "r1"},
    ]))
    mb = scan_bytes(tmp_path, "b.tar", make_tar([
        {"path": "r2", "data": b"b"},
        {"path": "l", "kind": "symlink", "link_target": "r2"},
    ]))
    policy = Policy(ignore_mtime=True, ignore_uidgid=True,
                    mode_mask=0o7777, ignore_order=True)
    result = compare_manifests(ma, mb, policy)
    assert result["verdict"] == VERDICT_DIFFERENT
    fields = [d["field"] for md in result["member_diffs"] for d in md["real"]]
    assert "link_target" in fields


def test_quarantine_verdict(tmp_path):
    good = scan_bytes(tmp_path, "g.tar",
                      make_tar([{"path": "f", "data": b"1"}]))
    bad = scan_bytes(tmp_path, "b.tar",
                     make_tar([{"path": "evil", "kind": "symlink",
                                "link_target": "../../x"}]))
    result = compare_manifests(good, bad, Policy(
        ignore_mtime=True, ignore_uidgid=True, mode_mask=0o7777,
        ignore_order=True, ignore_compression_params=True,
    ))
    assert result["verdict"] == VERDICT_QUARANTINED
    assert result["quarantine_notes"][0]["side"] == "b"


def test_proof_is_byte_stable(tmp_path):
    data = make_zip([("a", b"hello", 0o644)])
    ma = scan_bytes(tmp_path, "a.zip", data)
    mb = scan_bytes(tmp_path, "b.zip", data)
    policy = Policy(name="rel", version=3, ignore_mtime=True)
    result = compare_manifests(ma, mb, policy)
    arch_a = {"content_hash": "sha256:aaa", "manifest_hash": "sha256:mmm"}
    arch_b = {"content_hash": "sha256:bbb", "manifest_hash": "sha256:nnn"}
    proof1 = build_proof(arch_a, arch_b, ma, mb, policy, result)
    proof2 = build_proof(arch_a, arch_b, ma, mb, policy, result)
    assert canonical.canonical_bytes(proof1) == canonical.canonical_bytes(proof2)
    assert proof1["proof_hash"] == proof2["proof_hash"]
    assert len(proof1["proof_hash"]) == 64
