"""比较引擎：真实内容差异 vs 可忽略差异，以及策略各因素。"""

import zipfile

from archive_builders import make_tar, make_zip
from artifactproof.diff import VERDICT_DIFFERS, VERDICT_REPRODUCIBLE, compare_manifests
from artifactproof.manifest import build_manifest
from artifactproof.policy import default_policy, normalize_policy
from artifactproof.scanner import scan_archive


def _manifest(blob, name="a.bin"):
    scan = scan_archive(blob, budget=10 * 1024 * 1024)
    return build_manifest(scan, name, "0" * 64, len(blob))


def test_order_only_differs_then_ignored():
    z1 = make_zip([("a", b"1"), ("b", b"2")])
    z2 = make_zip([("b", b"2"), ("a", b"1")])
    m1, m2 = _manifest(z1), _manifest(z2)

    pol = normalize_policy({**default_policy(), "ignore_order": False})
    r = compare_manifests(m1, m2, pol)
    assert r["verdict"] == VERDICT_DIFFERS
    assert r["order_factor"]["ignored"] is False

    pol2 = normalize_policy({**default_policy(), "ignore_order": True})
    r2 = compare_manifests(m1, m2, pol2)
    assert r2["verdict"] == VERDICT_REPRODUCIBLE
    assert r2["order_factor"]["ignored"] is True


def test_mtime_default_ignored_but_counts_when_strict():
    z1 = make_zip([("a", b"1")], fixed_mtime=(1980, 1, 1, 0, 0, 0))
    z2 = make_zip([("a", b"1")], fixed_mtime=(1981, 6, 1, 0, 0, 0))
    m1, m2 = _manifest(z1), _manifest(z2)

    r = compare_manifests(m1, m2, default_policy())
    assert r["verdict"] == VERDICT_REPRODUCIBLE
    e = r["entries"][0]
    assert e["status"] == "ignorable_only"
    assert any(f["factor"] == "mtime" for f in e["ignorable_metadata"])

    strict = normalize_policy({**default_policy(), "ignore_mtime": False})
    r2 = compare_manifests(m1, m2, strict)
    assert r2["verdict"] == VERDICT_DIFFERS
    assert any(f["factor"] == "mtime" for f in r2["entries"][0]["effective_metadata"])


def test_mode_mask_filters_bits():
    z1 = make_zip([("a", b"1", {"mode": 0o755})])
    z2 = make_zip([("a", b"1", {"mode": 0o700})])
    m1, m2 = _manifest(z1), _manifest(z2)

    # 掩码 700：755&700=700，700&700=700 => 基础执行/拥有者位相同，组/其他位被屏蔽
    pol = normalize_policy({**default_policy(), "mode_mask": 0o700})
    r = compare_manifests(m1, m2, pol)
    assert r["verdict"] == VERDICT_REPRODUCIBLE

    # 全权限比较则不同
    pol_full = normalize_policy({**default_policy(), "mode_mask": 0o7777})
    r2 = compare_manifests(m1, m2, pol_full)
    assert r2["verdict"] == VERDICT_DIFFERS
    assert any(f["factor"] == "mode" for f in r2["entries"][0]["effective_metadata"])

    # 掩码 0：所有权限位忽略
    pol_zero = normalize_policy({**default_policy(), "mode_mask": 0})
    assert compare_manifests(m1, m2, pol_zero)["verdict"] == VERDICT_REPRODUCIBLE


def test_compression_method_ignored_by_default():
    z_stored = make_zip([("a", b"0" * 500)], compression=zipfile.ZIP_STORED)
    z_deflated = make_zip([("a", b"0" * 500)], compression=zipfile.ZIP_DEFLATED)
    m1, m2 = _manifest(z_stored), _manifest(z_deflated)
    r = compare_manifests(m1, m2, default_policy())
    assert r["verdict"] == VERDICT_REPRODUCIBLE
    e = r["entries"][0]
    assert any(f["factor"] == "compression" for f in e["ignorable_metadata"])

    strict = normalize_policy({**default_policy(), "ignore_compression": False})
    r2 = compare_manifests(m1, m2, strict)
    assert r2["verdict"] == VERDICT_DIFFERS


def test_real_content_diff_is_never_ignored():
    z1 = make_zip([("a", b"content-one")])
    z2 = make_zip([("a", b"content-two")])
    m1, m2 = _manifest(z1), _manifest(z2)
    # 即使所有因素都设为可忽略，内容不同仍不可复现
    pol = normalize_policy(
        {
            "ignore_mtime": True,
            "ignore_uid_gid": True,
            "ignore_compression": True,
            "ignore_order": True,
            "mode_mask": 0,
        }
    )
    r = compare_manifests(m1, m2, pol)
    assert r["verdict"] == VERDICT_DIFFERS
    e = r["entries"][0]
    assert e["status"] == "content_differs"
    assert "sha256" in e["content_diffs"]


def test_added_removed_members_are_content_diffs():
    m1 = _manifest(make_zip([("a", b"1"), ("b", b"2")]))
    m2 = _manifest(make_zip([("a", b"1"), ("c", b"3")]))
    r = compare_manifests(m1, m2, default_policy())
    statuses = {e["path"]: e["status"] for e in r["entries"]}
    assert statuses["b"] == "removed_in_b"
    assert statuses["c"] == "added_in_b"
    assert r["summary"]["content_diff_count"] == 2


def test_uid_gid_factor():
    t1 = make_tar([{"type": "file", "name": "a", "data": b"1", "uid": 10, "gid": 20}])
    t2 = make_tar([{"type": "file", "name": "a", "data": b"1", "uid": 33, "gid": 44}])
    m1, m2 = _manifest(t1), _manifest(t2)
    r = compare_manifests(m1, m2, default_policy())
    assert r["verdict"] == VERDICT_REPRODUCIBLE
    assert any(f["factor"] == "uid_gid" for f in r["entries"][0]["ignorable_metadata"])
    strict = normalize_policy({**default_policy(), "ignore_uid_gid": False})
    assert compare_manifests(m1, m2, strict)["verdict"] == VERDICT_DIFFERS


def test_symlink_target_change_is_content_diff():
    z1 = make_zip([("lnk", b"a", {"is_symlink": True})])
    z2 = make_zip([("lnk", b"b", {"is_symlink": True})])
    m1, m2 = _manifest(z1), _manifest(z2)
    r = compare_manifests(m1, m2, default_policy())
    e = r["entries"][0]
    assert e["status"] == "content_differs"
    assert "link_target" in e["content_diffs"]


def test_tar_container_compression_difference():
    t_plain = make_tar([{"type": "file", "name": "a", "data": b"x"}], compression="none")
    t_gz = make_tar([{"type": "file", "name": "a", "data": b"x"}], compression="gzip")
    m1, m2 = _manifest(t_plain), _manifest(t_gz)
    r = compare_manifests(m1, m2, default_policy())
    assert r["verdict"] == VERDICT_REPRODUCIBLE
    strict = normalize_policy({**default_policy(), "ignore_compression": False})
    r2 = compare_manifests(m1, m2, strict)
    assert r2["verdict"] == VERDICT_DIFFERS
    assert any(f["factor"] == "archive_compression" for f in r2["archive_factors"])

