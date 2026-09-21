"""HTTP 集成测试：真实启动服务，走 multipart 上传与 JSON API。"""

import json
import threading
import urllib.request

import pytest

from archive_builders import make_zip
from artifactproof.storage import Storage
from artifactproof.webapp import run_server


@pytest.fixture()
def server(tmp_path):
    st = Storage(str(tmp_path / "data"), budget=10 * 1024 * 1024)
    httpd = run_server(st, host="127.0.0.1", port=0)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:%d" % port
    httpd.shutdown()
    httpd.server_close()


def _get(base, path):
    with urllib.request.urlopen(base + path) as resp:
        return resp.status, resp.read(), dict(resp.headers)


def _post_json(base, path, obj):
    req = urllib.request.Request(
        base + path,
        data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode())


def _multipart(base, path, filename, data):
    boundary = "----testboundary123"
    body = (
        ("--%s\r\n" % boundary).encode()
        + ('Content-Disposition: form-data; name="file"; filename="%s"\r\n' % filename).encode()
        + b"Content-Type: application/octet-stream\r\n\r\n"
        + data
        + ("\r\n--%s--\r\n" % boundary).encode()
    )
    req = urllib.request.Request(
        base + path,
        data=body,
        headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode())


def test_index_shows_title(server):
    status, body, _ = _get(server, "/")
    assert status == 200
    assert "产物核验站".encode() in body


def test_upload_compare_proof_flow(server):
    z1 = make_zip([("f", b"hello")])
    z2 = make_zip([("f", b"hello")])
    _, up1 = _multipart(server, "/api/archives", "a.zip", z1)
    _, up2 = _multipart(server, "/api/archives", "b.zip", z2)
    a = up1["archives"][0]["id"]
    b = up2["archives"][0]["id"]

    # 列表接口
    _, listing_raw, _ = _get(server, "/api/archives")
    listing = json.loads(listing_raw.decode())
    assert len(listing["archives"]) == 2

    status, cmp = _post_json(
        server,
        "/api/compare",
        {"archive_a": a, "archive_b": b, "policy_name": "default", "policy_version": 1},
    )
    assert status == 201
    assert cmp["session"]["comparison"]["verdict"] == "reproducible"
    proof_text = cmp["proof_bytes"]

    # 证明下载端点字节一致
    sid = cmp["session"]["id"]
    _, proof_bytes, headers = _get(server, "/api/sessions/%s/proof" % sid)
    assert proof_bytes.decode() == proof_text
    assert headers["Content-Type"].startswith("application/json")


def test_blob_dedup_flag_and_refs(server):
    blob = make_zip([("f", b"abc")])
    _multipart(server, "/api/archives", "x.zip", blob)
    _, up2 = _multipart(server, "/api/archives", "y.zip", blob)
    assert up2["archives"][0]["blob_reused"] is True


def test_policy_lifecycle(server):
    _, data_raw, _ = _get(server, "/api/policies")
    data = json.loads(data_raw.decode())
    assert any(p["name"] == "default" for p in data["policies"])
    _, created = _post_json(
        server,
        "/api/policies",
        {"name": "strict", "body": {"ignore_mtime": False}},
    )
    assert created["policy"]["versions"][0]["version"] == 1


def test_quarantined_upload_visible(server):
    evil = make_zip([("ok", b"1"), ("../escape", b"2")])
    _, up = _multipart(server, "/api/archives", "evil.zip", evil)
    rec = up["archives"][0]
    assert rec["quarantined"] is True
    assert rec["safe_prefix"] == ["ok"]
