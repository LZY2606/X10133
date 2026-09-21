"""离线 Web 界面与 JSON API，全部基于标准库实现。"""

from __future__ import annotations

import json
import os
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import canonical
from .policy import Policy
from .storage import Store

ASSET_DIR = os.path.join(os.path.dirname(__file__), "web_assets")

ASSET_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
}


def create_handler(store):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ArtifactProof/1.0"

        def log_message(self, fmt, *args):
            return

        def _send_json(self, obj, status=HTTPStatus.OK, raw=False,
                       content_type="application/json; charset=utf-8"):
            data = obj if raw else canonical.canonical_bytes(obj)
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _send_error(self, status, message):
            self._send_json({"error": message}, status=status)

        def _read_body(self):
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length <= 0:
                return b""
            return self.rfile.read(length)

        def _load_json(self):
            body = self._read_body()
            try:
                return json.loads(body.decode("utf-8")) if body else {}
            except (ValueError, UnicodeDecodeError):
                raise ValueError("请求体不是合法 JSON")

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            query = urllib.parse.parse_qs(parsed.query)
            try:
                if path == "/":
                    return self._serve_asset("index.html")
                if path.startswith("/assets/"):
                    return self._serve_asset(os.path.basename(path))
                if path == "/api/archives":
                    return self._send_json({"archives": store.list_archives()})
                if path.startswith("/api/archives/"):
                    upload_id = path.rsplit("/", 1)[-1]
                    summary = store.archive_summary(upload_id)
                    if summary is None:
                        return self._send_error(404, "归档不存在")
                    return self._send_json(summary)
                if path == "/api/policies":
                    return self._send_json({"policies": store.list_policies()})
                if path == "/api/sessions":
                    return self._send_json({"sessions": store.list_sessions()})
                if path.startswith("/api/sessions/") and path.endswith("/proof"):
                    session_id = path.split("/")[3]
                    session = store.get_session(session_id)
                    if session is None:
                        return self._send_error(404, "比较会话不存在")
                    proof_bytes = canonical.canonical_bytes(session["proof"])
                    self.send_response(200)
                    self.send_header(
                        "Content-Type", "application/json; charset=utf-8"
                    )
                    self.send_header(
                        "Content-Disposition",
                        f'attachment; filename="proof-{session_id[:8]}.json"',
                    )
                    self.send_header("Content-Length", str(len(proof_bytes)))
                    self.end_headers()
                    self.wfile.write(proof_bytes)
                    return
                if path.startswith("/api/sessions/"):
                    session_id = path.rsplit("/", 1)[-1]
                    session = store.get_session(session_id)
                    if session is None:
                        return self._send_error(404, "比较会话不存在")
                    return self._send_json(session)
                return self._send_error(404, "未找到")
            except Exception as exc:  # noqa: BLE001
                return self._send_error(500, str(exc))

        def do_POST(self):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            query = urllib.parse.parse_qs(parsed.query)
            try:
                if path == "/api/archives":
                    filename = query.get("filename", [None])[0]
                    data = self._read_body()
                    if not data:
                        return self._send_error(400, "上传内容为空")
                    record = store.upload_archive(data, filename=filename)
                    return self._send_json(record, status=201)
                if path == "/api/policies":
                    body = self._load_json()
                    policy_id = body.get("id") or body.get("name") or "custom"
                    policy = Policy.from_dict(body.get("policy", body))
                    saved = store.create_policy(policy_id, policy)
                    return self._send_json(saved, status=201)
                if path == "/api/sessions":
                    body = self._load_json()
                    upload_a = body.get("archive_a")
                    upload_b = body.get("archive_b")
                    if not upload_a or not upload_b:
                        return self._send_error(400, "需要 archive_a 与 archive_b")
                    session = store.create_session(
                        upload_a, upload_b,
                        policy_id=body.get("policy_id"),
                        policy_version=body.get("policy_version"),
                    )
                    return self._send_json(session, status=201)
                if path == "/api/gc":
                    result = store.garbage_collect()
                    return self._send_json(result)
                return self._send_error(404, "未找到")
            except KeyError as exc:
                return self._send_error(404, str(exc))
            except PermissionError as exc:
                return self._send_error(409, str(exc))
            except ValueError as exc:
                return self._send_error(400, str(exc))

        def do_DELETE(self):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            try:
                if path.startswith("/api/archives/"):
                    upload_id = path.rsplit("/", 1)[-1]
                    if store.delete_archive(upload_id):
                        return self._send_json({"deleted": upload_id})
                    return self._send_error(404, "归档不存在")
                return self._send_error(404, "未找到")
            except PermissionError as exc:
                return self._send_error(409, str(exc))

        def _serve_asset(self, name):
            asset_path = os.path.join(ASSET_DIR, name)
            if not os.path.isfile(asset_path):
                return self._send_error(404, "资源不存在")
            with open(asset_path, "rb") as fh:
                data = fh.read()
            ext = os.path.splitext(name)[1]
            self.send_response(200)
            self.send_header(
                "Content-Type", ASSET_TYPES.get(ext, "application/octet-stream")
            )
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


def run(host="127.0.0.1", port=5218, data_dir=None):
    if data_dir is None:
        data_dir = os.environ.get(
            "ARTIFACTPROOF_DATA",
            os.path.join(os.getcwd(), ".artifactproof-data"),
        )
    store = Store(data_dir)
    handler = create_handler(store)
    server = ThreadingHTTPServer((host, port), handler)
    return server, store
