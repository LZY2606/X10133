"""仅使用标准库实现的离线 HTTP 服务：静态页面 + JSON API。"""

from __future__ import annotations

import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .service import Service

WEB_DIR = os.path.join(os.path.dirname(__file__), "web")
MAX_UPLOAD = 256 * 1024 * 1024


def parse_multipart(body: bytes, boundary: bytes):
    """极简 multipart/form-data 解析，返回 [(name, filename, content_type, data)]。"""
    delim = b"--" + boundary
    parts = []
    segments = body.split(delim)
    for seg in segments:
        if not seg or seg in (b"--", b"--\r\n", b"--\n"):
            continue
        if seg.startswith(b"\r\n"):
            seg = seg[2:]
        if seg.endswith(b"\r\n"):
            seg = seg[:-2]
        if b"\r\n\r\n" not in seg:
            continue
        header_blob, content = seg.split(b"\r\n\r\n", 1)
        headers = {}
        for line in header_blob.split(b"\r\n"):
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.strip().lower().decode()] = v.strip().decode()
        cd = headers.get("content-disposition", "")
        name_m = re.search(r'name="([^"]*)"', cd)
        fn_m = re.search(r'filename="([^"]*)"', cd)
        name = name_m.group(1) if name_m else ""
        filename = fn_m.group(1) if fn_m else None
        parts.append((name, filename, headers.get("content-type", ""), content))
    return parts


def create_handler(storage):
    service = Service(storage)

    class Handler(BaseHTTPRequestHandler):
        server_version = "ArtifactProof/0.1"

        def log_message(self, fmt, *args):
            pass

        def _send_json(self, obj, status=200, extra_headers=None):
            data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _send_bytes(self, data, content_type, status=200, download_name=None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            if download_name:
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="%s"' % download_name,
                )
            self.end_headers()
            self.wfile.write(data)

        def _read_body(self):
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_UPLOAD:
                raise ValueError("上传体超过上限")
            return self.rfile.read(length) if length else b""

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path
            try:
                if path == "/" or path == "/index.html":
                    self._serve_static("index.html")
                elif path.startswith("/static/"):
                    self._serve_static(path[len("/static/"):])
                elif path == "/api/archives":
                    self._send_json({"archives": [self._archive_brief(r) for r in storage.list_archives()]})
                elif path.startswith("/api/archives/"):
                    aid = path.rsplit("/", 1)[-1]
                    rec = storage.get_archive(aid)
                    if not rec:
                        self._send_json({"error": "not found"}, 404)
                    else:
                        self._send_json(rec)
                elif path == "/api/policies":
                    self._send_json({"policies": storage.list_policies()})
                elif path == "/api/sessions":
                    self._send_json({"sessions": [self._session_brief(s) for s in storage.list_sessions()]})
                elif path.startswith("/api/sessions/") and path.endswith("/proof"):
                    sid = path.split("/")[3]
                    sess = storage.get_session(sid)
                    if not sess:
                        self._send_json({"error": "not found"}, 404)
                    else:
                        from .canonical import canonical_bytes

                        self._send_bytes(
                            canonical_bytes(sess["proof"]),
                            "application/json; charset=utf-8",
                            download_name="proof-%s.json" % sid[:8],
                        )
                elif path.startswith("/api/sessions/"):
                    sid = path.rsplit("/", 1)[-1]
                    sess = storage.get_session(sid)
                    if not sess:
                        self._send_json({"error": "not found"}, 404)
                    else:
                        self._send_json(sess)
                elif path == "/api/blobs":
                    blobs = {}
                    for rec in storage.list_archives():
                        blobs.setdefault(rec["blob_sha256"], []).append(rec["id"])
                    self._send_json({"blobs": [{"sha256": k, "refs": v} for k, v in sorted(blobs.items())]})
                else:
                    self._send_json({"error": "not found"}, 404)
            except Exception as exc:  # noqa: BLE001
                self._send_json({"error": str(exc)}, 500)

        def do_POST(self):
            parsed = urlparse(self.path)
            path = parsed.path
            try:
                if path == "/api/archives":
                    self._handle_upload()
                elif path == "/api/policies":
                    self._handle_create_policy()
                elif path.startswith("/api/policies/") and path.endswith("/versions"):
                    name = path.split("/")[3]
                    body = json.loads(self._read_body().decode("utf-8"))
                    record, version = storage.add_policy_version(name, body.get("body", body))
                    self._send_json({"policy": record, "version": version})
                elif path == "/api/compare":
                    self._handle_compare()
                else:
                    self._send_json({"error": "not found"}, 404)
            except KeyError as exc:
                self._send_json({"error": str(exc)}, 404)
            except (ValueError, RuntimeError) as exc:
                self._send_json({"error": str(exc)}, 400)
            except Exception as exc:  # noqa: BLE001
                self._send_json({"error": str(exc)}, 500)

        def do_DELETE(self):
            parsed = urlparse(self.path)
            path = parsed.path
            try:
                if path.startswith("/api/archives/"):
                    aid = path.rsplit("/", 1)[-1]
                    try:
                        storage.delete_archive(aid)
                        self._send_json({"deleted": aid})
                    except RuntimeError as exc:
                        self._send_json({"error": str(exc)}, 409)
                elif path.startswith("/api/blobs/"):
                    digest = path.rsplit("/", 1)[-1]
                    try:
                        storage.delete_blob(digest)
                        self._send_json({"deleted": digest})
                    except RuntimeError as exc:
                        self._send_json({"error": str(exc)}, 409)
                elif path.startswith("/api/sessions/"):
                    sid = path.rsplit("/", 1)[-1]
                    storage.delete_session(sid)
                    self._send_json({"deleted": sid})
                else:
                    self._send_json({"error": "not found"}, 404)
            except Exception as exc:  # noqa: BLE001
                self._send_json({"error": str(exc)}, 500)

        def _handle_upload(self):
            ctype = self.headers.get("Content-Type", "")
            body = self._read_body()
            if ctype.startswith("multipart/form-data"):
                bm = re.search(r"boundary=([^;]+)", ctype)
                if not bm:
                    raise ValueError("缺少 multipart boundary")
                boundary = bm.group(1).strip().strip('"').encode()
                parts = parse_multipart(body, boundary)
                files = [p for p in parts if p[1] is not None]
                if not files:
                    raise ValueError("没有上传文件")
                saved = []
                for _, filename, _, data in files:
                    rec = storage.upload_blob(os.path.basename(filename), data)
                    saved.append(self._archive_brief(rec, include_manifest=True))
                self._send_json({"archives": saved}, 201)
            else:
                filename = "archive"
                m = re.search(r'filename="?([^\";]+)"?', ctype)
                rec = storage.upload_blob(filename, body)
                self._send_json({"archives": [self._archive_brief(rec, include_manifest=True)]}, 201)

        def _handle_create_policy(self):
            body = json.loads(self._read_body().decode("utf-8"))
            name = body.get("name")
            record = storage.create_policy(name, body.get("body", body))
            self._send_json({"policy": record}, 201)

        def _handle_compare(self):
            body = json.loads(self._read_body().decode("utf-8"))
            result = service.compare(
                body["archive_a"],
                body["archive_b"],
                body.get("policy_name", "default"),
                int(body.get("policy_version", 1)),
            )
            self._send_json(result, 201)

        def _serve_static(self, rel):
            rel = rel.replace("\\", "/").lstrip("/")
            if ".." in rel.split("/"):
                self._send_json({"error": "forbidden"}, 403)
                return
            full = os.path.normpath(os.path.join(WEB_DIR, rel))
            if not full.startswith(os.path.abspath(WEB_DIR)):
                self._send_json({"error": "forbidden"}, 403)
                return
            if not os.path.exists(full) or os.path.isdir(full):
                full = os.path.join(WEB_DIR, "index.html")
            ctype = "text/html; charset=utf-8"
            if rel.endswith(".css"):
                ctype = "text/css; charset=utf-8"
            elif rel.endswith(".js"):
                ctype = "application/javascript; charset=utf-8"
            with open(full, "rb") as fp:
                self._send_bytes(fp.read(), ctype)

        @staticmethod
        def _archive_brief(rec, include_manifest=False):
            man = rec["manifest"]
            brief = {
                "id": rec["id"],
                "filename": rec["filename"],
                "created_at": rec["created_at"],
                "blob_sha256": rec["blob_sha256"],
                "blob_size": rec["blob_size"],
                "blob_reused": rec["blob_reused"],
                "quarantined": man["quarantined"],
                "quarantine_reason": man.get("quarantine_reason"),
                "quarantine_path": man.get("quarantine_path"),
                "safe_prefix": man.get("safe_prefix", []),
                "family": man["archive_family"],
                "compression": man["archive_compression"],
                "member_count": man["member_count"],
                "manifest_sha256": man["manifest_sha256"],
            }
            if include_manifest:
                brief["manifest"] = man
            return brief

        @staticmethod
        def _session_brief(sess):
            return {
                "id": sess["id"],
                "created_at": sess["created_at"],
                "archive_a_id": sess["archive_a_id"],
                "archive_b_id": sess["archive_b_id"],
                "policy_name": sess["policy_name"],
                "policy_version": sess["policy_version"],
                "verdict": sess["comparison"]["verdict"],
                "verdict_text": sess["comparison"]["verdict_text"],
                "proof_sha256": sess["proof_sha256"],
            }

    return Handler


def run_server(storage, host="127.0.0.1", port=5218):
    httpd = ThreadingHTTPServer((host, port), create_handler(storage))
    return httpd
