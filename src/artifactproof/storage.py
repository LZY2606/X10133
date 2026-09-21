"""持久化存储。

目录布局（默认 ``.artifactproof``）::

    blobs/ab/cd<...>          内容寻址的原始上传字节（去重复用）
    archives/<id>.json        归档记录（含清单与所属 blob）
    policies/<name>.json      策略（含全部版本）
    sessions/<id>.json        比较会话（独立，即使 blob 相同也各自独立）
    index.json                各实体 id 列表（原子更新）

写入一律“临时文件 + os.replace”，保证崩溃时不留半截 JSON。
清理 blob 前会检查归档引用；删除归档前会检查会话引用。
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid

from .canonical import canonical_bytes
from .manifest import build_manifest
from .policy import default_policy, normalize_policy, policy_body_hash
from .proof import proof_sha256
from .scanner import DEFAULT_BUDGET, scan_archive


def _now():
    return int(time.time())


def atomic_write_bytes(path, data):
    tmp = "%s.tmp-%s" % (path, uuid.uuid4().hex)
    with open(tmp, "wb") as fp:
        fp.write(data)
        fp.flush()
        os.fsync(fp.fileno())
    os.replace(tmp, path)


def atomic_write_json(path, obj):
    atomic_write_bytes(path, canonical_bytes(obj))


class Storage:
    def __init__(self, root, budget=DEFAULT_BUDGET):
        self.root = os.path.abspath(root)
        self.budget = budget
        self.blobs_dir = os.path.join(self.root, "blobs")
        self.archives_dir = os.path.join(self.root, "archives")
        self.policies_dir = os.path.join(self.root, "policies")
        self.sessions_dir = os.path.join(self.root, "sessions")
        for d in (
            self.root,
            self.blobs_dir,
            self.archives_dir,
            self.policies_dir,
            self.sessions_dir,
        ):
            os.makedirs(d, exist_ok=True)
        self.lock = threading.RLock()
        self.index_path = os.path.join(self.root, "index.json")
        if not os.path.exists(self.index_path):
            atomic_write_json(
                self.index_path,
                {"archives": [], "policies": [], "sessions": []},
            )
        self._ensure_default_policy()

    # ---------- 基础 ----------
    def _read_json(self, path):
        with open(path, "rb") as fp:
            return json.loads(fp.read().decode("utf-8"))

    def _index(self):
        return self._read_json(self.index_path)

    def _save_index(self, index):
        atomic_write_json(self.index_path, index)

    def _blob_path(self, digest):
        return os.path.join(self.blobs_dir, digest[:2], digest[2:])

    # ---------- blob 与归档 ----------
    def upload_blob(self, filename, data):
        """保存上传字节（按 sha256 去重），扫描并生成归档记录。"""
        with self.lock:
            digest = hashlib.sha256(data).hexdigest()
            bpath = self._blob_path(digest)
            reused = os.path.exists(bpath)
            if not reused:
                os.makedirs(os.path.dirname(bpath), exist_ok=True)
                atomic_write_bytes(bpath, data)

            scan = scan_archive(data, budget=self.budget)
            manifest = build_manifest(
                scan,
                archive_filename=os.path.basename(filename) or "archive",
                blob_sha256=digest,
                blob_size=len(data),
            )
            archive_id = uuid.uuid4().hex
            record = {
                "id": archive_id,
                "filename": manifest["archive_filename"],
                "created_at": _now(),
                "blob_sha256": digest,
                "blob_size": len(data),
                "blob_reused": reused,
                "manifest": manifest,
            }
            atomic_write_json(os.path.join(self.archives_dir, archive_id + ".json"), record)
            index = self._index()
            if archive_id not in index["archives"]:
                index["archives"].append(archive_id)
                self._save_index(index)
            return record

    def list_archives(self):
        index = self._index()
        out = []
        for aid in index["archives"]:
            rec = self.get_archive(aid)
            if rec:
                out.append(rec)
        out.sort(key=lambda r: r["created_at"])
        return out

    def get_archive(self, archive_id):
        path = os.path.join(self.archives_dir, archive_id + ".json")
        if not os.path.exists(path):
            return None
        return self._read_json(path)

    def blob_references(self, digest):
        """返回引用某个 blob 的归档 id 列表。"""
        refs = []
        for rec in self.list_archives():
            if rec["blob_sha256"] == digest:
                refs.append(rec["id"])
        return refs

    def delete_blob_allowed(self, digest):
        """清理 blob 前必须确认没有任何归档记录引用。"""
        return self.blob_references(digest) == []

    def delete_blob(self, digest):
        with self.lock:
            refs = self.blob_references(digest)
            if refs:
                raise RuntimeError("blob 仍被归档引用，拒绝删除: %s" % refs)
            path = self._blob_path(digest)
            if os.path.exists(path):
                os.remove(path)
            return True

    def archive_session_refs(self, archive_id):
        return [
            sid
            for sid in self._index()["sessions"]
            if self._session_uses_archive(sid, archive_id)
        ]

    def _session_uses_archive(self, session_id, archive_id):
        sess = self.get_session(session_id)
        if not sess:
            return False
        return archive_id in (sess.get("archive_a_id"), sess.get("archive_b_id"))

    def delete_archive(self, archive_id):
        with self.lock:
            refs = self.archive_session_refs(archive_id)
            if refs:
                raise RuntimeError("归档仍被比较会话引用，拒绝删除: %s" % refs)
            rec = self.get_archive(archive_id)
            path = os.path.join(self.archives_dir, archive_id + ".json")
            if os.path.exists(path):
                os.remove(path)
            index = self._index()
            if archive_id in index["archives"]:
                index["archives"].remove(archive_id)
                self._save_index(index)
            return rec

    # ---------- 策略（版本化）----------
    def _ensure_default_policy(self):
        index = self._index()
        if "default" not in index["policies"]:
            self._write_new_policy("default", default_policy())

    def _policy_path(self, name):
        safe = name.replace(os.sep, "_")
        return os.path.join(self.policies_dir, safe + ".json")

    def _write_new_policy(self, name, body):
        body = normalize_policy(body)
        body["name"] = name
        version = {
            "version": 1,
            "created_at": _now(),
            "body": body,
            "sha256": policy_body_hash(body),
        }
        record = {"name": name, "created_at": _now(), "versions": [version]}
        atomic_write_json(self._policy_path(name), record)
        index = self._index()
        if name not in index["policies"]:
            index["policies"].append(name)
            self._save_index(index)
        return record

    def create_policy(self, name, body):
        with self.lock:
            if not name or name in (".", ".."):
                raise ValueError("非法策略名")
            if os.path.exists(self._policy_path(name)):
                raise RuntimeError("策略已存在: %s" % name)
            return self._write_new_policy(name, body)

    def add_policy_version(self, name, body):
        with self.lock:
            record = self.get_policy(name)
            if record is None:
                raise RuntimeError("策略不存在: %s" % name)
            new_body = normalize_policy(body)
            new_body["name"] = name
            new_hash = policy_body_hash(new_body)
            if any(v["sha256"] == new_hash for v in record["versions"]):
                # 幂等：相同策略体复用已有版本
                return record, next(v for v in record["versions"] if v["sha256"] == new_hash)
            version = {
                "version": len(record["versions"]) + 1,
                "created_at": _now(),
                "body": new_body,
                "sha256": new_hash,
            }
            record["versions"].append(version)
            atomic_write_json(self._policy_path(name), record)
            return record, version

    def get_policy(self, name):
        path = self._policy_path(name)
        if not os.path.exists(path):
            return None
        return self._read_json(path)

    def list_policies(self):
        return [self.get_policy(n) for n in self._index()["policies"]]

    def get_policy_version(self, name, version):
        record = self.get_policy(name)
        if not record:
            return None
        for v in record["versions"]:
            if v["version"] == int(version):
                return v
        return None

    # ---------- 比较会话 ----------
    def create_session(self, archive_a_id, archive_b_id, policy_name, policy_version, comparison, proof):
        with self.lock:
            session_id = uuid.uuid4().hex
            proof_digest = proof_sha256(proof)
            record = {
                "id": session_id,
                "created_at": _now(),
                "archive_a_id": archive_a_id,
                "archive_b_id": archive_b_id,
                "policy_name": policy_name,
                "policy_version": int(policy_version),
                "policy_sha256": proof["policy"]["sha256"],
                "comparison": comparison,
                "proof": proof,
                "proof_sha256": proof_digest,
            }
            atomic_write_json(os.path.join(self.sessions_dir, session_id + ".json"), record)
            index = self._index()
            index["sessions"].append(session_id)
            self._save_index(index)
            return record

    def list_sessions(self):
        out = []
        for sid in self._index()["sessions"]:
            rec = self.get_session(sid)
            if rec:
                out.append(rec)
        out.sort(key=lambda r: r["created_at"], reverse=True)
        return out

    def get_session(self, session_id):
        path = os.path.join(self.sessions_dir, session_id + ".json")
        if not os.path.exists(path):
            return None
        return self._read_json(path)

    def delete_session(self, session_id):
        with self.lock:
            path = os.path.join(self.sessions_dir, session_id + ".json")
            if os.path.exists(path):
                os.remove(path)
            index = self._index()
            if session_id in index["sessions"]:
                index["sessions"].remove(session_id)
                self._save_index(index)
