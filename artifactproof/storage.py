"""持久化：内容寻址 blob 存储 + SQLite 元数据。

- 相同字节只存一份 blob（按 sha256 复用）。
- 上传、策略（版本化）、比较会话全部落库，重启不丢。
- 删除 blob 前强制确认没有任何会话引用。
- 失败的上传先落临时文件再原子落库，绝不留下部分解压物
  （扫描本身也不向磁盘解包）。
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid

from . import canonical
from .models import ArchiveManifest
from .scanner import scan_archive, DEFAULT_BOMB_BUDGET
from .policy import Policy
from .compare import compare_manifests, build_proof

SCHEMA = """
CREATE TABLE IF NOT EXISTS archives (
    upload_id TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL,
    filename TEXT,
    size_bytes INTEGER NOT NULL,
    manifest_hash TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_archives_hash ON archives(content_hash);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT NOT NULL,
    version INTEGER NOT NULL,
    data_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (id, version)
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    archive_a TEXT NOT NULL,
    archive_b TEXT NOT NULL,
    policy_id TEXT,
    policy_version INTEGER,
    result_json TEXT NOT NULL,
    proof_json TEXT NOT NULL,
    proof_hash TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_a ON sessions(archive_a);
CREATE INDEX IF NOT EXISTS idx_sessions_b ON sessions(archive_b);
"""


class Store:
    def __init__(self, data_dir, bomb_budget=DEFAULT_BOMB_BUDGET):
        self.data_dir = os.path.abspath(data_dir)
        self.blobs_dir = os.path.join(self.data_dir, "blobs")
        self.tmp_dir = os.path.join(self.data_dir, "tmp")
        os.makedirs(self.blobs_dir, exist_ok=True)
        os.makedirs(self.tmp_dir, exist_ok=True)
        self.db_path = os.path.join(self.data_dir, "artifactproof.db")
        self.bomb_budget = bomb_budget
        self._lock_db()
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _lock_db(self):
        # 串行化写入，避免多线程上传时互相打断
        self._conn = self._connect()

    def _init_db(self):
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # ---- blobs ----
    def _blob_path(self, content_hash):
        hexed = content_hash.split(":", 1)[-1]
        return os.path.join(self.blobs_dir, hexed[:2], hexed[2:4], hexed)

    def put_blob(self, data):
        """写入上传字节；若已存在相同字节则直接复用。返回 (hash, path, reused)。"""
        content_hash = "sha256:" + canonical.sha256_hex(data)
        target = self._blob_path(content_hash)
        if os.path.exists(target):
            return content_hash, target, True
        os.makedirs(os.path.dirname(target), exist_ok=True)
        tmp_path = os.path.join(
            self.tmp_dir, "upload-" + uuid.uuid4().hex + ".part"
        )
        try:
            with open(tmp_path, "wb") as fh:
                fh.write(data)
            os.replace(tmp_path, target)
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
        return content_hash, target, False

    def blob_path(self, content_hash):
        path = self._blob_path(content_hash)
        if not os.path.exists(path):
            raise FileNotFoundError(content_hash)
        return path

    # ---- archives ----
    def upload_archive(self, data, filename=None):
        content_hash, blob_path, reused = self.put_blob(data)
        manifest = scan_archive(blob_path, budget=self.bomb_budget)
        manifest_bytes = canonical.canonical_bytes(manifest.to_dict())
        manifest_hash = "sha256:" + canonical.sha256_hex(manifest_bytes)
        upload_id = uuid.uuid4().hex
        now = time.time()
        self._conn.execute(
            "INSERT INTO archives (upload_id, content_hash, filename, "
            "size_bytes, manifest_hash, manifest_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                upload_id, content_hash, filename, len(data),
                manifest_hash, manifest_bytes.decode("utf-8"), now,
            ),
        )
        self._conn.commit()
        return {
            "upload_id": upload_id,
            "content_hash": content_hash,
            "filename": filename,
            "size_bytes": len(data),
            "manifest_hash": manifest_hash,
            "blob_reused": reused,
            "manifest": manifest.to_dict(),
            "created_at": now,
        }

    def list_archives(self):
        rows = self._conn.execute(
            "SELECT upload_id, content_hash, filename, size_bytes, "
            "manifest_hash, created_at FROM archives ORDER BY created_at"
        ).fetchall()
        result = []
        for row in rows:
            result.append({
                "upload_id": row["upload_id"],
                "content_hash": row["content_hash"],
                "filename": row["filename"],
                "size_bytes": row["size_bytes"],
                "manifest_hash": row["manifest_hash"],
                "created_at": row["created_at"],
                "quarantined": self.get_manifest(row["upload_id"]).quarantined,
            })
        return result

    def get_archive(self, upload_id):
        row = self._conn.execute(
            "SELECT * FROM archives WHERE upload_id = ?", (upload_id,)
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def get_manifest(self, upload_id):
        row = self.get_archive(upload_id)
        if row is None:
            raise KeyError(upload_id)
        return ArchiveManifest.from_dict(json.loads(row["manifest_json"]))

    def archive_summary(self, upload_id):
        row = self.get_archive(upload_id)
        if row is None:
            return None
        manifest = ArchiveManifest.from_dict(json.loads(row["manifest_json"]))
        return {
            "upload_id": row["upload_id"],
            "content_hash": row["content_hash"],
            "filename": row["filename"],
            "size_bytes": row["size_bytes"],
            "manifest_hash": row["manifest_hash"],
            "created_at": row["created_at"],
            "manifest": manifest.to_dict(),
        }

    def delete_archive(self, upload_id):
        """仅当没有任何会话引用该上传时才允许删除。"""
        refs = self._session_refs_for(upload_id)
        if refs:
            raise PermissionError(
                f"归档仍被 {len(refs)} 个比较会话引用: {', '.join(refs)}"
            )
        row = self.get_archive(upload_id)
        if row is None:
            return False
        self._conn.execute(
            "DELETE FROM archives WHERE upload_id = ?", (upload_id,)
        )
        self._conn.commit()
        return True

    def _session_refs_for(self, upload_id):
        rows = self._conn.execute(
            "SELECT session_id FROM sessions WHERE archive_a = ? OR archive_b = ?",
            (upload_id, upload_id),
        ).fetchall()
        return [r["session_id"] for r in rows]

    # ---- policies ----
    def create_policy(self, policy_id, policy):
        row = self._conn.execute(
            "SELECT COALESCE(MAX(version), 0) AS v FROM policies WHERE id = ?",
            (policy_id,),
        ).fetchone()
        version = row["v"] + 1
        policy.version = version
        data = canonical.canonical_bytes(policy.to_dict()).decode("utf-8")
        self._conn.execute(
            "INSERT INTO policies (id, version, data_json, created_at) "
            "VALUES (?, ?, ?, ?)",
            (policy_id, version, data, time.time()),
        )
        self._conn.commit()
        return {"id": policy_id, "version": version, "policy": policy.to_dict()}

    def list_policies(self):
        rows = self._conn.execute(
            "SELECT id, MAX(version) AS v FROM policies GROUP BY id"
        ).fetchall()
        out = []
        for row in rows:
            record = self.get_policy(row["id"], row["v"])
            out.append({"id": row["id"], "version": row["v"],
                        "policy": record["policy"].to_dict()})
        return out

    def get_policy(self, policy_id, version=None):
        if version is None:
            row = self._conn.execute(
                "SELECT version FROM policies WHERE id = ? "
                "ORDER BY version DESC LIMIT 1", (policy_id,)
            ).fetchone()
            if row is None:
                return None
            version = row["version"]
        row = self._conn.execute(
            "SELECT data_json FROM policies WHERE id = ? AND version = ?",
            (policy_id, version),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": policy_id,
            "version": version,
            "policy": Policy.from_dict(json.loads(row["data_json"])),
        }

    # ---- sessions ----
    def create_session(self, upload_a, upload_b, policy_id=None,
                       policy_version=None):
        archive_a = self.get_archive(upload_a)
        archive_b = self.get_archive(upload_b)
        if archive_a is None or archive_b is None:
            raise KeyError("归档不存在")
        if policy_id is not None:
            record = self.get_policy(policy_id, policy_version)
            if record is None:
                raise KeyError("策略不存在")
            policy = record["policy"]
            policy_version = record["version"]
        else:
            policy = Policy(name="strict")
        manifest_a = ArchiveManifest.from_dict(
            json.loads(archive_a["manifest_json"])
        )
        manifest_b = ArchiveManifest.from_dict(
            json.loads(archive_b["manifest_json"])
        )
        result = compare_manifests(manifest_a, manifest_b, policy)

        def archive_brief(row):
            return {
                "content_hash": row["content_hash"],
                "manifest_hash": row["manifest_hash"],
            }

        proof = build_proof(
            archive_brief(archive_a), archive_brief(archive_b),
            manifest_a, manifest_b, policy, result,
        )
        session_id = uuid.uuid4().hex
        result_json = canonical.canonical_bytes(result).decode("utf-8")
        proof_json = canonical.canonical_bytes(proof).decode("utf-8")
        self._conn.execute(
            "INSERT INTO sessions (session_id, archive_a, archive_b, "
            "policy_id, policy_version, result_json, proof_json, proof_hash, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                session_id, upload_a, upload_b, policy_id, policy_version,
                result_json, proof_json, proof["proof_hash"], time.time(),
            ),
        )
        self._conn.commit()
        return {
            "session_id": session_id,
            "upload_a": upload_a,
            "upload_b": upload_b,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "result": result,
            "proof": proof,
        }

    def list_sessions(self):
        rows = self._conn.execute(
            "SELECT session_id, archive_a, archive_b, policy_id, "
            "policy_version, proof_hash, created_at FROM sessions "
            "ORDER BY created_at"
        ).fetchall()
        return [dict(row) for row in rows]

    def get_session(self, session_id):
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row is None:
            return None
        return {
            "session_id": row["session_id"],
            "upload_a": row["archive_a"],
            "upload_b": row["archive_b"],
            "policy_id": row["policy_id"],
            "policy_version": row["policy_version"],
            "result": json.loads(row["result_json"]),
            "proof": json.loads(row["proof_json"]),
            "proof_hash": row["proof_hash"],
            "created_at": row["created_at"],
        }

    # ---- blob GC ----
    def garbage_collect(self, dry_run=False):
        """清理无任何上传记录引用的 blob；删除前确认引用计数为零。"""
        rows = self._conn.execute(
            "SELECT content_hash, COUNT(*) AS n FROM archives GROUP BY content_hash"
        ).fetchall()
        referenced = {row["content_hash"] for row in rows}
        removed = []
        for dirpath, _dirnames, filenames in os.walk(self.blobs_dir):
            for name in filenames:
                full = os.path.join(dirpath, name)
                # 文件名即完整 sha256 hex（两级目录仅为分片）
                candidate = "sha256:" + name
                if candidate in referenced:
                    continue
                if not dry_run:
                    os.remove(full)
                removed.append(candidate)
        return {"removed": removed, "dry_run": dry_run}

    def close(self):
        self._conn.close()
