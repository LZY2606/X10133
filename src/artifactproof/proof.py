"""字节稳定的 JSON 证明。

证明内容刻意不包含任何“现在时间”“临时 id”等环境量，只包含：
工具版本、所选策略（含其规范哈希）、两份归档的 blob/manifest 哈希、
以及比较结论与逐因素差异。因此对同样输入在任何机器重复导出，
得到的字节逐位相同（含末尾换行）。
"""

from __future__ import annotations

from . import __version__
from .canonical import canonical_bytes, canonical_hash
from .policy import normalize_policy, policy_body_hash

PROOF_KIND = "artifactproof.proof/v1"


def build_proof(manifest_a, manifest_b, policy_body, comparison):
    """构造证明 dict（逻辑结构，尚未序列化）。"""
    policy_body = normalize_policy(policy_body)
    return {
        "kind": PROOF_KIND,
        "tool": {"name": "artifactproof", "version": __version__},
        "policy": {"body": policy_body, "sha256": policy_body_hash(policy_body)},
        "archives": [
            {
                "role": "a",
                "filename": manifest_a["archive_filename"],
                "blob_sha256": manifest_a["blob_sha256"],
                "blob_size": manifest_a["blob_size"],
                "manifest_sha256": manifest_a["manifest_sha256"],
                "quarantined": manifest_a["quarantined"],
            },
            {
                "role": "b",
                "filename": manifest_b["archive_filename"],
                "blob_sha256": manifest_b["blob_sha256"],
                "blob_size": manifest_b["blob_size"],
                "manifest_sha256": manifest_b["manifest_sha256"],
                "quarantined": manifest_b["quarantined"],
            },
        ],
        "result": {
            "verdict": comparison["verdict"],
            "summary": comparison["summary"],
            "order_factor": comparison.get("order_factor"),
            "archive_factors": comparison.get("archive_factors", []),
            "entries": [
                {
                    "path": e["path"],
                    "status": e["status"],
                    "content_diffs": e["content_diffs"],
                    "effective_metadata": e["effective_metadata"],
                    "ignorable_metadata": e["ignorable_metadata"],
                }
                for e in comparison["entries"]
            ],
        },
    }


def proof_bytes(proof: dict) -> bytes:
    return canonical_bytes(proof)


def proof_sha256(proof: dict) -> str:
    return canonical_hash(proof)

