"""应用服务层：编排上传、策略、比较会话与证明。"""

from __future__ import annotations

from .diff import VERDICT_QUARANTINED, VERDICT_TEXT, compare_manifests
from .proof import build_proof, proof_bytes, proof_sha256


class Service:
    def __init__(self, storage):
        self.storage = storage

    def compare(self, archive_a_id, archive_b_id, policy_name, policy_version):
        rec_a = self.storage.get_archive(archive_a_id)
        rec_b = self.storage.get_archive(archive_b_id)
        if rec_a is None or rec_b is None:
            raise KeyError("归档不存在")
        pv = self.storage.get_policy_version(policy_name, policy_version)
        if pv is None:
            raise KeyError("策略版本不存在")
        policy_body = pv["body"]
        manifest_a = rec_a["manifest"]
        manifest_b = rec_b["manifest"]

        quarantined = manifest_a["quarantined"] or manifest_b["quarantined"]
        if quarantined:
            comparison = {
                "entries": [],
                "archive_factors": [],
                "order_factor": None,
                "order_a": [],
                "order_b": [],
                "summary": {
                    "content_diff_count": 0,
                    "effective_metadata_diff_count": 0,
                    "ignorable_metadata_diff_count": 0,
                    "archive_factor_diff_count": 0,
                    "order_differs": False,
                    "order_diff_ignored": False,
                },
                "verdict": VERDICT_QUARANTINED,
                "verdict_text": VERDICT_TEXT[VERDICT_QUARANTINED],
                "quarantine": {
                    "a": {
                        "quarantined": manifest_a["quarantined"],
                        "reason": manifest_a.get("quarantine_reason"),
                        "path": manifest_a.get("quarantine_path"),
                        "safe_prefix": manifest_a.get("safe_prefix", []),
                    },
                    "b": {
                        "quarantined": manifest_b["quarantined"],
                        "reason": manifest_b.get("quarantine_reason"),
                        "path": manifest_b.get("quarantine_path"),
                        "safe_prefix": manifest_b.get("safe_prefix", []),
                    },
                },
            }
        else:
            comparison = compare_manifests(manifest_a, manifest_b, policy_body)
            comparison["quarantine"] = None

        proof = build_proof(manifest_a, manifest_b, policy_body, comparison)
        session = self.storage.create_session(
            archive_a_id,
            archive_b_id,
            policy_name,
            pv["version"],
            comparison,
            proof,
        )
        return {
            "session": session,
            "proof_bytes": proof_bytes(proof).decode("utf-8"),
            "proof_sha256": proof_sha256(proof),
        }

