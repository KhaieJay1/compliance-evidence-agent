import os
import json
import datetime
from typing import List, Dict, Any, Tuple
from .models import (
    EvidenceItem,
    EvidenceManifest,
    AuditPackage,
    ComplianceEvaluation
)
from .collectors import HostEvidenceCollector, CloudEvidenceCollector
from .crypto import (
    compute_manifest_hash,
    verify_evidence_integrity,
    verify_manifest_integrity
)
from .policy_engine import PolicyEngine

DEFAULT_STORE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "evidence_store"
)

class ComplianceEvidenceAgent:
    """
    Continuous Compliance-as-Code Agent.
    Coordinates automated host and cloud evidence collection, cryptographic SHA-256
    chain of custody, Policy-as-Code evaluation, and audit package compilation.
    """
    def __init__(self, store_dir: str = DEFAULT_STORE_DIR, organization: str = "Enterprise FinTech Ltd"):
        self.store_dir = store_dir
        self.organization = organization
        self.host_collector = HostEvidenceCollector()
        self.cloud_collector = CloudEvidenceCollector()
        self.policy_engine = PolicyEngine()
        os.makedirs(self.store_dir, exist_ok=True)

    def collect_all_evidence(self) -> Tuple[EvidenceManifest, List[EvidenceItem]]:
        """Executes host and cloud collectors, calculates hashes, and builds manifest."""
        host_items = self.host_collector.collect_all()
        cloud_items = self.cloud_collector.collect_all()
        all_items = host_items + cloud_items

        root_hash = compute_manifest_hash(all_items)
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        manifest_id = f"MNF-{now_str[:10]}-{root_hash[:8]}"

        manifest = EvidenceManifest(
            manifest_id=manifest_id,
            generated_at=now_str,
            agent_version="1.0.0",
            evidence_count=len(all_items),
            items=all_items,
            manifest_sha256=root_hash
        )

        # Persist manifest to store
        manifest_path = os.path.join(self.store_dir, "evidence_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(manifest.model_dump(), indent=2))

        return manifest, all_items

    def run_audit(self) -> Tuple[AuditPackage, EvidenceManifest]:
        """Runs end-to-end evidence collection, Policy-as-Code evaluation, and packaging."""
        manifest, items = self.collect_all_evidence()
        evaluations = self.policy_engine.evaluate_evidence(items)
        package = self.policy_engine.compile_audit_package(
            items=items,
            evaluations=evaluations,
            organization=self.organization
        )

        # Persist audit package
        pkg_path = os.path.join(self.store_dir, "audit_package.json")
        with open(pkg_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(package.model_dump(), indent=2))

        return package, manifest

    def verify_stored_manifest(self) -> bool:
        """Loads and cryptographically validates the persisted evidence manifest."""
        manifest_path = os.path.join(self.store_dir, "evidence_manifest.json")
        if not os.path.exists(manifest_path):
            raise FileNotFoundError(f"Manifest not found at: {manifest_path}")

        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        manifest = EvidenceManifest(**data)
        return verify_manifest_integrity(manifest)
