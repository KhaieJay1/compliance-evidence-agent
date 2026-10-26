import pytest
import os
from src.agent import ComplianceEvidenceAgent
from src.models import CheckStatus

def test_agent_end_to_end_audit(test_agent):
    package, manifest = test_agent.run_audit()

    assert package.total_checks == 11
    assert package.passed_checks >= 9
    assert package.compliance_score_percent > 80.0
    assert len(package.manifest_sha256) == 64
    assert len(manifest.items) == 11

    # Verify manifest file was written
    manifest_path = os.path.join(test_agent.store_dir, "evidence_manifest.json")
    assert os.path.exists(manifest_path)

    # Verify stored manifest integrity
    assert test_agent.verify_stored_manifest() is True
