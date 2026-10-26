import pytest
from src.policy_engine import PolicyEngine
from src.models import EvidenceItem, EvidenceSourceType, CheckStatus
from src.crypto import compute_evidence_hash

def test_policy_engine_pass():
    engine = PolicyEngine()
    raw = {"firewall_service_running": True}
    h = compute_evidence_hash("CIS-HOST-1.1", "host-01", "2026-10-20", raw)
    item = EvidenceItem(
        evidence_id="E-1", check_id="CIS-HOST-1.1", title="Firewall",
        source_type=EvidenceSourceType.HOST_SYSTEM, collected_at="2026-10-20",
        resource_id="host-01", raw_data=raw, sha256_hash=h
    )

    evals = engine.evaluate_evidence([item])
    assert len(evals) == 1
    assert evals[0].status == CheckStatus.PASS
    assert evals[0].evidence_hash == h
    assert "CC6.6" in evals[0].soc2_mappings

def test_policy_engine_fail_wildcard_admin():
    engine = PolicyEngine()
    raw = {"policies_with_full_admin_wildcard": 2}
    h = compute_evidence_hash("AWS-IAM-03", "arn:aws:iam::123:policy", "2026-10-20", raw)
    item = EvidenceItem(
        evidence_id="E-2", check_id="AWS-IAM-03", title="Wildcard Admin",
        source_type=EvidenceSourceType.AWS_IAM, collected_at="2026-10-20",
        resource_id="arn:aws:iam::123:policy", raw_data=raw, sha256_hash=h
    )

    evals = engine.evaluate_evidence([item])
    assert len(evals) == 1
    assert evals[0].status == CheckStatus.FAIL
    assert evals[0].remediation_steps is not None
    assert "CC6.3" in evals[0].soc2_mappings
