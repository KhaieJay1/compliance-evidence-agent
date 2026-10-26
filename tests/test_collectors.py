import pytest
from src.collectors import HostEvidenceCollector, CloudEvidenceCollector
from src.crypto import verify_evidence_integrity
from src.models import EvidenceSourceType

def test_host_collector_all_checks():
    collector = HostEvidenceCollector(hostname="test-host")
    items = collector.collect_all()
    
    assert len(items) == 6
    check_ids = [i.check_id for i in items]
    assert "CIS-HOST-1.1" in check_ids
    assert "CIS-HOST-1.2" in check_ids
    assert "CIS-HOST-1.3" in check_ids
    assert "CIS-HOST-1.4" in check_ids
    assert "CIS-HOST-1.5" in check_ids
    assert "CIS-HOST-1.6" in check_ids

    # Every item must have a valid cryptographic hash matching its payload
    for item in items:
        assert item.source_type == EvidenceSourceType.HOST_SYSTEM
        assert len(item.sha256_hash) == 64
        assert verify_evidence_integrity(item) is True

def test_cloud_collector_all_checks():
    collector = CloudEvidenceCollector(account_id="999888777666")
    items = collector.collect_all()

    assert len(items) == 5
    check_ids = [i.check_id for i in items]
    assert "AWS-IAM-01" in check_ids
    assert "AWS-IAM-02" in check_ids
    assert "AWS-IAM-03" in check_ids
    assert "AWS-S3-01" in check_ids
    assert "AWS-TRAIL-01" in check_ids

    for item in items:
        assert len(item.sha256_hash) == 64
        assert verify_evidence_integrity(item) is True
