import pytest
from src.crypto import (
    canonical_json,
    compute_sha256,
    compute_evidence_hash,
    compute_manifest_hash,
    verify_evidence_integrity,
    verify_manifest_integrity
)
from src.models import EvidenceItem, EvidenceSourceType, EvidenceManifest

def test_canonical_json_key_order_invariance():
    d1 = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
    d2 = {"a": 2, "z": 1, "m": {"a": 4, "b": 3}}
    assert canonical_json(d1) == canonical_json(d2)

def test_sha256_computation():
    res = compute_sha256("test-string")
    assert isinstance(res, str)
    assert len(res) == 64

def test_evidence_integrity_tamper_detection():
    raw = {"firewall_enabled": True, "profiles": ["Domain", "Private"]}
    h = compute_evidence_hash("CIS-HOST-1.1", "host-01", "2026-10-20T00:00:00Z", raw)

    item = EvidenceItem(
        evidence_id="EV-01",
        check_id="CIS-HOST-1.1",
        title="Firewall Status",
        source_type=EvidenceSourceType.HOST_SYSTEM,
        collected_at="2026-10-20T00:00:00Z",
        resource_id="host-01",
        raw_data=raw,
        sha256_hash=h
    )

    # Valid check
    assert verify_evidence_integrity(item) is True

    # Tampering with 1 byte in raw_data
    tampered_item = item.model_copy(deep=True)
    tampered_item.raw_data["firewall_enabled"] = False
    assert verify_evidence_integrity(tampered_item) is False

def test_manifest_merkle_root_integrity():
    raw1 = {"key": "val1"}
    h1 = compute_evidence_hash("CHK-1", "res-1", "2026-10-20", raw1)
    item1 = EvidenceItem(
        evidence_id="E-1", check_id="CHK-1", title="T1",
        source_type=EvidenceSourceType.HOST_SYSTEM, collected_at="2026-10-20",
        resource_id="res-1", raw_data=raw1, sha256_hash=h1
    )

    raw2 = {"key": "val2"}
    h2 = compute_evidence_hash("CHK-2", "res-2", "2026-10-20", raw2)
    item2 = EvidenceItem(
        evidence_id="E-2", check_id="CHK-2", title="T2",
        source_type=EvidenceSourceType.AWS_IAM, collected_at="2026-10-20",
        resource_id="res-2", raw_data=raw2, sha256_hash=h2
    )

    root_hash = compute_manifest_hash([item1, item2])
    manifest = EvidenceManifest(
        manifest_id="MNF-01",
        generated_at="2026-10-20",
        evidence_count=2,
        items=[item1, item2],
        manifest_sha256=root_hash
    )

    assert verify_manifest_integrity(manifest) is True

    # Tampered root hash
    manifest_tampered = manifest.model_copy(deep=True)
    manifest_tampered.manifest_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
    assert verify_manifest_integrity(manifest_tampered) is False
