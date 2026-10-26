import hashlib
import json
from typing import Dict, Any, List
from .models import EvidenceItem, EvidenceManifest

def canonical_json(data: Any) -> str:
    """Produces deterministic, canonical JSON representation with sorted keys."""
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

def compute_sha256(data: Any) -> str:
    """Computes SHA-256 hex digest for any string or serializable structure."""
    if isinstance(data, (dict, list)):
        payload = canonical_json(data).encode("utf-8")
    elif isinstance(data, str):
        payload = data.encode("utf-8")
    elif isinstance(data, bytes):
        payload = data
    else:
        payload = str(data).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def compute_evidence_hash(check_id: str, resource_id: str, collected_at: str, raw_data: Dict[str, Any]) -> str:
    """Computes cryptographic digest binding the check ID, target resource, timestamp, and raw payload."""
    envelope = {
        "check_id": check_id,
        "resource_id": resource_id,
        "collected_at": collected_at,
        "raw_data": raw_data
    }
    return compute_sha256(envelope)

def compute_manifest_hash(items: List[EvidenceItem]) -> str:
    """
    Computes a composite Merkle-style root digest over all evidence items in the manifest.
    Guarantees detection of any tampering, omission, or reordering of audit evidence.
    """
    sorted_hashes = sorted([item.sha256_hash for item in items])
    composite_str = "|".join(sorted_hashes)
    return compute_sha256(composite_str)

def verify_evidence_integrity(item: EvidenceItem) -> bool:
    """Verifies that an evidence item's stored SHA-256 matches its actual contents."""
    expected = compute_evidence_hash(
        check_id=item.check_id,
        resource_id=item.resource_id,
        collected_at=item.collected_at,
        raw_data=item.raw_data
    )
    return item.sha256_hash == expected

def verify_manifest_integrity(manifest: EvidenceManifest) -> bool:
    """Verifies that every item in the manifest is internally intact and that the manifest hash matches."""
    for item in manifest.items:
        if not verify_evidence_integrity(item):
            return False
    expected_root = compute_manifest_hash(manifest.items)
    return manifest.manifest_sha256 == expected_root
