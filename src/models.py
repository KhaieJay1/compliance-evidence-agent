from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Union
from enum import Enum

class EvidenceSourceType(str, Enum):
    HOST_SYSTEM = "HOST_SYSTEM"
    AWS_IAM = "AWS_IAM"
    AWS_CLOUDTRAIL = "AWS_CLOUDTRAIL"
    AWS_S3 = "AWS_S3"

class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    MANUAL_REVIEW = "MANUAL_REVIEW"

class EvidenceItem(BaseModel):
    evidence_id: str
    check_id: str
    title: str
    source_type: EvidenceSourceType
    collected_at: str
    resource_id: str
    raw_data: Dict[str, Any]
    sha256_hash: str

class EvidenceManifest(BaseModel):
    manifest_id: str
    generated_at: str
    agent_version: str = "1.0.0"
    evidence_count: int
    items: List[EvidenceItem]
    manifest_sha256: str

class FrameworkMapping(BaseModel):
    check_id: str
    cis_control_id: str
    cis_title: str
    soc2_controls: List[str] = Field(default_factory=list)
    iso27001_controls: List[str] = Field(default_factory=list)
    audit_objective: str

class PolicyRule(BaseModel):
    rule_id: str
    name: str
    check_id: str
    field_path: str
    operator: str  # "equals", "not_equals", "in", "not_in", "greater_than_or_equal", "less_than_or_equal", "is_empty", "is_not_empty"
    expected_value: Any
    severity: str = "HIGH"  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    remediation: str

class ComplianceEvaluation(BaseModel):
    evaluation_id: str
    check_id: str
    rule_id: str
    title: str
    status: CheckStatus
    actual_value: Any
    expected_value: Any
    evidence_id: str
    evidence_hash: str
    soc2_mappings: List[str] = Field(default_factory=list)
    iso27001_mappings: List[str] = Field(default_factory=list)
    finding_details: str
    remediation_steps: Optional[str] = None

class AuditPackage(BaseModel):
    package_id: str
    organization: str
    audit_date: str
    total_checks: int
    passed_checks: int
    failed_checks: int
    warning_checks: int
    compliance_score_percent: float
    manifest_sha256: str
    evaluations: List[ComplianceEvaluation]
