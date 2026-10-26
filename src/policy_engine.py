import json
import os
from typing import List, Dict, Any, Optional
from .models import (
    EvidenceItem,
    PolicyRule,
    ComplianceEvaluation,
    CheckStatus,
    AuditPackage
)
from .mapper import ComplianceMapper
from .crypto import compute_manifest_hash

DEFAULT_POLICIES: List[PolicyRule] = [
    # Host Security Policies
    PolicyRule(
        rule_id="POL-HOST-01",
        name="Host Firewall All Profiles Active",
        check_id="CIS-HOST-1.1",
        field_path="firewall_service_running",
        operator="equals",
        expected_value=True,
        severity="CRITICAL",
        description="Host personal firewall must be active and enforcing rules across all network profiles.",
        remediation="Enable Windows Defender Firewall or host iptables service and apply baseline profile configuration."
    ),
    PolicyRule(
        rule_id="POL-HOST-02",
        name="System Disk Encryption Enforced",
        check_id="CIS-HOST-1.2",
        field_path="bitlocker_enabled",
        operator="equals",
        expected_value=True,
        severity="CRITICAL",
        description="Operating system boot drive must be encrypted with BitLocker or LUKS using AES-256.",
        remediation="Enable BitLocker on C: drive via Group Policy or Intune endpoint management."
    ),
    PolicyRule(
        rule_id="POL-HOST-03",
        name="Screen Inactivity Timeout <= 15 Minutes",
        check_id="CIS-HOST-1.3",
        field_path="inactivity_timeout_seconds",
        operator="less_than_or_equal",
        expected_value=900,
        severity="HIGH",
        description="Unattended workstations must lock automatically after 15 minutes (900 seconds) or less.",
        remediation="Configure screen saver lock policy to <= 900 seconds via Intune or GPO."
    ),
    PolicyRule(
        rule_id="POL-HOST-04",
        name="EDR Anti-Malware Real-Time Protection Active",
        check_id="CIS-HOST-1.4",
        field_path="realtime_protection_enabled",
        operator="equals",
        expected_value=True,
        severity="CRITICAL",
        description="Endpoint detection and response (EDR) agent must maintain active real-time protection.",
        remediation="Enable real-time monitoring and update anti-malware signatures on the host."
    ),
    PolicyRule(
        rule_id="POL-HOST-05",
        name="Operating System Supported & Updates Active",
        check_id="CIS-HOST-1.5",
        field_path="automatic_updates_enabled",
        operator="equals",
        expected_value=True,
        severity="HIGH",
        description="OS must have automatic security patching active and run a supported release.",
        remediation="Enable automatic Windows Update service or configure centralized WSUS/patch cadence."
    ),
    PolicyRule(
        rule_id="POL-HOST-06",
        name="Password Policy Minimum Length >= 12",
        check_id="CIS-HOST-1.6",
        field_path="minimum_password_length",
        operator="greater_than_or_equal",
        expected_value=12,
        severity="HIGH",
        description="Local password policy must enforce a minimum length of at least 12 characters.",
        remediation="Update local or Active Directory group policy password minimum length to >= 12."
    ),

    # Cloud & IAM Security Policies
    PolicyRule(
        rule_id="POL-AWS-01",
        name="AWS Root Account MFA Enforced",
        check_id="AWS-IAM-01",
        field_path="root_mfa_active",
        operator="equals",
        expected_value=True,
        severity="CRITICAL",
        description="AWS account root user must be protected with hardware or virtual MFA.",
        remediation="Log into AWS console as root and activate virtual or hardware FIDO2 MFA device."
    ),
    PolicyRule(
        rule_id="POL-AWS-02",
        name="IAM Access Key Age <= 90 Days",
        check_id="AWS-IAM-02",
        field_path="keys_older_than_90_days",
        operator="equals",
        expected_value=0,
        severity="HIGH",
        description="No active IAM programmatic access keys may exceed 90 days without rotation.",
        remediation="Rotate active credentials via AWS IAM console or CLI and deactivate stale keys."
    ),
    PolicyRule(
        rule_id="POL-AWS-03",
        name="Least Privilege Enforcement - No Wildcard Admin Policies",
        check_id="AWS-IAM-03",
        field_path="policies_with_full_admin_wildcard",
        operator="equals",
        expected_value=0,
        severity="CRITICAL",
        description="Customer managed IAM policies must not grant Action: * on Resource: * without explicit boundary.",
        remediation="Refactor violating IAM policies into scoped, role-based micro-permissions according to least privilege."
    ),
    PolicyRule(
        rule_id="POL-AWS-04",
        name="S3 Account-Level Public Access Block",
        check_id="AWS-S3-01",
        field_path="all_blocks_enabled",
        operator="equals",
        expected_value=True,
        severity="CRITICAL",
        description="All 4 Amazon S3 account-level public access block settings must be enabled.",
        remediation="Execute aws s3control put-public-access-block to enforce account-wide S3 boundaries."
    ),
    PolicyRule(
        rule_id="POL-AWS-05",
        name="CloudTrail Multi-Region Log Validation Active",
        check_id="AWS-TRAIL-01",
        field_path="log_file_validation_enabled",
        operator="equals",
        expected_value=True,
        severity="CRITICAL",
        description="AWS CloudTrail must be active across all regions with cryptographic log file validation.",
        remediation="Enable log file validation on the multi-region CloudTrail configuration."
    )
]

class PolicyEngine:
    """
    Policy-as-Code Rule Engine.
    Evaluates evidence payloads against declarative compliance rules,
    linking cryptographic evidence hashes directly to SOC 2 & ISO 27001 findings.
    """
    def __init__(self, rules: Optional[List[PolicyRule]] = None):
        self.rules = rules or DEFAULT_POLICIES

    def evaluate_evidence(self, items: List[EvidenceItem]) -> List[ComplianceEvaluation]:
        items_by_check: Dict[str, EvidenceItem] = {item.check_id: item for item in items}
        evaluations: List[ComplianceEvaluation] = []

        for rule in self.rules:
            item = items_by_check.get(rule.check_id)
            if not item:
                continue

            mapping = ComplianceMapper.get_mapping(rule.check_id)
            soc2_ctrls = mapping.soc2_controls if mapping else []
            iso_ctrls = mapping.iso27001_controls if mapping else []

            # Extract actual value from nested or top-level path
            actual_val = self._extract_value(item.raw_data, rule.field_path)
            passed = self._test_condition(actual_val, rule.operator, rule.expected_value)

            status = CheckStatus.PASS if passed else CheckStatus.FAIL
            eval_id = f"EVAL-{rule.rule_id}-{item.sha256_hash[:8]}"

            if passed:
                finding = f"Compliance verified: {rule.name} satisfied. Actual value ({actual_val}) meets requirement."
                remediation = None
            else:
                finding = (
                    f"NON-COMPLIANCE DETECTED: {rule.name} failed. "
                    f"Actual value: {actual_val}, Expected: {rule.operator} {rule.expected_value}."
                )
                remediation = rule.remediation

            evaluations.append(ComplianceEvaluation(
                evaluation_id=eval_id,
                check_id=rule.check_id,
                rule_id=rule.rule_id,
                title=rule.name,
                status=status,
                actual_value=actual_val,
                expected_value=rule.expected_value,
                evidence_id=item.evidence_id,
                evidence_hash=item.sha256_hash,
                soc2_mappings=soc2_ctrls,
                iso27001_mappings=iso_ctrls,
                finding_details=finding,
                remediation_steps=remediation
            ))

        return evaluations

    def compile_audit_package(
        self,
        items: List[EvidenceItem],
        evaluations: List[ComplianceEvaluation],
        organization: str = "Enterprise FinTech Ltd"
    ) -> AuditPackage:
        manifest_hash = compute_manifest_hash(items)
        passed = sum(1 for e in evaluations if e.status == CheckStatus.PASS)
        failed = sum(1 for e in evaluations if e.status == CheckStatus.FAIL)
        warning = sum(1 for e in evaluations if e.status == CheckStatus.WARNING)
        total = len(evaluations)
        score = round((passed / max(total, 1)) * 100.0, 1)

        import datetime
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        return AuditPackage(
            package_id=f"AUDIT-PKG-{now_str[:10]}-{manifest_hash[:8]}",
            organization=organization,
            audit_date=now_str,
            total_checks=total,
            passed_checks=passed,
            failed_checks=failed,
            warning_checks=warning,
            compliance_score_percent=score,
            manifest_sha256=manifest_hash,
            evaluations=evaluations
        )

    def _extract_value(self, data: Dict[str, Any], path: str) -> Any:
        keys = path.split(".")
        current = data
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return None
        return current

    def _test_condition(self, actual: Any, operator: str, expected: Any) -> bool:
        if actual is None:
            return False
        if operator == "equals":
            return actual == expected
        elif operator == "not_equals":
            return actual != expected
        elif operator == "greater_than_or_equal":
            return actual >= expected
        elif operator == "less_than_or_equal":
            return actual <= expected
        elif operator == "in":
            return actual in expected
        elif operator == "not_in":
            return actual not in expected
        elif operator == "is_empty":
            return len(actual) == 0
        elif operator == "is_not_empty":
            return len(actual) > 0
        return False
