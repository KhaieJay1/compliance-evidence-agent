from typing import Dict, List, Optional
from .models import FrameworkMapping

FRAMEWORK_MAPPINGS: Dict[str, FrameworkMapping] = {
    "CIS-HOST-1.1": FrameworkMapping(
        check_id="CIS-HOST-1.1",
        cis_control_id="CIS-v8-4.4",
        cis_title="Establish and Maintain a Host Firewall on Endpoints",
        soc2_controls=["CC6.6"],
        iso27001_controls=["A.8.20", "A.8.23"],
        audit_objective="Verify host firewall service is active on domain, private, and public network profiles with inbound blocking."
    ),
    "CIS-HOST-1.2": FrameworkMapping(
        check_id="CIS-HOST-1.2",
        cis_control_id="CIS-v8-3.11",
        cis_title="Encrypt Sensitive Data on End-User Devices",
        soc2_controls=["CC6.1", "CC6.7"],
        iso27001_controls=["A.8.24", "A.8.1"],
        audit_objective="Verify full disk volume encryption (BitLocker/LUKS) with AES-256 enabled on OS boot partition."
    ),
    "CIS-HOST-1.3": FrameworkMapping(
        check_id="CIS-HOST-1.3",
        cis_control_id="CIS-v8-4.10",
        cis_title="Enforce Automatic Session Lock on Inactive Endpoints",
        soc2_controls=["CC6.1"],
        iso27001_controls=["A.7.7", "A.8.1"],
        audit_objective="Ensure workstation locks session automatically after <= 15 minutes of inactivity."
    ),
    "CIS-HOST-1.4": FrameworkMapping(
        check_id="CIS-HOST-1.4",
        cis_control_id="CIS-v8-10.1",
        cis_title="Deploy and Maintain Anti-Malware and EDR Software",
        soc2_controls=["CC6.8"],
        iso27001_controls=["A.8.7"],
        audit_objective="Ensure active real-time anti-malware and behavior monitoring protection is running with updated signatures."
    ),
    "CIS-HOST-1.5": FrameworkMapping(
        check_id="CIS-HOST-1.5",
        cis_control_id="CIS-v8-7.1",
        cis_title="Establish Operating System Vulnerability and Patch Currency",
        soc2_controls=["CC7.1"],
        iso27001_controls=["A.8.8"],
        audit_objective="Verify operating system build is vendor-supported with automatic security patch delivery enabled."
    ),
    "CIS-HOST-1.6": FrameworkMapping(
        check_id="CIS-HOST-1.6",
        cis_control_id="CIS-v8-5.2",
        cis_title="Enforce Strong Password and Account Lockout Standards",
        soc2_controls=["CC6.1"],
        iso27001_controls=["A.5.17", "A.8.5"],
        audit_objective="Validate minimum password length >= 12, history enforcement >= 24, and account lockout threshold."
    ),
    "AWS-IAM-01": FrameworkMapping(
        check_id="AWS-IAM-01",
        cis_control_id="CIS-AWS-1.5",
        cis_title="Ensure MFA is Enabled for the Root Account",
        soc2_controls=["CC6.1", "CC6.2"],
        iso27001_controls=["A.8.2", "A.8.5"],
        audit_objective="Verify AWS root account is secured with multi-factor authentication (MFA) and has zero active API access keys."
    ),
    "AWS-IAM-02": FrameworkMapping(
        check_id="AWS-IAM-02",
        cis_control_id="CIS-AWS-1.14",
        cis_title="Ensure Access Keys are Rotated Every 90 Days or Less",
        soc2_controls=["CC6.2"],
        iso27001_controls=["A.8.5"],
        audit_objective="Ensure all active IAM user credentials and programmatic access keys are rotated within 90 days."
    ),
    "AWS-IAM-03": FrameworkMapping(
        check_id="AWS-IAM-03",
        cis_control_id="CIS-AWS-1.16",
        cis_title="Ensure IAM Policies Enforce Least Privilege (No Full Admin Wildcards)",
        soc2_controls=["CC6.3"],
        iso27001_controls=["A.5.15", "A.8.2"],
        audit_objective="Audit customer managed policies to prevent overly permissive Action: * on Resource: * wildcards."
    ),
    "AWS-S3-01": FrameworkMapping(
        check_id="AWS-S3-01",
        cis_control_id="CIS-AWS-2.1.5",
        cis_title="Ensure S3 Block Public Access Setting is Enabled at Account Level",
        soc2_controls=["CC6.6"],
        iso27001_controls=["A.8.12", "A.8.20"],
        audit_objective="Ensure all 4 S3 Block Public Access settings are active at the AWS account root level."
    ),
    "AWS-TRAIL-01": FrameworkMapping(
        check_id="AWS-TRAIL-01",
        cis_control_id="CIS-AWS-3.1",
        cis_title="Ensure CloudTrail is Enabled Across All Regions with Log File Validation",
        soc2_controls=["CC7.2"],
        iso27001_controls=["A.8.15", "A.8.16"],
        audit_objective="Verify immutable multi-region audit logging with cryptographic SHA-256 log file integrity validation active."
    )
}

class ComplianceMapper:
    """Resolves check IDs into authoritative CIS, SOC 2, and ISO 27001 control mappings."""

    @staticmethod
    def get_mapping(check_id: str) -> Optional[FrameworkMapping]:
        return FRAMEWORK_MAPPINGS.get(check_id)

    @staticmethod
    def get_all_mappings() -> List[FrameworkMapping]:
        return list(FRAMEWORK_MAPPINGS.values())

    @staticmethod
    def get_soc2_coverage() -> Dict[str, List[str]]:
        coverage: Dict[str, List[str]] = {}
        for m in FRAMEWORK_MAPPINGS.values():
            for sc in m.soc2_controls:
                coverage.setdefault(sc, []).append(m.check_id)
        return coverage

    @staticmethod
    def get_iso27001_coverage() -> Dict[str, List[str]]:
        coverage: Dict[str, List[str]] = {}
        for m in FRAMEWORK_MAPPINGS.values():
            for ic in m.iso27001_controls:
                coverage.setdefault(ic, []).append(m.check_id)
        return coverage
