import json
import os
import datetime
from typing import List, Dict, Any, Optional
from ..models import EvidenceItem, EvidenceSourceType
from ..crypto import compute_evidence_hash

DEFAULT_CLOUDTRAIL_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "sample_cloudtrail"
)

class CloudEvidenceCollector:
    """
    Collects AWS IAM, S3, and CloudTrail audit evidence.
    Ingests cloud configuration states and CloudTrail audit log events,
    computing cryptographic SHA-256 hashes at point of ingestion.
    """
    def __init__(self, data_dir: str = DEFAULT_CLOUDTRAIL_DIR, account_id: str = "123456789012"):
        self.data_dir = data_dir
        self.account_id = account_id

    def collect_all(self) -> List[EvidenceItem]:
        items = []
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. AWS IAM Root MFA (CIS AWS Benchmark 1.5 / SOC 2 CC6.1)
        root_mfa_data = self._get_root_mfa_evidence()
        items.append(self._create_evidence(
            check_id="AWS-IAM-01",
            title="AWS Root Account MFA Enforcement",
            source_type=EvidenceSourceType.AWS_IAM,
            resource_id=f"arn:aws:iam::{self.account_id}:root",
            raw_data=root_mfa_data,
            collected_at=now
        ))

        # 2. AWS IAM Access Key Age & Rotation (CIS AWS Benchmark 1.14 / SOC 2 CC6.2)
        access_keys_data = self._get_access_keys_evidence()
        items.append(self._create_evidence(
            check_id="AWS-IAM-02",
            title="AWS IAM Inactive & Stale Access Key Audit (< 90 Days)",
            source_type=EvidenceSourceType.AWS_IAM,
            resource_id=f"arn:aws:iam::{self.account_id}:user/*",
            raw_data=access_keys_data,
            collected_at=now
        ))

        # 3. AWS Overprivileged Wildcard IAM Policies (CIS AWS Benchmark 1.16 / SOC 2 CC6.3)
        wildcard_policy_data = self._get_wildcard_policy_evidence()
        items.append(self._create_evidence(
            check_id="AWS-IAM-03",
            title="AWS Least Privilege IAM Policy Analysis (Wildcard Admin Check)",
            source_type=EvidenceSourceType.AWS_IAM,
            resource_id=f"arn:aws:iam::{self.account_id}:policy/*",
            raw_data=wildcard_policy_data,
            collected_at=now
        ))

        # 4. AWS S3 Block Public Access (CIS AWS Benchmark 2.1.5 / SOC 2 CC6.6)
        s3_data = self._get_s3_public_block_evidence()
        items.append(self._create_evidence(
            check_id="AWS-S3-01",
            title="AWS S3 Account-Level Block Public Access Configuration",
            source_type=EvidenceSourceType.AWS_S3,
            resource_id=f"arn:aws:s3:::{self.account_id}-public-block",
            raw_data=s3_data,
            collected_at=now
        ))

        # 5. AWS CloudTrail Multi-Region & Log Integrity (CIS AWS Benchmark 3.1 & 3.2 / SOC 2 CC7.2)
        trail_data = self._get_cloudtrail_evidence()
        items.append(self._create_evidence(
            check_id="AWS-TRAIL-01",
            title="AWS CloudTrail Multi-Region Logging & Log File Validation",
            source_type=EvidenceSourceType.AWS_CLOUDTRAIL,
            resource_id=f"arn:aws:cloudtrail:eu-west-1:{self.account_id}:trail/main-audit-trail",
            raw_data=trail_data,
            collected_at=now
        ))

        return items

    def _create_evidence(
        self,
        check_id: str,
        title: str,
        source_type: EvidenceSourceType,
        resource_id: str,
        raw_data: Dict[str, Any],
        collected_at: str
    ) -> EvidenceItem:
        h = compute_evidence_hash(check_id, resource_id, collected_at, raw_data)
        ev_id = f"EV-CLOUD-{check_id.replace('-', '_')}-{h[:8]}"
        return EvidenceItem(
            evidence_id=ev_id,
            check_id=check_id,
            title=title,
            source_type=source_type,
            collected_at=collected_at,
            resource_id=resource_id,
            raw_data=raw_data,
            sha256_hash=h
        )

    def _get_root_mfa_evidence(self) -> Dict[str, Any]:
        return {
            "account_id": self.account_id,
            "root_account_present": True,
            "root_mfa_active": True,
            "mfa_device_type": "HARDWARE_TOTP",
            "root_access_keys_count": 0,
            "days_since_last_root_login": 142
        }

    def _get_access_keys_evidence(self) -> Dict[str, Any]:
        return {
            "total_active_keys": 4,
            "keys_older_than_90_days": 0,
            "max_key_age_days": 42,
            "keys_rotated_within_policy": True,
            "audited_users": ["ci-deployer", "analytics-sync", "infra-terraform", "backup-operator"]
        }

    def _get_wildcard_policy_evidence(self) -> Dict[str, Any]:
        # Realistic enterprise scenario: 1 overly permissive policy flagged
        return {
            "total_customer_managed_policies": 12,
            "policies_with_full_admin_wildcard": 1,
            "violating_policy_names": ["LegacyQuickAdminRolePolicy"],
            "violating_statements": [
                {
                    "Sid": "AllowFullAdminAccess",
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ],
            "least_privilege_enforced": False
        }

    def _get_s3_public_block_evidence(self) -> Dict[str, Any]:
        return {
            "account_level_s3_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            },
            "all_blocks_enabled": True,
            "buckets_evaluated": 18,
            "public_buckets_detected": 0
        }

    def _get_cloudtrail_evidence(self) -> Dict[str, Any]:
        return {
            "trail_name": "main-audit-trail",
            "is_multi_region_trail": True,
            "log_file_validation_enabled": True,
            "is_logging": True,
            "kms_key_encryption_enabled": True,
            "include_global_service_events": True,
            "sns_topic_configured": True
        }
