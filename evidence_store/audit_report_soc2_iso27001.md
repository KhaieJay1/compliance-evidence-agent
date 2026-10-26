# SOC 2 & ISO 27001 Continuous Compliance Audit Package
**Organization:** `Enterprise FinTech Ltd` | **Audit Timestamp:** `2026-10-26 09:30:17 UTC`
**Audit Package ID:** `AUDIT-PKG-2026-10-26-bfa3ff8c`
**Cryptographic Manifest Root Hash (SHA-256):**  
`bfa3ff8c69cf97147ce8b9a1bc7539ed5910d9a914e14002e1234ff0772d42e6`

---

## 1. Executive Summary & Audit Scorecard
| Metric | Value |
|---|---|
| **Overall Compliance Score** | **90.9%** |
| **Total Policy Controls Evaluated** | 11 |
| **Passed Controls** | 10 (Conforming) |
| **Failed Controls** | 1 (Deficiencies Found) |
| **Evidence Integrity Chain** | **100% Cryptographically Verified (SHA-256)** |

---

## 2. Control Evaluation & Cryptographic Evidence Lineage

### 1. `CIS-HOST-1.1`: Host Firewall All Profiles Active
- **Evaluation Status:** `[PASS] COMPLIANT`
- **Framework Crosswalk:** **SOC 2 Type II:** `CC6.6` | **ISO/IEC 27001:2022:** `A.8.20, A.8.23`
- **Evidence Lineage ID:** `EV-HOST-CIS-HOST-1_1-f99d05e3`
- **Cryptographic SHA-256 Hash:** `f99d05e345d7e55c5f56cb3744988a93b307792c09571a91fa62a74652ea7202`
- **Auditor Finding:** Compliance verified: Host Firewall All Profiles Active satisfied. Actual value (True) meets requirement.

### 2. `CIS-HOST-1.2`: System Disk Encryption Enforced
- **Evaluation Status:** `[PASS] COMPLIANT`
- **Framework Crosswalk:** **SOC 2 Type II:** `CC6.1, CC6.7` | **ISO/IEC 27001:2022:** `A.8.24, A.8.1`
- **Evidence Lineage ID:** `EV-HOST-CIS-HOST-1_2-3f8c211d`
- **Cryptographic SHA-256 Hash:** `3f8c211d09d66bce9b7a8229aad99f94d49888e708be3b155d42e88e73f1153f`
- **Auditor Finding:** Compliance verified: System Disk Encryption Enforced satisfied. Actual value (True) meets requirement.

### 3. `CIS-HOST-1.3`: Screen Inactivity Timeout <= 15 Minutes
- **Evaluation Status:** `[PASS] COMPLIANT`
- **Framework Crosswalk:** **SOC 2 Type II:** `CC6.1` | **ISO/IEC 27001:2022:** `A.7.7, A.8.1`
- **Evidence Lineage ID:** `EV-HOST-CIS-HOST-1_3-d7164058`
- **Cryptographic SHA-256 Hash:** `d7164058a93991ae34fa2746a68b713de3bf5dfa821f200f4c290ebf6f78213e`
- **Auditor Finding:** Compliance verified: Screen Inactivity Timeout <= 15 Minutes satisfied. Actual value (600) meets requirement.

### 4. `CIS-HOST-1.4`: EDR Anti-Malware Real-Time Protection Active
- **Evaluation Status:** `[PASS] COMPLIANT`
- **Framework Crosswalk:** **SOC 2 Type II:** `CC6.8` | **ISO/IEC 27001:2022:** `A.8.7`
- **Evidence Lineage ID:** `EV-HOST-CIS-HOST-1_4-53b5b879`
- **Cryptographic SHA-256 Hash:** `53b5b879c092614b74ef6308c54c3756e2d90902a04cde9f6426591fd2395acb`
- **Auditor Finding:** Compliance verified: EDR Anti-Malware Real-Time Protection Active satisfied. Actual value (True) meets requirement.

### 5. `CIS-HOST-1.5`: Operating System Supported & Updates Active
- **Evaluation Status:** `[PASS] COMPLIANT`
- **Framework Crosswalk:** **SOC 2 Type II:** `CC7.1` | **ISO/IEC 27001:2022:** `A.8.8`
- **Evidence Lineage ID:** `EV-HOST-CIS-HOST-1_5-e5de22cb`
- **Cryptographic SHA-256 Hash:** `e5de22cb4dda33f17fa574ba0b25296b4e5a6d34a038edd5286163afab354d56`
- **Auditor Finding:** Compliance verified: Operating System Supported & Updates Active satisfied. Actual value (True) meets requirement.

### 6. `CIS-HOST-1.6`: Password Policy Minimum Length >= 12
- **Evaluation Status:** `[PASS] COMPLIANT`
- **Framework Crosswalk:** **SOC 2 Type II:** `CC6.1` | **ISO/IEC 27001:2022:** `A.5.17, A.8.5`
- **Evidence Lineage ID:** `EV-HOST-CIS-HOST-1_6-9848be24`
- **Cryptographic SHA-256 Hash:** `9848be24fecd55d8b29cb009b0a24120cac4e2edab73a13034eeb26d1c02476f`
- **Auditor Finding:** Compliance verified: Password Policy Minimum Length >= 12 satisfied. Actual value (14) meets requirement.

### 7. `AWS-IAM-01`: AWS Root Account MFA Enforced
- **Evaluation Status:** `[PASS] COMPLIANT`
- **Framework Crosswalk:** **SOC 2 Type II:** `CC6.1, CC6.2` | **ISO/IEC 27001:2022:** `A.8.2, A.8.5`
- **Evidence Lineage ID:** `EV-CLOUD-AWS_IAM_01-fcf6d54f`
- **Cryptographic SHA-256 Hash:** `fcf6d54f28a7da50a2dd2de1a3127fcf7f52aefaf65b423e4764baa4808c0c7f`
- **Auditor Finding:** Compliance verified: AWS Root Account MFA Enforced satisfied. Actual value (True) meets requirement.

### 8. `AWS-IAM-02`: IAM Access Key Age <= 90 Days
- **Evaluation Status:** `[PASS] COMPLIANT`
- **Framework Crosswalk:** **SOC 2 Type II:** `CC6.2` | **ISO/IEC 27001:2022:** `A.8.5`
- **Evidence Lineage ID:** `EV-CLOUD-AWS_IAM_02-55edf760`
- **Cryptographic SHA-256 Hash:** `55edf760f0dbc9ab905d451eea8ed11c8cd375e32d2dc9a8fa91f1dfe6a8f015`
- **Auditor Finding:** Compliance verified: IAM Access Key Age <= 90 Days satisfied. Actual value (0) meets requirement.

### 9. `AWS-IAM-03`: Least Privilege Enforcement - No Wildcard Admin Policies
- **Evaluation Status:** `[FAIL] NON-COMPLIANT`
- **Framework Crosswalk:** **SOC 2 Type II:** `CC6.3` | **ISO/IEC 27001:2022:** `A.5.15, A.8.2`
- **Evidence Lineage ID:** `EV-CLOUD-AWS_IAM_03-0b79d2d9`
- **Cryptographic SHA-256 Hash:** `0b79d2d9f85f82045dfb0dcc5d95acd34a2a85793b4fe796f66e6cfe127d1a78`
- **Auditor Finding:** NON-COMPLIANCE DETECTED: Least Privilege Enforcement - No Wildcard Admin Policies failed. Actual value: 1, Expected: equals 0.
- **Remediation Action Required:**
  > [!IMPORTANT]
  > Refactor violating IAM policies into scoped, role-based micro-permissions according to least privilege.

### 10. `AWS-S3-01`: S3 Account-Level Public Access Block
- **Evaluation Status:** `[PASS] COMPLIANT`
- **Framework Crosswalk:** **SOC 2 Type II:** `CC6.6` | **ISO/IEC 27001:2022:** `A.8.12, A.8.20`
- **Evidence Lineage ID:** `EV-CLOUD-AWS_S3_01-423ecd41`
- **Cryptographic SHA-256 Hash:** `423ecd410923b7b3137b151847dfb41ca3a603c8c72bb5a88f754c0b227ccbda`
- **Auditor Finding:** Compliance verified: S3 Account-Level Public Access Block satisfied. Actual value (True) meets requirement.

### 11. `AWS-TRAIL-01`: CloudTrail Multi-Region Log Validation Active
- **Evaluation Status:** `[PASS] COMPLIANT`
- **Framework Crosswalk:** **SOC 2 Type II:** `CC7.2` | **ISO/IEC 27001:2022:** `A.8.15, A.8.16`
- **Evidence Lineage ID:** `EV-CLOUD-AWS_TRAIL_01-810ab68d`
- **Cryptographic SHA-256 Hash:** `810ab68d191c64cd4bb518cb67ee30644eb6877b7fefc79d052af6b7fc44b665`
- **Auditor Finding:** Compliance verified: CloudTrail Multi-Region Log Validation Active satisfied. Actual value (True) meets requirement.

---

## 3. Cryptographic Chain of Custody Statement
All underlying technical evidence artifacts in this package were captured in runtime, serialized into canonical JSON, and cryptographically hashed using SHA-256 at point of collection. Any modification of operating system configuration, cloud log entries, or evaluation parameters invalidates the manifest root hash.

*Compiled automatically by Compliance-as-Code Evidence Agent.*