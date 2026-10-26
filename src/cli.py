import argparse
import sys
import os
from tabulate import tabulate
from .agent import ComplianceEvidenceAgent
from .mapper import ComplianceMapper
from .reporter import AuditReporter

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compliance-as-Code Evidence Agent - Automated Audit & Cryptographic Chain of Custody",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: collect
    subparsers.add_parser("collect", help="Collect raw host and cloud security evidence with SHA-256 hashing")

    # Command: evaluate
    eval_p = subparsers.add_parser("evaluate", help="Execute Policy-as-Code audit evaluation and generate compliance package")
    eval_p.add_argument("--output", "-o", choices=["terminal", "markdown", "json"], default="terminal", help="Output format")
    eval_p.add_argument("--save", "-s", help="Save audit package to specified file path")
    eval_p.add_argument("--org", default="Enterprise FinTech Ltd", help="Organization name for audit report")

    # Command: verify
    subparsers.add_parser("verify", help="Cryptographically verify stored evidence manifest SHA-256 chain of custody")

    # Command: mappings
    subparsers.add_parser("mappings", help="Display CIS Benchmarks to SOC 2 Type II and ISO 27001:2022 crosswalk")

    # Command: stats
    subparsers.add_parser("stats", help="Display agent collection coverage and policy metrics")

    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    agent = ComplianceEvidenceAgent()

    if args.command == "collect":
        print("\nExecuting continuous evidence collection (Host CIS + AWS CloudTrail/IAM)...")
        manifest, items = agent.collect_all_evidence()
        print(f"\n[+] Successfully collected {len(items)} evidence artifacts with SHA-256 digests.")
        print(f"Manifest ID:   {manifest.manifest_id}")
        print(f"Manifest Root: {manifest.manifest_sha256}\n")

        rows = []
        for it in items:
            rows.append([
                it.check_id,
                it.source_type.value,
                it.title[:38],
                it.sha256_hash[:12] + "..."
            ])
        print(tabulate(rows, headers=["Check ID", "Source Type", "Evidence Title", "SHA-256 Digest"], tablefmt="grid"))
        print(f"\nManifest saved to: {os.path.join(agent.store_dir, 'evidence_manifest.json')}")

    elif args.command == "evaluate":
        agent.organization = args.org
        package, manifest = agent.run_audit()

        if args.output == "markdown":
            formatted = AuditReporter.to_markdown(package)
        elif args.output == "json":
            formatted = AuditReporter.to_json(package)
        else: # terminal
            print(f"\n=== COMPLIANCE-AS-CODE AUDIT EVALUATION: {package.organization} ===")
            print(f"Audit Package ID: {package.package_id}")
            print(f"Manifest SHA-256: {package.manifest_sha256}\n")
            print(AuditReporter.to_terminal_table(package))
            print(f"\nAudit Scorecard: {package.passed_checks}/{package.total_checks} Controls Passed ({package.compliance_score_percent}% Compliance Score)")
            formatted = None

        if formatted:
            if args.save:
                with open(args.save, "w", encoding="utf-8") as f:
                    f.write(formatted)
                print(f"[+] Audit package successfully saved to: {args.save}")
            else:
                print("\n" + formatted)

    elif args.command == "verify":
        print("\nVerifying cryptographic integrity of stored evidence manifest...")
        try:
            valid = agent.verify_stored_manifest()
            if valid:
                print("\n[+] INTEGRITY VERIFIED (PASS): All evidence hashes and Merkle root digest match exactly.")
                print("Zero tampering, alteration, or evidence omission detected.")
            else:
                print("\n[!] INTEGRITY VIOLATION (FAIL): Evidence hash mismatch or corrupted manifest!")
                sys.exit(1)
        except FileNotFoundError as e:
            print(f"[!] Error: {e}")
            print("Run 'python -m src.cli collect' first to generate an evidence manifest.")
            sys.exit(1)

    elif args.command == "mappings":
        mappings = ComplianceMapper.get_all_mappings()
        rows = []
        for m in mappings:
            rows.append([
                m.check_id,
                m.cis_control_id,
                ", ".join(m.soc2_controls),
                ", ".join(m.iso27001_controls),
                m.cis_title[:45]
            ])
        print("\n=== CIS BENCHMARKS TO SOC 2 & ISO 27001 CROSSWALK ===\n")
        print(tabulate(rows, headers=["Check ID", "CIS Control", "SOC 2 Criteria", "ISO 27001:2022", "Audit Objective Title"], tablefmt="grid"))

    elif args.command == "stats":
        mappings = ComplianceMapper.get_all_mappings()
        soc2_map = ComplianceMapper.get_soc2_coverage()
        iso_map = ComplianceMapper.get_iso27001_coverage()
        print("\n=== COMPLIANCE-AS-CODE AGENT METRICS ===")
        print(f"Total Automated Checks:        {len(mappings)}")
        print(f"Host CIS Benchmark Checks:     6")
        print(f"Cloud (AWS IAM/Trail/S3) Checks: 5")
        print(f"Mapped SOC 2 Criteria:         {len(soc2_map)} unique criteria ({', '.join(sorted(soc2_map.keys()))})")
        print(f"Mapped ISO 27001:2022 Controls: {len(iso_map)} unique controls")
        print("Cryptographic Integrity:       SHA-256 canonical Merkle root verification active")

if __name__ == "__main__":
    main()
