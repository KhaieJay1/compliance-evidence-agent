import subprocess
import sys
import os

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run_cli(*args):
    cmd = [sys.executable, "-m", "src.cli"] + list(args)
    res = subprocess.run(
        cmd,
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )
    return res

def test_cli_stats():
    res = run_cli("stats")
    assert res.returncode == 0
    assert "Total Automated Checks:        11" in res.stdout
    assert "Mapped SOC 2 Criteria:" in res.stdout

def test_cli_mappings():
    res = run_cli("mappings")
    assert res.returncode == 0
    assert "CIS-HOST-1.1" in res.stdout
    assert "AWS-IAM-01" in res.stdout

def test_cli_collect():
    res = run_cli("collect")
    assert res.returncode == 0
    assert "Successfully collected 11 evidence artifacts" in res.stdout
    assert "Manifest Root:" in res.stdout

def test_cli_verify():
    # Run collect first, then verify
    run_cli("collect")
    res = run_cli("verify")
    assert res.returncode == 0
    assert "INTEGRITY VERIFIED (PASS)" in res.stdout

def test_cli_evaluate():
    res = run_cli("evaluate")
    assert res.returncode == 0
    assert "COMPLIANCE-AS-CODE AUDIT EVALUATION" in res.stdout
    assert "Audit Scorecard:" in res.stdout
