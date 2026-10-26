import pytest
from src.mapper import ComplianceMapper

def test_mapper_lookup_valid():
    m = ComplianceMapper.get_mapping("CIS-HOST-1.1")
    assert m is not None
    assert m.cis_control_id == "CIS-v8-4.4"
    assert "CC6.6" in m.soc2_controls
    assert "A.8.20" in m.iso27001_controls

def test_mapper_lookup_nonexistent():
    m = ComplianceMapper.get_mapping("DOES-NOT-EXIST")
    assert m is None

def test_soc2_coverage():
    cov = ComplianceMapper.get_soc2_coverage()
    assert "CC6.1" in cov
    assert "CC6.2" in cov
    assert "CC6.3" in cov
    assert "CC6.6" in cov
    assert "CC7.2" in cov

def test_iso27001_coverage():
    cov = ComplianceMapper.get_iso27001_coverage()
    assert "A.8.24" in cov # Cryptography
    assert "A.8.15" in cov # Logging
    assert "A.5.15" in cov # Access control
