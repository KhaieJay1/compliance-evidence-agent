import pytest
import tempfile
import os
import shutil
from src.agent import ComplianceEvidenceAgent

@pytest.fixture
def temp_store():
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)

@pytest.fixture
def test_agent(temp_store):
    return ComplianceEvidenceAgent(store_dir=temp_store, organization="Test Org")
