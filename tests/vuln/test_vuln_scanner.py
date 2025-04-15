import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

import pytest
from security_toolbox.vuln.vuln_scanner import VulnScanner

def test_vuln_scanner_fetch(monkeypatch):
    # Mock de la méthode _fetch_cve pour éviter un vrai appel API
    def mock_fetch_cve(self, service):
        if service == "ssh":
            return [{"id": "CVE-2024-0001", "summary": "Test vuln SSH"}]
        return []
    monkeypatch.setattr(VulnScanner, "_fetch_cve", mock_fetch_cve)

    scanner = VulnScanner(api_url="http://fake-api", config={})
    results = scanner.scan([{"port": 22, "service": "ssh"}])
    assert results == {
        22: [{"id": "CVE-2024-0001", "summary": "Test vuln SSH"}]
    }

def test_vuln_scanner_empty():
    scanner = VulnScanner(api_url="http://fake-api", config={})
    results = scanner.scan([])
    assert results == {}
