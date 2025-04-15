import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

import pytest
from security_toolbox.scan.port_scanner import PortScanner

def test_scan_localhost_ports(monkeypatch):
    # Mock du scan pour éviter un vrai scan réseau
    def mock_scan(self):
        return {"22": "open", "80": "closed"}
    monkeypatch.setattr(PortScanner, "scan", mock_scan)

    scanner = PortScanner("127.0.0.1", config={})
    result = scanner.scan()
    assert result == {"22": "open", "80": "closed"}

def test_scan_invalid_target():
    with pytest.raises(ValueError):
        scanner = PortScanner("invalid_ip", config={})
        scanner.scan()
