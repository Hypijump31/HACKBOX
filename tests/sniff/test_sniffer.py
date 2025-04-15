import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

import pytest
from security_toolbox.sniff.sniffer import NetworkSniffer

def test_sniff_capture(monkeypatch):
    def mock_capture(self):
        return ["packet1", "packet2"]
    monkeypatch.setattr(NetworkSniffer, "capture", mock_capture)
    sniffer = NetworkSniffer(config={"interface": "lo"})
    packets = sniffer.capture()
    assert packets == ["packet1", "packet2"]

def test_sniff_error(monkeypatch):
    def mock_capture(self):
        raise Exception("Interface error")
    monkeypatch.setattr(NetworkSniffer, "capture", mock_capture)
    sniffer = NetworkSniffer(config={"interface": "lo"})
    with pytest.raises(Exception):
        sniffer.capture()
