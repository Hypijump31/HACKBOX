import pytest
import sys
from security_toolbox.main import main

def test_cli_scan(monkeypatch):
    test_args = ["main.py", "--scan", "--target", "127.0.0.1"]
    monkeypatch.setattr(sys, "argv", test_args)
    # On s'attend à ce que la fonction main ne plante pas et retourne None
    assert main() is None
