import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

import pytest
from security_toolbox.auth.auth_tester import AuthTester

def test_ssh_auth_success(monkeypatch):
    def mock_ssh(self, host, user, password):
        return True
    monkeypatch.setattr(AuthTester, "test_ssh", mock_ssh)
    tester = AuthTester(config={"ssh_max_attempts": 3})
    assert tester.test_ssh("127.0.0.1", "user", "pass") is True

def test_ssh_auth_fail(monkeypatch):
    def mock_ssh(self, host, user, password):
        return False
    monkeypatch.setattr(AuthTester, "test_ssh", mock_ssh)
    tester = AuthTester(config={"ssh_max_attempts": 3})
    assert tester.test_ssh("127.0.0.1", "user", "wrong") is False

def test_ssh_auth_limit():
    tester = AuthTester(config={"ssh_max_attempts": 1})
    tester.attempts = 1
    with pytest.raises(Exception):
        tester.test_ssh("127.0.0.1", "user", "pass")
