import paramiko
import requests

class AuthTester:
    def __init__(self, config):
        self.config = config
        self.attempts = 0

    def test_ssh(self, host, user, password, port=22, timeout=5):
        max_attempts = self.config.get("ssh_max_attempts", 5)
        if self.attempts >= max_attempts:
            raise Exception("Max SSH attempts reached")
        self.attempts += 1
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=host, port=port, username=user, password=password, timeout=timeout)
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except Exception as e:
            raise Exception(f"SSH error: {e}")

    def test_http_basic(self, url, user, password):
        max_attempts = self.config.get("http_max_attempts", 5)
        if self.attempts >= max_attempts:
            raise Exception("Max HTTP attempts reached")
        self.attempts += 1
        try:
            resp = requests.get(url, auth=(user, password), timeout=5)
            return resp.status_code == 200
        except Exception as e:
            raise Exception(f"HTTP error: {e}")
