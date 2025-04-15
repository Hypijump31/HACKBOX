import socket

def check_smbghost(host, port=445, timeout=3):
    """
    Teste la vulnérabilité SMBGhost (CVE-2020-0796) sur SMBv3.
    Retourne True si vulnérable, False sinon, None si erreur.
    """
    pkt = bytes.fromhex('fe534d424000010000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(pkt)
            resp = sock.recv(1024)
            if resp.startswith(b'\xfeSMB'):  # Réponse SMBv3 attendue
                return True
            return False
    except Exception:
        return None
