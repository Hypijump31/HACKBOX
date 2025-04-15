import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import ssl
import re
from datetime import datetime

class PortScanner:
    def __init__(self, target, config):
        if target == 'localhost':
            self.target = '127.0.0.1'
        else:
            try:
                socket.gethostbyname(target)
                self.target = target
            except Exception:
                raise ValueError("Invalid target IP or hostname")
        self.config = config

    def parse_ssl_cert(self, host, port):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=4) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    ssl_version = ssock.version()
                    ciphers = ssock.cipher()
                    return {
                        'ssl_version': ssl_version,
                        'ciphers': ciphers,
                        'cert_subject': dict(cert.get('subject', [('', '')])[0]),
                        'cert_issuer': dict(cert.get('issuer', [('', '')])[0]),
                        'cert_notBefore': cert.get('notBefore'),
                        'cert_notAfter': cert.get('notAfter'),
                        'cert_serial': cert.get('serialNumber'),
                        'cert_SAN': cert.get('subjectAltName', [])
                    }
        except Exception:
            return {}

    def detect_web_technologies(self, http_headers, body):
        techs = []
        # Serveur web
        if 'Server' in http_headers:
            techs.append(http_headers['Server'])
        # X-Powered-By
        if 'X-Powered-By' in http_headers:
            techs.append(http_headers['X-Powered-By'])
        # Frameworks Python
        if 'wsgi' in http_headers.get('Server', '').lower() or 'django' in body.lower():
            techs.append('Django')
        if 'flask' in body.lower():
            techs.append('Flask')
        if 'rails' in body.lower():
            techs.append('Ruby on Rails')
        # Cookies
        set_cookie = http_headers.get('Set-Cookie', '')
        if 'wordpress' in set_cookie.lower() or 'wp-' in body.lower():
            techs.append('WordPress')
        if 'joomla' in set_cookie.lower() or 'joomla' in body.lower():
            techs.append('Joomla')
        if 'drupal' in set_cookie.lower() or 'drupal' in body.lower():
            techs.append('Drupal')
        # JS frameworks
        if re.search(r'react(\.|-)?[0-9]', body, re.I):
            techs.append('ReactJS')
        if 'angular' in body.lower():
            techs.append('AngularJS')
        if 'vue' in body.lower():
            techs.append('VueJS')
        if 'jquery' in body.lower():
            techs.append('jQuery')
        # CMS signatures
        if 'content="WordPress' in body:
            techs.append('WordPress')
        if 'content="Joomla' in body:
            techs.append('Joomla')
        if 'content="Drupal' in body:
            techs.append('Drupal')
        # PHP
        if 'php' in body.lower() or '.php' in body.lower():
            techs.append('PHP')
        # ASP.NET
        if 'asp.net' in set_cookie.lower() or 'asp.net' in body.lower():
            techs.append('ASP.NET')
        return list(set(techs))

    def grab_banner(self, port, sock):
        try:
            if port in [80, 8080, 8000, 8888]:  # HTTP
                sock.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                resp = b''
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > 4096:
                        break
                resp_str = resp.decode(errors='ignore')
                headers, _, body = resp_str.partition('\r\n\r\n')
                http_headers = {}
                for line in headers.split('\r\n'):
                    if ':' in line:
                        k, v = line.split(':', 1)
                        http_headers[k.strip()] = v.strip()
                banner = headers.split("\r\n")[0]
                service = 'http'
                version = http_headers.get('Server')
                technologies = self.detect_web_technologies(http_headers, body)
                return banner, service, version, technologies, {}
            elif port == 443:  # HTTPS
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    ssock.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    resp = b''
                    while True:
                        chunk = ssock.recv(1024)
                        if not chunk:
                            break
                        resp += chunk
                        if len(resp) > 4096:
                            break
                    resp_str = resp.decode(errors='ignore')
                    headers, _, body = resp_str.partition('\r\n\r\n')
                    http_headers = {}
                    for line in headers.split('\r\n'):
                        if ':' in line:
                            k, v = line.split(':', 1)
                            http_headers[k.strip()] = v.strip()
                    banner = headers.split("\r\n")[0]
                    service = 'https'
                    version = http_headers.get('Server')
                    technologies = self.detect_web_technologies(http_headers, body)
                    ssl_info = self.parse_ssl_cert(self.target, port)
                    return banner, service, version, technologies, ssl_info
            elif port == 22:  # SSH
                resp = sock.recv(1024).decode(errors='ignore')
                banner = resp.strip()
                service = 'ssh'
                version = banner
                # Extraction version OpenSSH/Dropbear/Putty etc.
                return banner, service, version, [], {}
            elif port == 21:  # FTP
                resp = sock.recv(1024).decode(errors='ignore')
                banner = resp.strip()
                service = 'ftp'
                version = banner
                return banner, service, version, [], {}
            elif port == 25:  # SMTP
                resp = sock.recv(1024).decode(errors='ignore')
                banner = resp.strip()
                service = 'smtp'
                version = banner
                return banner, service, version, [], {}
            elif port == 110:  # POP3
                resp = sock.recv(1024).decode(errors='ignore')
                banner = resp.strip()
                service = 'pop3'
                version = banner
                return banner, service, version, [], {}
            elif port == 143:  # IMAP
                resp = sock.recv(1024).decode(errors='ignore')
                banner = resp.strip()
                service = 'imap'
                version = banner
                return banner, service, version, [], {}
            elif port == 3306:  # MySQL
                resp = sock.recv(1024)
                if resp and resp[0] == 0xFF:
                    banner = resp[1:].decode(errors='ignore')
                else:
                    banner = resp.decode(errors='ignore')
                service = 'mysql'
                version = banner
                return banner, service, version, [], {}
            elif port == 5432:  # PostgreSQL
                resp = sock.recv(1024).decode(errors='ignore')
                banner = resp.strip()
                service = 'postgresql'
                version = banner
                return banner, service, version, [], {}
            elif port == 6379:  # Redis
                sock.sendall(b"INFO\r\n")
                resp = sock.recv(1024).decode(errors='ignore')
                banner = resp.split("\r\n")[0]
                service = 'redis'
                version = banner
                return banner, service, version, [], {}
        except Exception:
            pass
        return None, None, None, [], {}

    def scan_port(self, port):
        timeout = self.config.get('scan', {}).get('timeout', 2)
        banner = None
        service = None
        version = None
        technologies = []
        ssl_info = {}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                banner, service, version, technologies, ssl_info = self.grab_banner(port, sock)
                sock.close()
                return port, {'status': 'open', 'banner': banner, 'service': service, 'version': version, 'technologies': technologies, 'ssl_info': ssl_info}
            else:
                sock.close()
                return port, {'status': 'closed'}
        except Exception:
            return port, {'status': 'error'}

    def scan_ports_multithread(self, ports, max_workers=100, tqdm_callback=None):
        results = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            for future in as_completed(future_to_port):
                port, result = future.result()
                results[str(port)] = result
                if tqdm_callback:
                    tqdm_callback()
        return results

    def scan(self):
        pass
