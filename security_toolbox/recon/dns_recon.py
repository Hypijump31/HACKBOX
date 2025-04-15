import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def brute_force_subdomains(domain, wordlist, max_workers=20):
    found = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(resolve_subdomain, sub, domain): sub for sub in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
    return found

def resolve_subdomain(sub, domain):
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return {'subdomain': fqdn, 'ip': ip}
    except Exception:
        return None

def reverse_ip_lookup(ip):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None

def dns_bruteforce(domain, subdomain_wordlist=None):
    if subdomain_wordlist is None:
        subdomain_wordlist = [
            'www', 'mail', 'admin', 'dev', 'test', 'ftp', 'webmail', 'portal', 'api', 'blog', 'vpn', 'intranet', 'shop', 'secure', 'm', 'mobile', 'beta', 'staging', 'old', 'backup', 'ns1', 'ns2', 'smtp', 'pop', 'imap', 'docs', 'files', 'db', 'sql', 'git', 'jira', 'help', 'support', 'forum', 'news', 'img', 'cdn', 'static', 'media', 'assets', 'download', 'upload', 'cloud', 'dashboard', 'panel', 'monitor', 'status', 'pay', 'payment', 'auth', 'login', 'logout', 'sso', 'crm', 'erp', 'ws', 'ws1', 'ws2', 'office', 'share', 'drive', 'calendar', 'notes', 'hr', 'jobs', 'careers', 'api2', 'api3', 'dev2', 'dev3', 'test2', 'test3', 'stage', 'prod', 'prod2', 'prod3', 'sandbox', 'preview', 'private', 'public', 'search', 'web', 'app', 'apps', 'node', 'nodes', 'cluster', 'clusters', 'edge', 'edges', 'proxy', 'proxies', 'cache', 'cdn2', 'cdn3', 'edge2', 'edge3', 'admin2', 'admin3', 'mail2', 'mail3', 'ftp2', 'ftp3', 'smtp2', 'smtp3', 'pop2', 'pop3', 'imap2', 'imap3'
        ]
    return brute_force_subdomains(domain, subdomain_wordlist)
