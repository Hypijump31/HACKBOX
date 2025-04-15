import requests
import json
import datetime
import os

class VulnScanner:
    def __init__(self, api_url, config):
        self.api_url = api_url.rstrip('/')
        self.config = config

    def _get_export_dir(self, module="vulnscan"):
        import os, datetime
        date_dir = datetime.datetime.now().strftime("%Y%m%d")
        base_dir = os.path.join(os.getcwd(), "exports", date_dir, module)
        os.makedirs(base_dir, exist_ok=True)
        return base_dir

    def detect_service(self, port, banner=None):
        # Mapping rapide ports/services, à enrichir
        common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3',
            143: 'imap', 443: 'https', 3306: 'mysql', 3389: 'rdp', 8080: 'http-proxy', 5900: 'vnc', 6379: 'redis', 5432: 'postgresql', 389: 'ldap', 445: 'smb', 139: 'netbios', 2049: 'nfs', 53: 'dns', 161: 'snmp', 636: 'ldaps', 25: 'smtp', 993: 'imaps', 995: 'pop3s', 465: 'smtps', 69: 'tftp'
        }
        if banner:
            # TODO: enrichir avec fingerprinting
            pass
        return common_ports.get(port, 'unknown')

    def fetch_cves(self, service, version=None):
        # Utilise l'API cve.circl.lu pour chercher les CVEs d'un service
        try:
            url = f"{self.api_url}/search/{service}"
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                cves = resp.json().get('data', [])
                # Optionnel : filtrer par version si dispo
                if version:
                    cves = [cve for cve in cves if version and version.lower() in str(cve).lower()]
                return cves
            return []
        except Exception:
            return []

    def enrich_exploit_links(self, cve_id):
        # Ajoute un lien exploit-db et metasploit si possible
        links = {}
        if cve_id and cve_id.startswith('CVE-'):
            links['exploitdb'] = f"https://www.exploit-db.com/search?cve={cve_id}"
            links['metasploit'] = f"https://www.rapid7.com/db/?q={cve_id}"
        return links

    def scan(self, services):
        # services = [{"port": 80, "service": "http", "banner": ...}, ...]
        results = []
        for svc in services:
            port = svc.get('port')
            banner = svc.get('banner')
            service = svc.get('service') or self.detect_service(port, banner)
            version = svc.get('version')
            cves = self.fetch_cves(service, version)
            for cve in cves[:20]:  # Affiche jusqu'à 20 CVEs par service
                links = self.enrich_exploit_links(cve.get('id', cve.get('cve', '-')))
                results.append({
                    'port': port,
                    'service': service,
                    'version': version or '-',
                    'cve_id': cve.get('id', cve.get('cve', '-')),
                    'summary': cve.get('summary', '-')[:100],
                    'cvss': cve.get('cvss', '-'),
                    'url': cve.get('href', '-'),
                    'exploitdb': links.get('exploitdb'),
                    'metasploit': links.get('metasploit')
                })
        return results

    def export_results(self, results, target, export_dir=None):
        base_dir = self._get_export_dir("vulnscan") if export_dir is None else export_dir
        now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"{base_dir}/vulnscan_{target}_{now}"
        # JSON
        with open(base+".json", "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        # Markdown
        with open(base+".md", "w", encoding="utf-8") as f:
            f.write("| Port | Service | Version | CVE | CVSS | Résumé | ExploitDB | Metasploit |\n")
            f.write("|------|---------|---------|-----|------|---------|-----------|------------|\n")
            for r in results:
                f.write(f"| {r['port']} | {r['service']} | {r['version']} | [{r['cve_id']}]({r['url']}) | {r['cvss']} | {r['summary'][:40]} | [exploit-db]({r['exploitdb']}) | [metasploit]({r['metasploit']}) |\n")
        # HTML
        with open(base+".html", "w", encoding="utf-8") as f:
            f.write("<table border='1'><tr><th>Port</th><th>Service</th><th>Version</th><th>CVE</th><th>CVSS</th><th>Résumé</th><th>ExploitDB</th><th>Metasploit</th></tr>")
            for r in results:
                f.write(f"<tr><td>{r['port']}</td><td>{r['service']}</td><td>{r['version']}</td><td><a href='{r['url']}'>{r['cve_id']}</a></td><td>{r['cvss']}</td><td>{r['summary'][:40]}</td><td><a href='{r['exploitdb']}'>exploit-db</a></td><td><a href='{r['metasploit']}'>metasploit</a></td></tr>")
            f.write("</table>")
        return base

    def summarize(self, results):
        if not results:
            return {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'max_cvss': '-',
                'advices': ["Aucune vulnérabilité détectée. Système propre !"]
            }
        crit, high, med, low = 0, 0, 0, 0
        max_cvss = 0
        for r in results:
            try:
                score = float(r['cvss'])
                if score >= 9:
                    crit += 1
                elif score >= 7:
                    high += 1
                elif score >= 4:
                    med += 1
                else:
                    low += 1
                if score > max_cvss:
                    max_cvss = score
            except Exception:
                pass
        advices = []
        if crit > 0:
            advices.append("Des vulnérabilités CRITIQUES ont été trouvées. Mettez à jour ou segmentez le service concerné immédiatement.")
        if high > 0:
            advices.append("Des vulnérabilités importantes sont présentes. Planifiez une mise à jour rapide.")
        if med > 0:
            advices.append("Des vulnérabilités moyennes existent. Surveillez les correctifs.")
        if low > 0:
            advices.append("Des vulnérabilités faibles sont listées. Risque limité.")
        if not advices:
            advices.append("Aucune vulnérabilité détectée. Système propre !")
        return {
            'total': len(results),
            'critical': crit,
            'high': high,
            'medium': med,
            'low': low,
            'max_cvss': max_cvss if max_cvss else '-',
            'advices': advices
        }
