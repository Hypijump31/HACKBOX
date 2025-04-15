import requests
import os
import datetime

def shodan_host_lookup(ip, api_key):
    """
    Recherche les infos sur une IP via Shodan (bannières, ports, vulnérabilités).
    """
    url = f'https://api.shodan.io/shodan/host/{ip}'
    params = {'key': api_key}
    r = requests.get(url, params=params)
    if r.status_code == 200:
        return r.json()
    elif r.status_code == 404:
        return None
    else:
        raise Exception(f"Erreur API Shodan: {r.status_code} {r.text}")

def export_shodan_report(ip, data, export_base):
    os.makedirs(os.path.dirname(export_base), exist_ok=True)
    with open(os.path.join(export_base, 'shodan_report.json'), 'w', encoding='utf-8') as f:
        import json
        json.dump({'ip': ip, 'shodan': data}, f, ensure_ascii=False, indent=2)
    with open(os.path.join(export_base, 'shodan_report.md'), 'w', encoding='utf-8') as f:
        f.write(f"# Rapport Shodan\n\n")
        f.write(f"**IP** : {ip}\n**Date** : {datetime.datetime.now().isoformat()}\n\n")
        if data:
            f.write(f"## Ports ouverts\n\n")
            for item in data.get('data', []):
                f.write(f"- Port {item.get('port')}: {item.get('product', 'N/A')} | {item.get('transport', '')}\n")
            vulns = data.get('vulns', {})
            if vulns:
                f.write(f"\n## Vulnérabilités détectées\n\n")
                for v in vulns:
                    f.write(f"- {v}\n")
        else:
            f.write("Aucune donnée trouvée.\n")
