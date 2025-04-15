import requests
import os
import datetime

def hunterio_search(domain, api_key):
    """
    Recherche les emails liés à un domaine via l'API Hunter.io.
    """
    url = f'https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}'
    r = requests.get(url)
    if r.status_code == 200:
        return r.json().get('data', {}).get('emails', [])
    else:
        raise Exception(f"Erreur API Hunter.io: {r.status_code} {r.text}")

def export_hunterio_report(domain, results, export_base):
    os.makedirs(os.path.dirname(export_base), exist_ok=True)
    with open(os.path.join(export_base, 'report.md'), 'w', encoding='utf-8') as f:
        f.write(f"# Résultats Hunter.io\n\n")
        f.write(f"**Domaine** : {domain}\n**Date** : {datetime.datetime.now().isoformat()}\n\n")
        if results:
            for entry in results:
                f.write(f"- {entry.get('value', '')} ({entry.get('type', '')})\n")
        else:
            f.write("Aucun email trouvé.\n")
    with open(os.path.join(export_base, 'report.json'), 'w', encoding='utf-8') as f:
        import json
        json.dump({'domain': domain, 'results': results}, f, ensure_ascii=False, indent=2)
