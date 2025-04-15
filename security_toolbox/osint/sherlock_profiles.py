import requests
import os
import datetime

def search_sherlock_profiles(username, proxies=None):
    """
    Recherche de profils publics par pseudo via l'API Sherlock/WhatsMyName (ou scraping de sites connus).
    username : pseudo à rechercher
    proxies : dict proxies pour requests (optionnel, ex: {'http': 'socks5://127.0.0.1:9050', ...})
    """
    # Simulé : à remplacer par intégration réelle de Sherlock ou WhatsMyName (API ou CLI)
    known_sites = [
        f'https://twitter.com/{username}',
        f'https://github.com/{username}',
        f'https://instagram.com/{username}',
        f'https://facebook.com/{username}',
        f'https://gitlab.com/{username}',
        f'https://medium.com/@{username}',
        f'https://keybase.io/{username}',
    ]
    # Optionnel : vérifier existence réelle via requests.head()
    found = []
    for url in known_sites:
        try:
            r = requests.head(url, timeout=5, proxies=proxies)
            if r.status_code < 400:
                found.append(url)
        except Exception:
            continue
    return found

def export_sherlock_report(username, results, export_base):
    import os, datetime
    date_dir = datetime.datetime.now().strftime("%Y%m%d")
    base_dir = os.path.join(os.getcwd(), "exports", date_dir, "osint_sherlock")
    os.makedirs(base_dir, exist_ok=True)
    export_base = os.path.join(base_dir, os.path.basename(export_base))
    with open(export_base+'.md', 'w', encoding='utf-8') as f:
        f.write(f"# Recherche de profils publics\n\n")
        f.write(f"**Pseudo** : {username}\n**Date** : {datetime.datetime.now().isoformat()}\n\n")
        if results:
            for url in results:
                f.write(f"- {url}\n")
        else:
            f.write("Aucun profil trouvé.\n")
    with open(export_base+'.json', 'w', encoding='utf-8') as f:
        import json
        json.dump({'username': username, 'results': results}, f, ensure_ascii=False, indent=2)
