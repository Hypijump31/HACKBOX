import requests
import os
import datetime

def search_github_leaks(query, github_token=None, proxies=None):
    """
    Recherche de leaks publics sur GitHub via l'API search/code.
    query : email, domaine, mot-clé, token, etc.
    github_token : token API GitHub (optionnel, recommandé pour quota).
    proxies : dict proxies pour requests (optionnel, ex: {'http': 'socks5://127.0.0.1:9050', ...})
    """
    url = 'https://api.github.com/search/code'
    headers = {'Accept': 'application/vnd.github.v3+json'}
    if github_token:
        headers['Authorization'] = f'token {github_token}'
    params = {'q': query, 'per_page': 10}
    r = requests.get(url, headers=headers, params=params, proxies=proxies)
    if r.status_code == 200:
        return r.json().get('items', [])
    else:
        return {'error': f'GitHub API: {r.status_code} {r.text}'}

def export_github_report(query, results, export_base):
    import os, datetime
    date_dir = datetime.datetime.now().strftime("%Y%m%d")
    base_dir = os.path.join(os.getcwd(), "exports", date_dir, "osint_github")
    os.makedirs(base_dir, exist_ok=True)
    export_base = os.path.join(base_dir, os.path.basename(export_base))
    with open(os.path.join(export_base, '.md'), 'w', encoding='utf-8') as f:
        f.write(f"# Recherche GitHub leaks\n\n")
        f.write(f"**Recherche** : {query}\n**Date** : {datetime.datetime.now().isoformat()}\n\n")
        if isinstance(results, list) and results:
            for item in results:
                f.write(f"- {item.get('html_url', '')} ({item.get('repository', {}).get('full_name', '')})\n")
        elif 'error' in results:
            f.write(results['error']+"\n")
        else:
            f.write("Aucun résultat trouvé.\n")
    with open(os.path.join(export_base, '.json'), 'w', encoding='utf-8') as f:
        import json
        json.dump({'query': query, 'results': results}, f, ensure_ascii=False, indent=2)
