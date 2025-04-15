import requests

def censys_lookup(ip, api_id, api_secret):
    """
    Interroge l'API Censys pour obtenir des infos sur une IP.
    Retourne un dictionnaire avec les données principales ou None en cas d'erreur.
    """
    url = f'https://search.censys.io/api/v2/hosts/{ip}/view'
    try:
        resp = requests.get(url, auth=(api_id, api_secret), timeout=10)
        if resp.status_code == 200:
            data = resp.json().get('result', {})
            return {
                'ip': data.get('ip'),
                'services': data.get('services'),
                'location': data.get('location'),
                'autonomous_system': data.get('autonomous_system'),
                'vulns': data.get('vulnerabilities'),
                'raw': data
            }
        else:
            return None
    except Exception as e:
        return None
