import requests

def shodan_lookup(ip, api_key):
    """
    Interroge l'API Shodan pour obtenir des infos sur une IP.
    Retourne un dictionnaire avec les données principales ou None en cas d'erreur.
    """
    url = f'https://api.shodan.io/shodan/host/{ip}?key={api_key}'
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {
                'ip': data.get('ip_str'),
                'ports': data.get('ports'),
                'hostnames': data.get('hostnames'),
                'org': data.get('org'),
                'os': data.get('os'),
                'vulns': data.get('vulns'),
                'data': data.get('data'),
                'raw': data
            }
        else:
            return None
    except Exception as e:
        return None
