import requests
import time
import json
import datetime
from urllib.parse import urljoin

def http_bruteforce(url, userlist=None, passlist=None, method='POST', user_field='username', pass_field='password', success_flag=None, fail_flag=None, timeout=5, delay=0.5, max_attempts=20, extra_data=None, auth_type=None):
    """
    Brute-force HTTP avancé : formulaire POST, Basic/Digest, gestion timing, erreurs, export pro.
    userlist/passlist : listes de users/pwds à tester.
    method : 'POST' ou 'GET'.
    user_field/pass_field : noms des champs du formulaire.
    success_flag/fail_flag : texte ou code HTTP indiquant succès/échec.
    extra_data : dict pour champs additionnels.
    auth_type : 'basic', 'digest', ou None.
    Retourne credentials valides et erreurs.
    """
    results = []
    valid = []
    errors = []
    attempts = 0
    meta = {
        'url': url,
        'method': method,
        'user_field': user_field,
        'pass_field': pass_field,
        'date': datetime.datetime.now().isoformat(),
        'total_users': len(userlist) if userlist else 0,
        'total_pwds': len(passlist) if passlist else 0,
        'max_attempts': max_attempts,
        'timeout': timeout,
        'delay': delay,
        'auth_type': auth_type
    }
    if not userlist or not passlist:
        return {'meta': meta, 'valid': valid, 'errors': ['Userlist or passlist missing'], 'results': results}
    session = requests.Session()
    for user in userlist:
        for pwd in passlist:
            if attempts >= max_attempts:
                errors.append('Max attempts reached')
                break
            try:
                if auth_type == 'basic':
                    resp = session.request(method, url, auth=(user, pwd), timeout=timeout)
                elif auth_type == 'digest':
                    from requests.auth import HTTPDigestAuth
                    resp = session.request(method, url, auth=HTTPDigestAuth(user, pwd), timeout=timeout)
                else:
                    data = {user_field: user, pass_field: pwd}
                    if extra_data:
                        data.update(extra_data)
                    resp = session.request(method, url, data=data, timeout=timeout)
                status = resp.status_code
                body = resp.text
                ok = False
                if success_flag and success_flag in body:
                    ok = True
                elif fail_flag and fail_flag in body:
                    ok = False
                elif success_flag is None and fail_flag is None:
                    ok = status == 200 and user.lower() not in body.lower()
                if ok:
                    valid.append({'user': user, 'password': pwd, 'status': status})
                    results.append({'user': user, 'password': pwd, 'status': 'success', 'code': status})
                else:
                    results.append({'user': user, 'password': pwd, 'status': 'fail', 'code': status})
            except Exception as e:
                err = str(e)
                results.append({'user': user, 'password': pwd, 'status': 'error', 'error': err})
                errors.append(err)
            attempts += 1
            time.sleep(delay)
    return {'meta': meta, 'valid': valid, 'errors': errors, 'results': results}


def export_http_bruteforce_results(data, export_base):
    """
    Exporte les résultats du brute-force HTTP en JSON, Markdown, HTML.
    """
    meta = data.get('meta', {})
    valid = data.get('valid', [])
    errors = data.get('errors', [])
    results = data.get('results', [])
    import os, datetime
    date_dir = datetime.datetime.now().strftime("%Y%m%d")
    base_dir = os.path.join(os.getcwd(), "exports", date_dir, "bruteforce_http")
    os.makedirs(base_dir, exist_ok=True)
    export_base = os.path.join(base_dir, os.path.basename(export_base))
    # JSON
    with open(export_base + '.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    # Markdown
    with open(export_base + '.md', 'w', encoding='utf-8') as f:
        f.write(f"# Rapport Brute-force HTTP\n\n")
        for k, v in meta.items():
            f.write(f"**{k}** : {v}\n")
        f.write(f"\n**Valides** : {len(valid)}\n\n")
        for v in valid:
            f.write(f"- {v['user']} : {v['password']}\n")
        f.write(f"\n**Erreurs** : {len(errors)}\n\n")
        for e in errors:
            f.write(f"- {e}\n")
        f.write(f"\n**Détail des tentatives** : {len(results)}\n\n")
        for i, r in enumerate(results, 1):
            f.write(f"## Tentative {i}\n")
            for k, v in r.items():
                f.write(f"- **{k}** : {v}\n")
            f.write("\n")
    # HTML
    with open(export_base + '.html', 'w', encoding='utf-8') as f:
        f.write(f"<html><head><meta charset='utf-8'><title>Rapport Brute-force HTTP</title></head><body>")
        f.write(f"<h1>Rapport Brute-force HTTP</h1>")
        for k, v in meta.items():
            f.write(f"<b>{k}</b> : {v}<br>")
        f.write(f"<br><b>Valides :</b> {len(valid)}<ul>")
        for v in valid:
            f.write(f"<li>{v['user']} : {v['password']}</li>")
        f.write("</ul><br><b>Erreurs :</b> %d<ul>" % len(errors))
        for e in errors:
            f.write(f"<li>{e}</li>")
        f.write("</ul><br><b>Détail des tentatives :</b> %d<br>" % len(results))
        for i, r in enumerate(results, 1):
            f.write(f"<h2>Tentative {i}</h2><ul>")
            for k, v in r.items():
                f.write(f"<li><b>{k}</b> : {v}</li>")
            f.write("</ul><br>")
        f.write("</body></html>")
