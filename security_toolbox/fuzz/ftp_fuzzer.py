import ftplib
import socket
import datetime
import json
import os

def ftp_fuzz(host, port=21, user='anonymous', passwd='anonymous@', timeout=5):
    """
    Fuzzing avancé d'un service FTP : commandes non standards, injections, brute-force simple, énumération.
    Retourne une liste de résultats suspects ou d'anomalies.
    """
    results = []
    meta = {
        'host': host,
        'port': port,
        'user': user,
        'date': datetime.datetime.now().isoformat()
    }
    # Liste de commandes à tester (standards, non standards, injections)
    commands = [
        'USER anonymous', 'PASS anonymous@',
        'HELP', 'NOOP', 'SYST', 'STAT', 'PWD', 'CWD /', 'LIST', 'PASV',
        'SITE EXEC id', 'SITE EXEC whoami', 'SITE CHMOD 777 /etc/passwd',
        'MKD fuzztest', 'RMD fuzztest', 'RNFR fuzztest', 'RNTO fuzzed',
        'DELE fuzztest', 'STOR fuzzed.txt', 'RETR /etc/passwd',
        'SITE CPFR /etc/passwd', 'SITE CPTO /tmp/copy',
        'PORT 127,0,0,1,7,138', 'ABOR', 'ACCT fuzz', 'ALLO 123',
        'APPE fuzzed.txt', 'SMNT /', 'STOU', 'STRU F', 'MODE S',
        'TYPE A', 'TYPE I', 'FEAT', 'OPTS UTF8 ON',
        'SITE', 'SITE HELP', 'SITE ZZZ', 'SITE %s' % ('A'*500)
    ]
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=timeout)
        ftp.login(user, passwd)
        for cmd in commands:
            try:
                resp = ftp.sendcmd(cmd)
                if any(x in resp.lower() for x in ['error', 'fail', 'not allowed', 'denied', 'unknown', 'syntax']):
                    results.append({'command': cmd, 'response': resp, 'type': 'error'})
                elif resp and len(resp) > 0:
                    results.append({'command': cmd, 'response': resp, 'type': 'info'})
            except Exception as e:
                results.append({'command': cmd, 'response': str(e), 'type': 'exception'})
        ftp.quit()
    except (socket.error, ftplib.all_errors) as e:
        results.append({'command': 'CONNECT', 'response': str(e), 'type': 'fatal'})
    return {'meta': meta, 'results': results}


def export_ftp_fuzz_results(fuzz_data, export_base):
    """
    Exporte les résultats du fuzzing FTP au format JSON, Markdown et HTML.
    """
    meta = fuzz_data.get('meta', {})
    results = fuzz_data.get('results', [])
    import os, datetime
    date_dir = datetime.datetime.now().strftime("%Y%m%d")
    base_dir = os.path.join(os.getcwd(), "exports", date_dir, "fuzz_ftp")
    os.makedirs(base_dir, exist_ok=True)
    export_base = os.path.join(base_dir, os.path.basename(export_base))
    # JSON
    with open(export_base + '.json', 'w', encoding='utf-8') as f:
        json.dump(fuzz_data, f, ensure_ascii=False, indent=2)
    # Markdown
    with open(export_base + '.md', 'w', encoding='utf-8') as f:
        f.write(f"# Rapport de Fuzzing FTP\n\n")
        for k, v in meta.items():
            f.write(f"**{k}** : {v}\n")
        f.write(f"\n**Total résultats** : {len(results)}\n\n")
        for i, r in enumerate(results, 1):
            f.write(f"## Commande {i}\n")
            for k, v in r.items():
                f.write(f"- **{k}** : {v}\n")
            f.write("\n")
    # HTML
    with open(export_base + '.html', 'w', encoding='utf-8') as f:
        f.write(f"<html><head><meta charset='utf-8'><title>Rapport Fuzzing FTP</title></head><body>")
        f.write(f"<h1>Rapport de Fuzzing FTP</h1>")
        for k, v in meta.items():
            f.write(f"<b>{k}</b> : {v}<br>")
        f.write(f"<br><b>Total résultats :</b> {len(results)}<hr>")
        for i, r in enumerate(results, 1):
            f.write(f"<h2>Commande {i}</h2><ul>")
            for k, v in r.items():
                f.write(f"<li><b>{k}</b> : {v}</li>")
            f.write("</ul><br>")
        f.write("</body></html>")
