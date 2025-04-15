import requests
import datetime
import os

def check_email_pwned(email, api_key=None):
    """
    Vérifie si un email a été compromis (HaveIBeenPwned).
    """
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {'hibp-api-key': api_key} if api_key else {}
    r = requests.get(url, headers=headers, params={'truncateResponse': 'false'})
    if r.status_code == 200:
        return r.json()
    elif r.status_code == 404:
        return []
    else:
        raise Exception(f"Erreur API HIBP: {r.status_code} {r.text}")

def export_hibp_report(email, breaches, export_base):
    os.makedirs(os.path.dirname(export_base), exist_ok=True)
    with open(os.path.join(export_base, 'report.md'), 'w', encoding='utf-8') as f:
        f.write(f"# Rapport HaveIBeenPwned\n\n")
        f.write(f"**Email** : {email}\n**Date** : {datetime.datetime.now().isoformat()}\n\n")
        if breaches:
            f.write(f"## Breaches détectées ({len(breaches)})\n\n")
            for b in breaches:
                f.write(f"- {b['Name']} ({b['BreachDate']}) : {b['Title']}\n")
        else:
            f.write("Aucune compromission détectée.\n")
    with open(os.path.join(export_base, 'report.json'), 'w', encoding='utf-8') as f:
        import json
        json.dump({'email': email, 'breaches': breaches}, f, ensure_ascii=False, indent=2)
