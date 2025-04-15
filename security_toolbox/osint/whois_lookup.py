import os
import os
import datetime
import socket
import re

def whois_lookup(domain):
    """
    Effectue une requête WHOIS brute sur un domaine.
    """
    import subprocess
    try:
        result = subprocess.check_output(['whois', domain], stderr=subprocess.DEVNULL, timeout=10, text=True)
        return result
    except Exception as e:
        return f"Erreur WHOIS: {e}"

def export_whois_report(domain, data, export_base):
    os.makedirs(os.path.dirname(export_base), exist_ok=True)
    with open(os.path.join(export_base, 'whois_report.txt'), 'w', encoding='utf-8') as f:
        f.write(f"# WHOIS pour {domain}\n\n")
        f.write(f"Date : {datetime.datetime.now().isoformat()}\n\n")
        f.write(data)
