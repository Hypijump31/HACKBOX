import os
import platform
import subprocess
import datetime

def detect_escalation_vectors():
    """
    Détecte des vecteurs d'escalade de privilèges classiques sur Linux/Windows.
    """
    results = []
    sys = platform.system().lower()
    if sys == 'windows':
        # Vérifie si l'utilisateur est admin
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            is_admin = 'S-1-5-32-544' in subprocess.getoutput('whoami /groups')
        results.append({'check': 'Admin', 'result': is_admin})
        # UAC
        uac = subprocess.getoutput('reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA')
        results.append({'check': 'UAC', 'result': uac})
        # Services non protégés
        unquoted = subprocess.getoutput('wmic service get name,pathname | findstr /i " :\\" | findstr /i /v "\""')
        results.append({'check': 'Services non protégés', 'result': unquoted})
    else:
        # Linux
        sudoers = subprocess.getoutput('sudo -l')
        results.append({'check': 'sudo -l', 'result': sudoers})
        suids = subprocess.getoutput('find / -perm -4000 -type f 2>/dev/null')
        results.append({'check': 'SUID binaries', 'result': suids})
        world_writable = subprocess.getoutput('find / -writable -type d 2>/dev/null | grep -v "/proc"')
        results.append({'check': 'World-writable dirs', 'result': world_writable})
        passwd_shadow = os.path.exists('/etc/shadow') and os.access('/etc/shadow', os.R_OK)
        results.append({'check': '/etc/shadow readable', 'result': passwd_shadow})
    return results

def export_escalation_report(results, output_base):
    # Organisation : exports/<date>/escalation/
    date_dir = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = os.path.join(os.getcwd(), "exports", date_dir, "escalation")
    os.makedirs(base_dir, exist_ok=True)
    export_base = os.path.join(base_dir, os.path.basename(output_base))
    with open(export_base+'.md', 'w', encoding='utf-8') as f:
        f.write(f"# Rapport Escalade de Privilèges\n\n")
        f.write(f"**Date** : {datetime.datetime.now().isoformat()}\n\n")
        for r in results:
            f.write(f"## {r['check']}\n\n")
            f.write(f"{r['result']}\n\n")
    with open(export_base+'.json', 'w', encoding='utf-8') as f:
        import json
        json.dump(results, f, ensure_ascii=False, indent=2)
