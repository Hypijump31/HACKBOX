import datetime
import os
from tqdm import tqdm

def generate_google_dorks(domain):
    """
    Génère une liste de Google Dorks pour un domaine donné.
    """
    dorks = [
        f"site:{domain} ext:sql | ext:db | ext:bak | ext:old | ext:backup",
        f"site:{domain} inurl:admin | inurl:login | inurl:auth",
        f"site:{domain} intitle:index.of",
        f"site:{domain} ext:env | ext:ini | ext:conf | ext:json | ext:yaml",
        f"site:{domain} password | pass | pwd | secret | credentials",
        f"site:{domain} ext:log | ext:txt | ext:xml",
        f"site:{domain} inurl:wp-content | inurl:wp-admin",
        f"site:{domain} ext:php | ext:asp | ext:jsp | ext:aspx",
        f"site:{domain} ext:git | ext:svn | ext:hg | ext:bz2 | ext:zip | ext:tar | ext:gz",
        f"site:pastebin.com {domain}",
        f"site:github.com {domain}",
        f"site:trello.com {domain}",
        f"site:stackoverflow.com {domain} password",
    ]
    return dorks

def export_dorks_report(domain, dorks, export_base, scrape=False, max_results=3):
    """
    Exporte la liste des dorks en .md et .txt.
    Si scrape=True, ajoute les 3 premiers résultats Google sous chaque dork.
    """
    if scrape:
        from .google_scraper import scrape_google_dork
    date_dir = datetime.datetime.now().strftime("%Y%m%d")
    base_dir = os.path.join(os.getcwd(), "exports", date_dir, "osint")
    os.makedirs(base_dir, exist_ok=True)
    export_base = os.path.join(base_dir, os.path.basename(export_base))
    with open(export_base+'.md', 'w', encoding='utf-8') as f:
        f.write(f"# Google Dorks pour {domain}\n\n")
        f.write(f"**Date** : {datetime.datetime.now().isoformat()}\n\n")
        if scrape:
            for d in tqdm(dorks, desc="Scraping Google", ncols=70):
                f.write(f"- {d}\n")
                results = scrape_google_dork(d, max_results=max_results)
                for idx, (title, url) in enumerate(results, 1):
                    if url:
                        f.write(f"    > {idx}. [{title}]({url})\n")
                    else:
                        f.write(f"    > {idx}. {title}\n")
        else:
            for d in dorks:
                f.write(f"- {d}\n")
    with open(export_base+'.txt', 'w', encoding='utf-8') as f:
        for d in dorks:
            f.write(d+'\n')
