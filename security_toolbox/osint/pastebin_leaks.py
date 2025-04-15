import requests
import os
import datetime

def search_pastebin_leaks(query):
    """
    Recherche de fuites potentielles sur Pastebin via scraping non authentifié (limité) ou via une API tierce si dispo.
    Retourne une liste d'URLs de pastes trouvés.
    """
    # Pastebin n'a pas d'API publique pour la recherche. On peut utiliser scraping ou une API tierce.
    # Ici, on simule la recherche (à remplacer par une vraie API ou scraping si légalement autorisé).
    return [f'https://pastebin.com/search?q={query}']

def export_pastebin_report(query, results, export_base):
    import os, datetime
    date_dir = datetime.datetime.now().strftime("%Y%m%d")
    base_dir = os.path.join(os.getcwd(), "exports", date_dir, "osint_pastebin")
    os.makedirs(base_dir, exist_ok=True)
    export_base = os.path.join(base_dir, os.path.basename(export_base))
    with open(os.path.join(export_base, 'report.md'), 'w', encoding='utf-8') as f:
        f.write(f"# Résultats Pastebin\n\n")
        f.write(f"**Recherche** : {query}\n**Date** : {datetime.datetime.now().isoformat()}\n\n")
        if results:
            for url in results:
                f.write(f"- {url}\n")
        else:
            f.write("Aucun résultat trouvé.\n")
    with open(os.path.join(export_base, 'report.json'), 'w', encoding='utf-8') as f:
        import json
        json.dump({'query': query, 'results': results}, f, ensure_ascii=False, indent=2)
