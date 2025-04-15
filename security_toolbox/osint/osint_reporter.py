import os
import os
import json
import datetime

def export_osint_global_report(target, target_type, results, export_base):
    """
    Exporte un rapport global OSINT (JSON et Markdown).
    export_base : chemin de base sans extension
    """
    now = datetime.datetime.now().isoformat()
    # JSON
    with open(export_base + '.json', 'w', encoding='utf-8') as f:
        json.dump({'target': target, 'type': target_type, 'date': now, 'results': results}, f, ensure_ascii=False, indent=2)
    # Markdown
    with open(export_base + '.md', 'w', encoding='utf-8') as f:
        f.write(f"# Rapport OSINT global\n\n")
        f.write(f"**Cible** : {target}\n\n")
        f.write(f"**Type** : {target_type}\n\n")
        f.write(f"**Date** : {now}\n\n")
        f.write(f"## Résultats\n\n")
        for module, data in results.items():
            f.write(f"### {module}\n\n")
            if isinstance(data, list):
                for entry in data:
                    f.write(f"- {entry}\n")
            elif isinstance(data, dict):
                for k, v in data.items():
                    f.write(f"- {k} : {v}\n")
            else:
                f.write(str(data) + '\n')
