# Placeholder for Reporter implementation
class Reporter:
    def generate_txt(self, data, output_file):
        import os, datetime
        date_dir = datetime.datetime.now().strftime("%Y%m%d")
        base_dir = os.path.join(os.getcwd(), "exports", date_dir, "global")
        os.makedirs(base_dir, exist_ok=True)
        output_file = os.path.join(base_dir, os.path.basename(output_file))
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("=== Rapport de sécurité ===\n")
                if "scan" in data:
                    f.write("\n[Scan de ports]\n")
                    for port, status in data["scan"].items():
                        f.write(f"Port {port}: {status}\n")
                if "vuln" in data:
                    f.write("\n[Failles détectées]\n")
                    for port, vulns in data["vuln"].items():
                        for vuln in vulns:
                            f.write(f"Port {port}: {vuln.get('id', '')} - {vuln.get('summary', '')}\n")
        except Exception as e:
            raise Exception(f"Erreur lors de la génération du rapport: {e}")

    def generate_global_report(self, data, output_base):
        """
        Génère un rapport global (JSON, Markdown, HTML) intégrant scan, vuln, recon, fuzzing.
        data : {
            'scan': ..., 'vuln': ..., 'recon': ..., 'fuzz_http': ..., 'fuzz_ftp': ..., 'fuzz_smtp': ...
        }
        output_base : chemin de base sans extension
        """
        import json, datetime, os
        now = datetime.datetime.now().isoformat()
        meta = {
            'date': now,
            'modules': list(data.keys())
        }
        date_dir = datetime.datetime.now().strftime("%Y%m%d")
        base_dir = os.path.join(os.getcwd(), "exports", date_dir, "global")
        os.makedirs(base_dir, exist_ok=True)
        output_base = os.path.join(base_dir, os.path.basename(output_base))
        # JSON
        with open(output_base + '.json', 'w', encoding='utf-8') as f:
            json.dump({'meta': meta, 'data': data}, f, ensure_ascii=False, indent=2)
        # Markdown
        with open(output_base + '.md', 'w', encoding='utf-8') as f:
            f.write(f"# Rapport Global HACKBOX\n\n")
            f.write(f"**Date** : {now}\n\n**Modules inclus** : {', '.join(meta['modules'])}\n\n")
            f.write(f"---\n\n")
            for section, content in data.items():
                f.write(f"## {section.upper()}\n\n")
                if isinstance(content, dict) or isinstance(content, list):
                    f.write(f"```json\n{json.dumps(content, ensure_ascii=False, indent=2)}\n```\n\n")
                else:
                    f.write(f"{content}\n\n")
        # HTML
        html_file = os.path.join(base_dir, os.path.basename(output_base) + '.html')
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(f"<html><head><meta charset='utf-8'><title>Rapport Global HACKBOX</title></head><body>")
            f.write(f"<h1>Rapport Global HACKBOX</h1>")
            f.write(f"<b>Date :</b> {now}<br><b>Modules inclus :</b> {', '.join(meta['modules'])}<hr>")
            for section, content in data.items():
                f.write(f"<h2>{section.upper()}</h2>")
                f.write(f"<pre>{json.dumps(content, ensure_ascii=False, indent=2)}</pre>")
            f.write("</body></html>")
