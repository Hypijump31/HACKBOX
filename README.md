# Security Toolbox

Une boîte à outils Python modulaire pour l'évaluation de la sécurité informatique.

## Fonctionnalités
- **Scan de ports** (socket/nmap)
- **Analyse de vulnérabilités** (API CVE)
- **Test d'authentification** (SSH/HTTP)
- **Sniffing réseau** (scapy/pyshark)
- **Rapport automatisé** (texte/PDF)

## Installation

```bash
pip install -r requirements.txt
```

## Utilisation

```bash
python -m security_toolbox.main --scan --target 127.0.0.1
```

Voir `config.yaml` pour la configuration initiale (cibles, limites, etc).

## Exécution des tests

```bash
pytest --cov=security_toolbox
coverage report --fail-under=90
```

## Méthodologie TDD
- Tests écrits avant chaque fonctionnalité
- Couverture > 90%
- Cas nominaux, limites et erreurs

## Structure du projet

Voir l'arborescence dans la documentation du projet.

## Dépendances principales
- argparse/click, pyyaml, socket/nmap, requests, paramiko, scapy/pyshark, fpdf/reportlab, pytest, coverage

## Bonnes pratiques
- Modularité, PEP8, gestion des erreurs, logging

---

**Pour toute contribution, merci de suivre la méthodologie TDD et de documenter chaque module.**
