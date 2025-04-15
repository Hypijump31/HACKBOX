# HACKBOX <span style="font-size:0.7em; vertical-align:super; color:#888;">By HYPIJUMP</span> – Pentest & OSINT Toolkit

![Python](https://img.shields.io/badge/python-3.8%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-Active-brightgreen)

> **Toolkit complet pour pentest, OSINT, brute-force, fuzzing, loot, rapports, et plus. Accessible aux débutants comme aux experts.**

---

## ✨ Fonctionnalités principales

- **Scan & Fingerprinting** : Scan de ports TCP, détection de services et bannières.
- **Vulnérabilités & Exploitation** : Recherche automatique de CVE, tests Heartbleed/Shellshock/SMBGhost.
- **Bruteforce & Authentification** : Attaques SSH, FTP, HTTP (formulaires, basic/digest), password spraying, détection de lockout.
- **Fuzzing & Injection** : Fuzzing HTTP/FTP/SMTP, détection XSS, LFI, SQLi, etc.
- **Reconnaissance & OSINT** : Google Dorks, Shodan, Sherlock, Pastebin, DNS, Transparency Report.
- **Post-exploitation & Loot** : Extraction automatique de secrets, tokens, cookies, fichiers sensibles.
- **Rapports & Export** : Génération de rapports détaillés (JSON, Markdown, HTML).
- **Outils offensifs** : Reverse shells, stagers, génération de payloads, exploits publics.

---

## 📸 Aperçu

> Ajoute ici une ou deux captures d’écran du menu principal et d’un exemple de rapport/export.

![Menu principal](./docs/screenshot_menu.png)
![Exemple de rapport](./docs/screenshot_report.png)

---

## 🛠️ Installation

```bash
git clone https://github.com/TonPseudo/HACKBOX.git
cd HACKBOX
python -m venv venv
source venv/bin/activate  # (Linux/Mac) ou .\venv\Scripts\activate (Windows)
pip install -r requirements.txt
```

---

## 🚀 Utilisation rapide

```bash
python security_toolbox/main.py
```

- Suis le menu interactif pour choisir un module (scan, brute-force, osint, etc.).
- Les exports sont générés automatiquement dans le dossier `exports/`.

---

## 📚 Documentation

- **Aide complète** : [HELP.html](./HELP.html) — Ouvre dans ton navigateur pour une doc illustrée et pédagogique.
- **Roadmap** : [ROADMAP.md](./ROADMAP.md)
- **Plan de tests** : [TEST_PLAN.md](./TEST_PLAN.md)

---

## 🧑‍💻 Exemples d’utilisation

- **Scan de ports** :
  ```bash
  python security_toolbox/main.py
  # Choisir 1. Scan & Fingerprinting
  # Entrer la cible : 192.168.1.10
  # Plage de ports : 1-1024
  ```
- **Brute-force SSH** :
  ```bash
  # Préparer users.txt et passwords.txt
  python security_toolbox/main.py
  # Choisir 3. Authentification & Bruteforce > SSH
  ```
- **OSINT Google Dorks** :
  ```bash
  python security_toolbox/main.py
  # Choisir 5. OSINT > Google Dorks
  # Domaine : site.com
  ```

---

## ⚠️ Sécurité & Légalité

- **N’utilise jamais cet outil sans autorisation explicite.**
- Destiné à l’audit légal, la formation, la recherche et l’auto-évaluation.
- Respecte la vie privée et la législation en vigueur.

---

## 📝 Contribuer

- Fork, crée une branche, propose un PR !
- Suggestions, issues et feedback bienvenus.

---

## 📄 Licence

Ce projet est sous licence MIT.

---

## 🙏 Remerciements

- [Python](https://www.python.org/)
- [colorama](https://pypi.org/project/colorama/)
- [requests](https://pypi.org/project/requests/)
- Outils et communautés open-source ayant inspiré ce projet.

---
