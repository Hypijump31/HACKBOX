# 🗒️ Roadmap HACKBOX – Pentest Toolkit Avancé

## Fingerprinting & Recon
- [x] Fingerprinting multi-protocoles (HTTP, SSH, FTP, SMTP, POP3, IMAP, MySQL, PostgreSQL, Redis, etc.)
- [x] Détection de technologies web (headers, cookies, JS, CMS, frameworks)
- [x] Détection de versions avancée (HTTP/SSL fingerprint, banners custom)
- [x] Recherche de sous-domaines, DNS bruteforce, reverse IP

## Vulnérabilités & Exploitation
- [x] Recherche CVE avancée (service+version, liens exploit-db/metasploit)
- [x] Export JSON/Markdown/HTML + résumé global/conseils
- [x] Scan de vulnérabilités emblématiques (Heartbleed, Shellshock, SMBGhost, etc.)
- [x] Téléchargement/Exécution automatisée de POCs/exploits publics (si critique)
- [x] Fuzzing HTTP/FTP (404 bypass, LFI, RCE, etc.)

## Authentification & Bruteforce
- [x] Brute-force SSH (user/pass, gestion timing/erreurs)
- [x] Brute-force FTP
- [x] Brute-force HTTP (formulaire, Basic/Digest)
- [x] Password spraying

## Recherche passive & OSINT
- [x] Intégration Shodan/Censys pour IP/domaines
- [x] HaveIBeenPwned/Hunter.io pour leaks et emails exposés

## Post-exploitation & Automatisation
- [x] Téléchargement automatique de loot (hashes, fichiers sensibles, config leaks)
- [x] Génération de scripts Metasploit/Empire prêts à l’emploi

## Offensive & Post-Exploitation
- [x] Lancement d'exploits externes (Metasploit, nmap, scripts…)
- [x] Générateur de reverse shells (bash, python, PHP, PowerShell, socat, nc…)
- [x] Générateur de stagers Empire/Metasploit (powershell, macro, unix…)
- [x] Automatisation du loot (téléchargement de fichiers sensibles, extraction tokens/cookies)
- [x] Escalade de privilèges & bypass (checklists, scripts, persistence)

## [X] Reconnaissance passive (Shodan & Censys)
- Intégration des modules shodan_recon.py et censys_recon.py
- Menu principal : option 7 pour interrogation API Shodan/Censys
- Affichage des résultats principaux (ports, services, vulnérabilités)
- Clés API configurables dans config.yaml

## [X] Fuzzing HTTP avancé
- Module fuzz/http_fuzzer.py avec payloads XSS, SQLi, LFI, RCE, etc.
- Menu principal : option 8 pour fuzzing HTTP sur URL cible
- Détection et affichage des réponses suspectes

## [X] Export avancé des résultats de fuzzing
- Export automatique des résultats de fuzzing HTTP en JSON, Markdown, HTML après chaque test
- Métadonnées complètes (URL, méthode, paramètres, date, total)
- Nommage de fichier sécurisé et standardisé

## [X] Fuzzers additionnels
- Fuzzing avancé pour FTP (commandes, injections, énumération, export pro)
- Fuzzing avancé pour SMTP (commandes, injections, open relay, export pro)
- Menu principal : options 9 (FTP) et 10 (SMTP) avec export JSON/Markdown/HTML

## [X] Intégration avancée rapport/vulnérabilité
- Rapport global professionnel (scan, vuln, recon, fuzz HTTP/FTP/SMTP)
- Export automatique JSON, Markdown, HTML avec sommaire, sections, métadonnées
- Agrégation automatique des résultats de session et fichiers d’export
- Option dédiée dans le menu principal

## [ ] Authentification & Bruteforce avancé
- Brute-force SSH (gestion timing, erreurs, export pro)
- Brute-force FTP (user/pass, export pro)
- Brute-force HTTP (formulaire, Basic/Digest, export pro)
- Password spraying (multi-protocole, export pro)
- Détection de lockout, alertes, limitations

## [ ] OSINT avancé & Leaks
- Intégration HaveIBeenPwned/Hunter.io pour leaks et emails exposés
- Modules pour Google Dorks, GitHub leaks, Pastebin, etc.
- Agrégation et export dans le rapport global

## [ ] Personnalisation & UX pro
- Personnalisation du rapport global (sections, tri, PDF, branding)
- Interface graphique (GUI) ou API REST
- Mode batch/scriptable pour automatisation CI/CD

## À venir
- [ ] OSINT avancé (HaveIBeenPwned, Google Dorks, GitHub, Pastebin…)

---

### Dernières évolutions majeures
- Menus clairs à sous-menus, navigation thématique
- Modules brute-force SSH/FTP/HTTP, password spraying, détection lockout
- Offensive : exploit launcher, reverse shell, stager generator, loot auto, escalation

---

# Suivi d’avancement
- [x] = Fait
- [ ] = À faire
- [~] = En cours

---

Cette roadmap est mise à jour à chaque étape majeure du développement.
Pour toute modification de priorité ou ajout de fonctionnalité, indique-le simplement dans ta prochaine demande !
