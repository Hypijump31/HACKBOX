# Plan de tests et avancement du projet Security Toolbox

| Fonctionnalité                | Test(s) prévus                                   | Test(s) implémentés | Test(s) passés |
|-------------------------------|-------------------------------------------------|---------------------|---------------|
| **Scan de ports**             | Cas nominal, ports fermés, IP invalide, erreurs | Oui                 | Oui           |
| **Analyse de vulnérabilités** | Cas nominal (service trouvé), aucun service     | Oui                 | À vérifier    |
| **Test d'authentification**   | SSH/HTTP : succès, échec, limite atteinte       | Non                 | Non           |
| **Sniffing réseau**           | Capture simple, erreur interface, anomalie      | Non                 | Non           |
| **Rapport automatisé**        | Génération TXT/PDF, contenu, erreur écriture    | Non                 | Non           |
| **Reconnaissance passive**    | Shodan & Censys, clé API valide/invalide       | Oui                 | Oui           |
| **Fuzzing HTTP**              | GET/POST, paramètres, réponses suspectes        | Oui                 | Oui           |
| **Export avancé**             | JSON, Markdown, HTML                            | Oui                 | Oui           |
| **Exploit launcher**          | Lancement d'un exploit externe                  | Oui                 | Oui           |
| **Reverse shell generator**   | Génération reverse shell                        | Oui                 | Oui           |
| **Stager generator**          | Génération stager Empire/Metasploit            | Oui                 | Oui           |
| **Loot**                      | Automatisation du loot                          | Oui                 | Oui           |
| **Escalade de privilèges**    | Escalade de privilèges                          | Oui                 | Oui           |

## Détail des tests réalisés

### Scan de ports
- Scan mocké (résultat attendu)
- Scan IP invalide (erreur)

### Analyse de vulnérabilités
- Mock API CVE (résultat attendu)
- Aucun service (résultat vide)

### Test Reconnaissance passive (Shodan & Censys)
- [X] Vérifier que l'option 7 du menu lance la requête sur l'IP cible
- [X] Tester avec clé API valide/invalide (Shodan & Censys)
- [X] Contrôler l'affichage des ports, services, vulnérabilités
- [X] Vérifier la gestion des erreurs API

### Test Fuzzing HTTP
- [X] Vérifier que l'option 8 du menu lance le fuzzing sur une URL cible
- [X] Tester avec GET et POST, avec/sans paramètres
- [X] Contrôler la détection des réponses suspectes (erreurs 500, reflets XSS, etc.)
- [X] Tester la robustesse avec des URLs invalides

### Test Export avancé des résultats de fuzzing
- [X] Vérifier l’export automatique après chaque fuzzing HTTP
- [X] Vérifier la présence des fichiers .json, .md, .html
- [X] Contrôler la présence des métadonnées (URL, méthode, paramètres, date, total)
- [X] Vérifier l’intégrité des données exportées et la lisibilité pro (Markdown/HTML)
- [X] Tester le nommage sécurisé des fichiers (pas de caractères spéciaux problématiques)

### Test Fuzzers additionnels (à venir)
- [ ] Fuzzing FTP, SMTP, etc.

### Test intégration avancée rapport/vulnérabilité (à venir)
- [ ] Fusion des résultats de fuzzing/recon avec les rapports globaux

## Offensive & Exploitation

- [x] Test : Lancement d'un exploit externe (commande, export résultat)
- [x] Test : Génération reverse shell (tous langages, export)
- [x] Test : Génération stager Empire/Metasploit (tous types, export)
- [x] Test : Automatisation du loot (scan, dump, extraction tokens, export rapport)
- [x] Test : Escalade de privilèges (détection vecteurs, export rapport)
- [ ] Test : OSINT avancé (à venir)

---

### Récapitulatif
- Les modules offensifs sont testés pour : génération payload, export, robustesse interface.
- Les modules loot et escalation sont testés pour : détection, extraction, export rapport.
- Les modules à venir (OSINT avancé) seront ajoutés dès leur implémentation.

---

**Mise à jour automatique à chaque nouvelle fonctionnalité/test.**
