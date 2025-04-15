import os
import datetime
from .haveibeenpwned import check_email_pwned, export_hibp_report
from .google_dorks import generate_google_dorks, export_dorks_report
from .shodan_lookup import shodan_host_lookup, export_shodan_report
from .pastebin_leaks import search_pastebin_leaks, export_pastebin_report
from .hunterio_lookup import hunterio_search, export_hunterio_report
from .whois_lookup import whois_lookup, export_whois_report
from .github_leaks import search_github_leaks, export_github_report
from .sherlock_profiles import search_sherlock_profiles, export_sherlock_report

# TODO: Ajouter les imports pour les autres modules OSINT (github, sherlock, etc.)

def run_osint(target, target_type, api_keys=None, export_dir=None, proxies=None, batch_targets=None):
    """
    Orchestrateur OSINT : lance tous les modules disponibles sur la cible ou sur un batch de cibles.
    target_type : 'email', 'domain', 'user', 'ip', etc.
    api_keys : dict optionnel pour les API nécessitant une clé.
    export_dir : dossier d'export (défaut : ./exports/osint_<date>)
    proxies : dict proxies pour requests (optionnel, ex: {'http': 'socks5://127.0.0.1:9050'})
    batch_targets : liste de cibles à traiter en mode batch (optionnel)
    Retourne un dict global des résultats.
    """
    results = {}
    now = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    if not export_dir:
        export_dir = os.path.join(os.getcwd(), 'exports', f'osint_{now}')
    os.makedirs(export_dir, exist_ok=True)
    targets_to_process = batch_targets if batch_targets is not None else [target]
    for tgt in targets_to_process:
        tgt_results = {}
        # HaveIBeenPwned (emails)
        if target_type == 'email':
            hibp_api_key = api_keys.get('hibp') if api_keys else None
            if hibp_api_key:
                try:
                    breaches = check_email_pwned(tgt, hibp_api_key)
                    export_hibp_report(tgt, breaches, os.path.join(export_dir, f'hibp_{tgt}'))
                    tgt_results['hibp'] = breaches
                except Exception as e:
                    tgt_results['hibp'] = {'error': str(e)}
            else:
                tgt_results['hibp'] = {'error': 'Clé API HIBP absente (module désactivé)'}
            # Pastebin leaks (email)
            pastebin_results = search_pastebin_leaks(tgt)
            export_pastebin_report(tgt, pastebin_results, os.path.join(export_dir, f'pastebin_{tgt}'))
            tgt_results['pastebin'] = pastebin_results
            # GitHub leaks (email)
            github_token = api_keys.get('github') if api_keys else None
            github_results = search_github_leaks(tgt, github_token=github_token, proxies=proxies)
            export_github_report(tgt, github_results, os.path.join(export_dir, f'github_{tgt}'))
            tgt_results['github'] = github_results
            # Ajout : Hunter.io (si email = domaine connu)
            hunterio_api_key = api_keys.get('hunterio') if api_keys else None
            if hunterio_api_key and '@' in tgt:
                domain = tgt.split('@')[1]
                try:
                    hunterio_results = hunterio_search(domain, hunterio_api_key)
                    export_hunterio_report(domain, hunterio_results, os.path.join(export_dir, f'hunterio_{domain}'))
                    tgt_results['hunterio'] = hunterio_results
                except Exception as e:
                    tgt_results['hunterio'] = {'error': str(e)}
        # Google Dorks (domain)
        if target_type == 'domain':
            dorks = generate_google_dorks(tgt)
            export_dorks_report(tgt, dorks, os.path.join(export_dir, f'dorks_{tgt}'))
            tgt_results['google_dorks'] = {'dorks': dorks}
            # Hunter.io (domain)
            hunterio_api_key = api_keys.get('hunterio') if api_keys else None
            if hunterio_api_key:
                try:
                    hunterio_results = hunterio_search(tgt, hunterio_api_key)
                    export_hunterio_report(tgt, hunterio_results, os.path.join(export_dir, f'hunterio_{tgt}'))
                    tgt_results['hunterio'] = hunterio_results
                except Exception as e:
                    tgt_results['hunterio'] = {'error': str(e)}
            # Pastebin leaks (domain)
            pastebin_results = search_pastebin_leaks(tgt)
            export_pastebin_report(tgt, pastebin_results, os.path.join(export_dir, f'pastebin_{tgt}'))
            tgt_results['pastebin'] = pastebin_results
            # GitHub leaks (domain)
            github_token = api_keys.get('github') if api_keys else None
            github_results = search_github_leaks(tgt, github_token=github_token, proxies=proxies)
            export_github_report(tgt, github_results, os.path.join(export_dir, f'github_{tgt}'))
            tgt_results['github'] = github_results
            # WHOIS
            whois_data = whois_lookup(tgt)
            export_whois_report(tgt, whois_data, os.path.join(export_dir, f'whois_{tgt}'))
            tgt_results['whois'] = whois_data
            # Ajout : Google Transparency Report (disponibilité/phishing/malware)
            try:
                import requests
                resp = requests.get(f'https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site={tgt}')
                if resp.status_code == 200:
                    tgt_results['google_transparency'] = resp.text
                else:
                    tgt_results['google_transparency'] = f'Erreur HTTP {resp.status_code}'
            except Exception as e:
                tgt_results['google_transparency'] = f'Erreur : {e}'
        # Sherlock/WhatsMyName (user)
        if target_type == 'user':
            sherlock_results = search_sherlock_profiles(tgt, proxies=proxies)
            export_sherlock_report(tgt, sherlock_results, os.path.join(export_dir, f'sherlock_{tgt}'))
            tgt_results['sherlock'] = sherlock_results
            # Ajout : GitHub & GitLab username check
            github_url = f'https://github.com/{tgt}'
            gitlab_url = f'https://gitlab.com/{tgt}'
            import requests
            try:
                r_gh = requests.head(github_url, timeout=5, proxies=proxies)
                tgt_results['github_profile'] = github_url if r_gh.status_code == 200 else None
            except Exception:
                tgt_results['github_profile'] = None
            try:
                r_gl = requests.head(gitlab_url, timeout=5, proxies=proxies)
                tgt_results['gitlab_profile'] = gitlab_url if r_gl.status_code == 200 else None
            except Exception:
                tgt_results['gitlab_profile'] = None
        # Shodan (IP/domain)
        if target_type in ['ip', 'domain']:
            shodan_api_key = api_keys.get('shodan') if api_keys else None
            if shodan_api_key:
                try:
                    shodan_data = shodan_host_lookup(tgt, shodan_api_key)
                    export_shodan_report(tgt, shodan_data, os.path.join(export_dir, f'shodan_{tgt}'))
                    tgt_results['shodan'] = shodan_data
                except Exception as e:
                    tgt_results['shodan'] = {'error': str(e)}
            # Ajout : Censys (si API dispo)
            censys_id = api_keys.get('censys_id') if api_keys else None
            censys_secret = api_keys.get('censys_secret') if api_keys else None
            if censys_id and censys_secret:
                try:
                    from security_toolbox.recon.censys_recon import censys_lookup
                    censys_data = censys_lookup(tgt, censys_id, censys_secret)
                    tgt_results['censys'] = censys_data
                except Exception as e:
                    tgt_results['censys'] = {'error': str(e)}
        # TODO: Ajouter ici les autres modules OSINT (GitLab, WhatsMyName API, etc.)
        # Scoring global et recommandations
        tgt_results['score'], tgt_results['recommendations'] = osint_score_and_advice(tgt_results)
        results[tgt] = tgt_results
    return results

def osint_score_and_advice(results):
    """
    Analyse les résultats OSINT pour scorer le risque et générer des recommandations.
    Retourne (score sur 100, liste de recommandations)
    """
    score = 0
    advice = []
    # Exemples :
    if 'hibp' in results and results['hibp']:
        score += 40
        advice.append("Fuite(s) de données détectée(s) dans HaveIBeenPwned : changez les mots de passe concernés et surveillez les comptes.")
    if 'shodan' in results and results['shodan'] and isinstance(results['shodan'], dict):
        vulns = results['shodan'].get('vulns', {})
        if vulns:
            score += 30
            advice.append("Des vulnérabilités connues sont exposées sur l'IP/domaine (Shodan). Mettez à jour ou isolez les services concernés.")
    if 'github' in results and isinstance(results['github'], list) and results['github']:
        score += 20
        advice.append("Des traces ou tokens publics ont été trouvés sur GitHub. Révoquez les secrets exposés et supprimez les fichiers concernés.")
    if 'hunterio' in results and isinstance(results['hunterio'], list) and results['hunterio']:
        score += 10
        advice.append("Des emails d'entreprise sont publics (Hunter.io). Surveillez les risques de phishing.")
    if 'pastebin' in results and results['pastebin']:
        score += 10
        advice.append("Des traces de la cible ont été trouvées sur Pastebin. Analysez les pastes pour détecter d'éventuelles fuites.")
    if 'sherlock' in results and results['sherlock']:
        score += 5
        advice.append("Des profils publics ont été trouvés sur plusieurs plateformes. Vérifiez la cohérence des informations exposées.")
    if score > 100:
        score = 100
    if not advice:
        advice.append("Aucune fuite ou exposition critique détectée. Continuez la veille et appliquez les bonnes pratiques de sécurité.")
    return score, advice

# Exemple d'utilisation :
# results = run_osint('test@example.com', 'email', api_keys={'hibp': 'VOTRE_API_KEY'})
# results = run_osint('example.com', 'domain')
