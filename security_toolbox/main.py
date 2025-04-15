import sys
from security_toolbox.scan.port_scanner import PortScanner
from security_toolbox.vuln.vuln_scanner import VulnScanner
from security_toolbox.auth.auth_tester import AuthTester
from security_toolbox.sniff.sniffer import NetworkSniffer
from security_toolbox.reporter import Reporter
from security_toolbox.config import load_config
from security_toolbox.osint.osint_orchestrator import run_osint
from security_toolbox.osint.osint_reporter import export_osint_global_report

from pyfiglet import Figlet
from colorama import init, Fore, Style, Back
from tqdm import tqdm
import time
import datetime
import os
init(autoreset=True)

MENU_BORDER = f"{Fore.BLUE}{'═'*56}{Style.RESET_ALL}"
MENU_HEADER = f"{Fore.CYAN}{Style.BRIGHT}║   HACKBOX \033[90mBy HYPIJUMP\033[0m - Pentest Toolkit   {Style.RESET_ALL}"

STATUS_ICONS = {
    'info': f"{Fore.CYAN}ℹ{Style.RESET_ALL}",
    'success': f"{Fore.GREEN}✔{Style.RESET_ALL}",
    'error': f"{Fore.RED}✖{Style.RESET_ALL}",
    'warn': f"{Fore.YELLOW}!{Style.RESET_ALL}",
    'scan': f"{Fore.MAGENTA}⚡{Style.RESET_ALL}"
}


def print_ascii_art():
    f = Figlet(font='slant')
    hackbox_ascii = f.renderText('HACKBOX')
    print(f"{Fore.GREEN}{Style.BRIGHT}{hackbox_ascii}{Style.RESET_ALL}")


def print_main_menu():
    print(f"{MENU_BORDER}")
    print(MENU_HEADER)
    print(f"{MENU_BORDER}")
    print(f"║ {Fore.MAGENTA}1{Style.RESET_ALL}. Scan & Fingerprinting  {Fore.LIGHTBLACK_EX}- Découverte des ports, services, bannières{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}2{Style.RESET_ALL}. Vulnérabilités & Exploitation  {Fore.LIGHTBLACK_EX}- Recherche CVE, exploits, Heartbleed, Shellshock…{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}3{Style.RESET_ALL}. Authentification & Bruteforce  {Fore.LIGHTBLACK_EX}- SSH, FTP, HTTP, spraying, lockout…{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}4{Style.RESET_ALL}. Fuzzing & Tests d'injection  {Fore.LIGHTBLACK_EX}- XSS, LFI, SQLi, FTP/SMTP fuzz…{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}5{Style.RESET_ALL}. Reconnaissance & OSINT  {Fore.LIGHTBLACK_EX}- Shodan, Censys, leaks, Google Dorks…{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}6{Style.RESET_ALL}. Post-exploitation & Loot  {Fore.LIGHTBLACK_EX}- Extraction, scripts, tokens, cookies…{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}7{Style.RESET_ALL}. Rapports & Export  {Fore.LIGHTBLACK_EX}- Génération, export, branding, dossiers datés…{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}8{Style.RESET_ALL}. Outils offensifs & Exploitation  {Fore.LIGHTBLACK_EX}- Exploits, reverse shells, stagers…{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}9{Style.RESET_ALL}. Loot automatique  {Fore.LIGHTBLACK_EX}- Dump fichiers sensibles, tokens, cookies…{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}10{Style.RESET_ALL}. Escalade de privilèges  {Fore.LIGHTBLACK_EX}- sudo, SUID, UAC, services…{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}11{Style.RESET_ALL}. Google Dorks  {Fore.LIGHTBLACK_EX}- Génération automatique de dorks ciblés{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}H{Style.RESET_ALL}. Aide  {Fore.LIGHTBLACK_EX}- Documentation & support (ouvre une page web){Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}0{Style.RESET_ALL}. Quitter")
    print(f"║ ? pour réafficher ce menu à tout moment.")
    print(f"{MENU_BORDER}\n")


def print_bruteforce_menu():
    print(f"{MENU_BORDER}")
    print(f"║  Authentification & Bruteforce  ")
    print(f"{MENU_BORDER}")
    print(f"║ {Fore.MAGENTA}1{Style.RESET_ALL}. Brute-force SSH {Fore.LIGHTBLACK_EX}- user/pass, export, gestion erreurs{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}2{Style.RESET_ALL}. Brute-force FTP {Fore.LIGHTBLACK_EX}- user/pass, export, gestion erreurs{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}3{Style.RESET_ALL}. Brute-force HTTP {Fore.LIGHTBLACK_EX}- formulaire, Basic, Digest, flags custom{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}4{Style.RESET_ALL}. Password Spraying {Fore.LIGHTBLACK_EX}- multi-cibles/protocoles, export pro{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}5{Style.RESET_ALL}. Détection lockout/alertes {Fore.LIGHTBLACK_EX}- blocages, délais, codes erreurs{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}0{Style.RESET_ALL}. Retour menu principal")
    print(f"{MENU_BORDER}\n")


def print_fuzzing_menu():
    print(f"{MENU_BORDER}")
    print(f"║  Fuzzing & Tests d'injection  ")
    print(f"{MENU_BORDER}")
    print(f"║ {Fore.MAGENTA}1{Style.RESET_ALL}. Fuzzing HTTP {Fore.LIGHTBLACK_EX}- XSS, LFI, SQLi, path, params…{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}2{Style.RESET_ALL}. Fuzzing FTP {Fore.LIGHTBLACK_EX}- commandes, injections, énumération{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}3{Style.RESET_ALL}. Fuzzing SMTP {Fore.LIGHTBLACK_EX}- commandes, open relay, injections{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}0{Style.RESET_ALL}. Retour menu principal")
    print(f"{MENU_BORDER}\n")


def print_osint_menu():
    print(f"{MENU_BORDER}")
    print(f"║  Reconnaissance & OSINT  ")
    print(f"{MENU_BORDER}")
    print(f"║ {Fore.MAGENTA}1{Style.RESET_ALL}. Reconnaissance passive {Fore.LIGHTBLACK_EX}- Shodan, Censys, fingerprinting{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}2{Style.RESET_ALL}. Recherche leaks/OSINT avancé {Fore.LIGHTBLACK_EX}- HaveIBeenPwned, Google Dorks, GitHub, Pastebin…{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}0{Style.RESET_ALL}. Retour menu principal")
    print(f"{MENU_BORDER}\n")


def print_report_menu():
    print(f"{MENU_BORDER}")
    print(f"║  Rapports & Export  ")
    print(f"{MENU_BORDER}")
    print(f"║ {Fore.MAGENTA}1{Style.RESET_ALL}. Rapport global {Fore.LIGHTBLACK_EX}- scan, vuln, recon, fuzz, brute-force…{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}2{Style.RESET_ALL}. Générer rapport personnalisé {Fore.LIGHTBLACK_EX}- sections, branding, format…{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}0{Style.RESET_ALL}. Retour menu principal")
    print(f"{MENU_BORDER}\n")


def print_offensive_menu():
    print(f"{MENU_BORDER}")
    print(f"║  Outils offensifs & Exploitation  ")
    print(f"{MENU_BORDER}")
    print(f"║ {Fore.MAGENTA}1{Style.RESET_ALL}. Lancer un exploit externe {Fore.LIGHTBLACK_EX}- Metasploit, nmap script, exploit.py…{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}2{Style.RESET_ALL}. Générer un reverse shell {Fore.LIGHTBLACK_EX}- Bash, Python, PowerShell, PHP…{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}3{Style.RESET_ALL}. Générer un stager Empire/Metasploit {Fore.LIGHTBLACK_EX}- Windows, Linux, macro…{Style.RESET_ALL}")
    print(f"║ {Fore.MAGENTA}0{Style.RESET_ALL}. Retour menu principal")
    print(f"{MENU_BORDER}\n")


def print_status(msg, kind='info'):
    icon = STATUS_ICONS.get(kind, STATUS_ICONS['info'])
    print(f"{icon} {msg}{Style.RESET_ALL}")


def print_scan_results(scan_results):
    print(f"\n{Fore.MAGENTA}{'─'*36}\nRésultats du scan de ports :\n{'─'*36}{Style.RESET_ALL}")
    for port, info in sorted(scan_results.items(), key=lambda x: int(x[0])):
        status = info['status'] if isinstance(info, dict) else info
        if status == 'open':
            color = Fore.GREEN
            symbol = '✔'
        elif status == 'closed':
            color = Fore.RED
            symbol = '✖'
        else:
            color = Fore.YELLOW
            symbol = '!'
        banner = info.get('banner') if isinstance(info, dict) else None
        service = info.get('service') if isinstance(info, dict) else None
        version = info.get('version') if isinstance(info, dict) else None
        technologies = info.get('technologies') if isinstance(info, dict) else None
        extra = ''
        if banner:
            extra += f" | Banner: {banner}"
        if service:
            extra += f" | Service: {service}"
        if version:
            extra += f" | Version: {version}"
        if technologies and len(technologies) > 0:
            extra += f" | Tech: {', '.join(technologies)}"
        print(f"  {color}Port {port:<5} {symbol}  {status}{extra}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'─'*36}{Style.RESET_ALL}\n")


def print_vuln_summary(summary):
    print(f"{Fore.CYAN}{'═'*60}\nRésumé de l'analyse de vulnérabilités :\n{'═'*60}{Style.RESET_ALL}")
    print(f"Total failles : {summary['total']}")
    print(f"Critiques : {Fore.RED}{summary['critical']}{Style.RESET_ALL} | Hautes : {Fore.YELLOW}{summary['high']}{Style.RESET_ALL} | Moyennes : {Fore.MAGENTA}{summary['medium']}{Style.RESET_ALL} | Faibles : {Fore.GREEN}{summary['low']}{Style.RESET_ALL}")
    print(f"Score CVSS max : {summary['max_cvss']}")
    print(f"Conseils :")
    for advice in summary['advices']:
        print(f"  - {advice}")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}\n")


def print_vuln_results(vuln_results, paginate=30):
    if not vuln_results:
        print_status("Aucune vulnérabilité critique détectée sur les services scannés.", 'success')
        return
    print(f"\n{Fore.RED}{'═'*60}\nRésultats de l'analyse de vulnérabilités :\n{'═'*60}{Style.RESET_ALL}")
    header = f"{Fore.YELLOW}{'Port':<6}{'Service':<12}{'Version':<18}{'CVE':<18}{'CVSS':<6}{'Résumé':<40}{Style.RESET_ALL}"
    print(header)
    print(f"{Fore.RED}{'─'*60}{Style.RESET_ALL}")
    for i, v in enumerate(vuln_results):
        cvss = v['cvss']
        if cvss == '-' or cvss == '' or cvss is None:
            color = Fore.WHITE
        else:
            try:
                score = float(cvss)
                if score >= 9:
                    color = Fore.RED + Style.BRIGHT
                elif score >= 7:
                    color = Fore.RED
                elif score >= 4:
                    color = Fore.YELLOW
                else:
                    color = Fore.GREEN
            except Exception:
                color = Fore.WHITE
        print(f"{Fore.CYAN}{str(v['port']):<6}{Fore.MAGENTA}{(v['service'] or '-'):<12}{Fore.BLUE}{(v['version'] or '-'):<18}{Fore.YELLOW}{v['cve_id']:<18}{color}{str(v['cvss']):<6}{Fore.WHITE}{v['summary']:<40}{Style.RESET_ALL}")
        # Affiche les liens exploit-db/metasploit si présents
        if v.get('exploitdb') or v.get('metasploit'):
            print(f"    {Fore.CYAN}ExploitDB: {v.get('exploitdb', '-')}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}Metasploit: {v.get('metasploit', '-')}{Style.RESET_ALL}")
        if (i+1) % paginate == 0 and (i+1) < len(vuln_results):
            input(f"{Fore.YELLOW}-- Appuyez sur Entrée pour voir la suite --{Style.RESET_ALL}")
    print(f"{Fore.RED}{'═'*60}{Style.RESET_ALL}\n")


def parse_ports(port_str):
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end)+1))
        else:
            if part.isdigit():
                ports.add(int(part))
    return sorted(ports)


def main():
    print_ascii_art()
    print_main_menu()
    config = load_config()
    scan_results = {}
    vuln_results = []
    while True:
        print(f"{Fore.BLUE}{'─'*56}{Style.RESET_ALL}")
        choix = input(f"{Fore.CYAN}Votre choix : {Style.RESET_ALL}").strip()
        if choix == "?":
            print_main_menu()
            continue
        if choix == "1":
            print_status("Mode : Scan de ports", 'scan')
            target = input(f"{Fore.CYAN}Cible (IP ou domaine) [défaut: localhost] : {Style.RESET_ALL}").strip()
            if not target:
                target = "localhost"
            port_input = input(f"{Fore.CYAN}Ports à scanner (ex : 22,80,443 ou 1-1024) [défaut: 1-1024] : {Style.RESET_ALL}").strip()
            if port_input:
                ports = parse_ports(port_input)
            else:
                ports = list(range(1, 1025))
            print_status(f"Scan en cours sur {target}...", 'scan')
            scanner = PortScanner(target, config)
            scan_results = {}
            with tqdm(total=len(ports), desc=f"{Fore.MAGENTA}Scan de ports{Style.RESET_ALL}", ncols=70, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]') as pbar:
                def update():
                    pbar.update(1)
                results = scanner.scan_ports_multithread(ports, max_workers=100, tqdm_callback=update)
                scan_results.update(results)
            print_scan_results(scan_results)
        elif choix == "2":
            if not scan_results:
                print_status("Lancez d'abord un scan de ports pour détecter les services !", 'warn')
                continue
            print_status("Analyse de vulnérabilités en cours...", 'scan')
            services = []
            for port, info in scan_results.items():
                if isinstance(info, dict) and info.get('status') == 'open':
                    services.append({
                        "port": int(port),
                        "service": info.get('service'),
                        "banner": info.get('banner'),
                        "version": info.get('version')
                    })
            vuln_scanner = VulnScanner(api_url=config.get("vuln", {}).get("cve_api_url", "https://cve.circl.lu/api"), config=config)
            vuln_results = []
            with tqdm(total=len(services), desc=f"{Fore.YELLOW}Analyse vulnérabilités{Style.RESET_ALL}", ncols=70, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]') as pbar:
                for svc in services:
                    vuln_results.extend(vuln_scanner.scan([svc]))
                    # --- Ajout tests emblématiques ---
                    port = svc.get('port')
                    host = target
                    try:
                        if svc.get('service') == 'https' or port == 443:
                            from security_toolbox.vuln.heartbleed import check_heartbleed
                            hb = check_heartbleed(host, port)
                            if hb is True:
                                vuln_results.append({
                                    'port': port,
                                    'service': 'https',
                                    'version': svc.get('version') or '-',
                                    'cve_id': 'CVE-2014-0160',
                                    'summary': 'Heartbleed: fuite mémoire critique via TLS',
                                    'cvss': '9.4',
                                    'url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160',
                                    'exploitdb': 'https://www.exploit-db.com/exploits/32745',
                                    'metasploit': 'https://www.rapid7.com/db/modules/auxiliary/scanner/ssl/openssl_heartbleed/'
                                })
                        if svc.get('service') == 'http' or port == 80:
                            from security_toolbox.vuln.shellshock import check_shellshock
                            sh = check_shellshock(host, port)
                            if sh is True:
                                vuln_results.append({
                                    'port': port,
                                    'service': 'http',
                                    'version': svc.get('version') or '-',
                                    'cve_id': 'CVE-2014-6271',
                                    'summary': 'Shellshock: exécution de commandes via Bash',
                                    'cvss': '10.0',
                                    'url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271',
                                    'exploitdb': 'https://www.exploit-db.com/exploits/34766',
                                    'metasploit': 'https://www.rapid7.com/db/modules/exploit/multi/http/apache_mod_cgi_bash_env_exec/'
                                })
                        if svc.get('service') == 'smb' or port == 445:
                            from security_toolbox.vuln.smbghost import check_smbghost
                            smb = check_smbghost(host, port)
                            if smb is True:
                                vuln_results.append({
                                    'port': port,
                                    'service': 'smb',
                                    'version': svc.get('version') or '-',
                                    'cve_id': 'CVE-2020-0796',
                                    'summary': 'SMBGhost: exécution de code à distance sur SMBv3',
                                    'cvss': '10.0',
                                    'url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0796',
                                    'exploitdb': 'https://www.exploit-db.com/exploits/48225',
                                    'metasploit': 'https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_ms17_010/'
                                })
                    except Exception as e:
                        print_status(f"Erreur test vulnérabilité emblématique: {e}", 'warn')
                    pbar.update(1)
            print_vuln_results(vuln_results)
            summary = vuln_scanner.summarize(vuln_results)
            print_vuln_summary(summary)
            # Export automatique des résultats
            target_name = target.replace('.', '_').replace(':', '_')
            export_base = vuln_scanner.export_results(vuln_results, target=target_name)
            print_status(f"Résultats exportés :\n- {export_base}.json\n- {export_base}.md\n- {export_base}.html", 'info')
        elif choix == "3":
            print_bruteforce_menu()
            bruteforce_choix = input(f"{Fore.CYAN}Votre choix : {Style.RESET_ALL}").strip()
            if bruteforce_choix == "1":
                print_status("Mode : Brute-force SSH avancé", 'scan')
                host = input(f"{Fore.CYAN}Cible SSH (IP ou domaine) : {Style.RESET_ALL}").strip()
                port = input(f"{Fore.CYAN}Port [22] : {Style.RESET_ALL}").strip()
                port = int(port) if port else 22
                userfile = input(f"{Fore.CYAN}Fichier userlist (1 user/ligne) : {Style.RESET_ALL}").strip()
                passfile = input(f"{Fore.CYAN}Fichier passlist (1 mot de passe/ligne) : {Style.RESET_ALL}").strip()
                try:
                    with open(userfile, encoding='utf-8') as f:
                        userlist = [line.strip() for line in f if line.strip()]
                    with open(passfile, encoding='utf-8') as f:
                        passlist = [line.strip() for line in f if line.strip()]
                except Exception as e:
                    print_status(f"Erreur lecture fichiers : {e}", 'error')
                    return
                from security_toolbox.bruteforce.ssh_bruteforce import ssh_bruteforce, export_ssh_bruteforce_results
                print_status(f"Brute-force SSH en cours sur {host}:{port}...", 'scan')
                data = ssh_bruteforce(host, port=port, userlist=userlist, passlist=passlist)
                valid = data.get('valid', [])
                if valid:
                    print(f"{Fore.GREEN}--- Credentials valides trouvés : ---{Style.RESET_ALL}")
                    for v in valid:
                        print(f"{v['user']} : {v['password']}")
                else:
                    print_status("Aucun credentials valide trouvé.", 'success')
                # Export automatique
                import os
                safe_host = host.replace('.', '_').replace(':', '_')
                export_base = os.path.join(os.getcwd(), f"bruteforce_ssh_{safe_host}_{port}")
                export_ssh_bruteforce_results(data, export_base)
                print_status(f"Résultats exportés :\n- {export_base}.json\n- {export_base}.md\n- {export_base}.html", 'info')
            elif bruteforce_choix == "2":
                print_status("Mode : Brute-force FTP avancé", 'scan')
                host = input(f"{Fore.CYAN}Cible FTP (IP ou domaine) : {Style.RESET_ALL}").strip()
                port = input(f"{Fore.CYAN}Port [21] : {Style.RESET_ALL}").strip()
                port = int(port) if port else 21
                userfile = input(f"{Fore.CYAN}Fichier userlist (1 user/ligne) : {Style.RESET_ALL}").strip()
                passfile = input(f"{Fore.CYAN}Fichier passlist (1 mot de passe/ligne) : {Style.RESET_ALL}").strip()
                try:
                    with open(userfile, encoding='utf-8') as f:
                        userlist = [line.strip() for line in f if line.strip()]
                    with open(passfile, encoding='utf-8') as f:
                        passlist = [line.strip() for line in f if line.strip()]
                except Exception as e:
                    print_status(f"Erreur lecture fichiers : {e}", 'error')
                    return
                from security_toolbox.bruteforce.ftp_bruteforce import ftp_bruteforce, export_ftp_bruteforce_results
                print_status(f"Brute-force FTP en cours sur {host}:{port}...", 'scan')
                data = ftp_bruteforce(host, port=port, userlist=userlist, passlist=passlist)
                valid = data.get('valid', [])
                if valid:
                    print(f"{Fore.GREEN}--- Credentials valides trouvés : ---{Style.RESET_ALL}")
                    for v in valid:
                        print(f"{v['user']} : {v['password']}")
                else:
                    print_status("Aucun credentials valide trouvé.", 'success')
                # Export automatique
                import os
                safe_host = host.replace('.', '_').replace(':', '_')
                export_base = os.path.join(os.getcwd(), f"bruteforce_ftp_{safe_host}_{port}")
                export_ftp_bruteforce_results(data, export_base)
                print_status(f"Résultats exportés :\n- {export_base}.json\n- {export_base}.md\n- {export_base}.html", 'info')
            elif bruteforce_choix == "3":
                print_status("Mode : Brute-force HTTP avancé", 'scan')
                url = input(f"{Fore.CYAN}URL cible : {Style.RESET_ALL}").strip()
                method = input(f"{Fore.CYAN}Méthode [POST/GET] [POST] : {Style.RESET_ALL}").strip().upper() or 'POST'
                userfile = input(f"{Fore.CYAN}Fichier userlist (1 user/ligne) : {Style.RESET_ALL}").strip()
                passfile = input(f"{Fore.CYAN}Fichier passlist (1 mot de passe/ligne) : {Style.RESET_ALL}").strip()
                user_field = input(f"{Fore.CYAN}Nom du champ utilisateur [username] : {Style.RESET_ALL}").strip() or 'username'
                pass_field = input(f"{Fore.CYAN}Nom du champ mot de passe [password] : {Style.RESET_ALL}").strip() or 'password'
                auth_type = input(f"{Fore.CYAN}Type d'auth (form/basic/digest) [form] : {Style.RESET_ALL}").strip().lower() or 'form'
                success_flag = input(f"{Fore.CYAN}Mot-clé succès (laisser vide si inconnu) : {Style.RESET_ALL}").strip() or None
                fail_flag = input(f"{Fore.CYAN}Mot-clé échec (laisser vide si inconnu) : {Style.RESET_ALL}").strip() or None
                try:
                    with open(userfile, encoding='utf-8') as f:
                        userlist = [line.strip() for line in f if line.strip()]
                    with open(passfile, encoding='utf-8') as f:
                        passlist = [line.strip() for line in f if line.strip()]
                except Exception as e:
                    print_status(f"Erreur lecture fichiers : {e}", 'error')
                    return
                from security_toolbox.bruteforce.http_bruteforce import http_bruteforce, export_http_bruteforce_results
                print_status(f"Brute-force HTTP en cours sur {url}...", 'scan')
                data = http_bruteforce(url, userlist=userlist, passlist=passlist, method=method, user_field=user_field, pass_field=pass_field, success_flag=success_flag, fail_flag=fail_flag, auth_type=(None if auth_type=='form' else auth_type))
                valid = data.get('valid', [])
                if valid:
                    print(f"{Fore.GREEN}--- Credentials valides trouvés : ---{Style.RESET_ALL}")
                    for v in valid:
                        print(f"{v['user']} : {v['password']}")
                else:
                    print_status("Aucun credentials valide trouvé.", 'success')
                # Export automatique
                import os
                safe_url = url.replace('://', '_').replace('/', '_').replace(':', '_')
                export_base = os.path.join(os.getcwd(), f"bruteforce_http_{safe_url}")
                export_http_bruteforce_results(data, export_base)
                print_status(f"Résultats exportés :\n- {export_base}.json\n- {export_base}.md\n- {export_base}.html", 'info')
            elif bruteforce_choix == "4":
                print_status("Mode : Password Spraying multi-protocole", 'scan')
                proto = input(f"{Fore.CYAN}Protocole (ssh/ftp/http) : {Style.RESET_ALL}").strip().lower()
                targets_file = input(f"{Fore.CYAN}Fichier cible(s) (1 IP/host/URL par ligne) : {Style.RESET_ALL}").strip()
                userfile = input(f"{Fore.CYAN}Fichier userlist (1 user/ligne) : {Style.RESET_ALL}").strip()
                password = input(f"{Fore.CYAN}Mot de passe unique à tester : {Style.RESET_ALL}").strip()
                http_method = 'POST'
                http_url = None
                user_field = 'username'
                pass_field = 'password'
                success_flag = None
                fail_flag = None
                auth_type = None
                if proto == 'http':
                    http_url = input(f"{Fore.CYAN}URL cible HTTP (si différente de la cible) : {Style.RESET_ALL}").strip()
                    http_method = input(f"{Fore.CYAN}Méthode [POST/GET] [POST] : {Style.RESET_ALL}").strip().upper() or 'POST'
                    user_field = input(f"{Fore.CYAN}Nom du champ utilisateur [username] : {Style.RESET_ALL}").strip() or 'username'
                    pass_field = input(f"{Fore.CYAN}Nom du champ mot de passe [password] : {Style.RESET_ALL}").strip() or 'password'
                    auth_type = input(f"{Fore.CYAN}Type d'auth (form/basic/digest) [form] : {Style.RESET_ALL}").strip().lower() or 'form'
                    success_flag = input(f"{Fore.CYAN}Mot-clé succès (laisser vide si inconnu) : {Style.RESET_ALL}").strip() or None
                    fail_flag = input(f"{Fore.CYAN}Mot-clé échec (laisser vide si inconnu) : {Style.RESET_ALL}").strip() or None
                try:
                    with open(targets_file, encoding='utf-8') as f:
                        targets = [line.strip() for line in f if line.strip()]
                    with open(userfile, encoding='utf-8') as f:
                        userlist = [line.strip() for line in f if line.strip()]
                except Exception as e:
                    print_status(f"Erreur lecture fichiers : {e}", 'error')
                    return
                from security_toolbox.bruteforce.password_spraying import password_spraying, export_password_spraying_results
                print_status(f"Password spraying en cours sur {len(targets)} cibles...", 'scan')
                data = password_spraying(targets, userlist, password, protocol=proto, http_method=http_method, http_url=http_url, user_field=user_field, pass_field=pass_field, success_flag=success_flag, fail_flag=fail_flag, auth_type=(None if auth_type=='form' else auth_type))
                valid = data.get('valid', [])
                if valid:
                    print(f"{Fore.GREEN}--- Credentials valides trouvés : ---{Style.RESET_ALL}")
                    for v in valid:
                        print(f"{v['host']} / {v['user']} : {v['password']}")
                else:
                    print_status("Aucun credentials valide trouvé.", 'success')
                # Export automatique
                import os
                export_base = os.path.join(os.getcwd(), f"password_spraying_{proto}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
                export_password_spraying_results(data, export_base)
                print_status(f"Résultats exportés :\n- {export_base}.json\n- {export_base}.md\n- {export_base}.html", 'info')
            elif bruteforce_choix == "5":
                print_status("Mode : Détection lockout/alertes brute-force", 'scan')
                result_file = input(f"{Fore.CYAN}Fichier résultats brute-force (JSON) : {Style.RESET_ALL}").strip()
                try:
                    import json
                    with open(result_file, encoding='utf-8') as f:
                        data = json.load(f)
                    results = data['results'] if 'results' in data else data
                except Exception as e:
                    print_status(f"Erreur lecture fichier : {e}", 'error')
                    return
                from security_toolbox.bruteforce.lockout_detection import detect_lockout, export_lockout_alerts
                alerts = detect_lockout(results)
                if alerts['alerts']:
                    print(f"{Fore.YELLOW}--- Alertes lockout détectées : ---{Style.RESET_ALL}")
                    for a in alerts['alerts']:
                        print(f"[{a['type'].upper()}] {a['msg']}")
                else:
                    print_status("Aucune alerte détectée.", 'success')
                # Export
                import os
                export_base = os.path.join(os.getcwd(), f"lockout_alerts_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
                export_lockout_alerts(alerts, export_base)
                print_status(f"Alertes exportées :\n- {export_base}.json\n- {export_base}.md", 'info')
            elif bruteforce_choix == "0":
                print_main_menu()
        elif choix == "4":
            print_fuzzing_menu()
            fuzzing_choix = input(f"{Fore.CYAN}Votre choix : {Style.RESET_ALL}").strip()
            if fuzzing_choix == "1":
                print_status("Mode : Fuzzing HTTP (injections, LFI, XSS, etc.)", 'scan')
                url = input(f"{Fore.CYAN}URL cible à fuzz (ex: http://site/test.php) : {Style.RESET_ALL}").strip()
                method = input(f"{Fore.CYAN}Méthode (GET/POST) [GET] : {Style.RESET_ALL}").strip().upper() or "GET"
                params_str = input(f"{Fore.CYAN}Paramètres (ex: id=1&user=test) [optionnel] : {Style.RESET_ALL}").strip()
                params = dict(p.split('=') for p in params_str.split('&') if '=' in p) if params_str else {}
                from security_toolbox.fuzz.http_fuzzer import fuzz_url, export_fuzz_results
                print_status(f"Fuzzing en cours sur {url}...", 'scan')
                results = fuzz_url(url, method=method, params=params)
                if results:
                    print(f"{Fore.MAGENTA}--- Résultats suspects détectés ---{Style.RESET_ALL}")
                    for r in results:
                        if r['type'] == 'param':
                            print(f"[Paramètre] {r['param']} => Payload: {r['payload']} | Code: {r['status']} | Taille: {r['length']}")
                            print(f"  Evidence: {r['evidence']}")
                        elif r['type'] == 'path':
                            print(f"[Chemin] Payload: {r['payload']} | Code: {r['status']} | Taille: {r['length']}")
                            print(f"  Evidence: {r['evidence']}")
                        elif r['type'] == 'error':
                            print(f"[Erreur] {r.get('param','')} Payload: {r['payload']} | {r['error']}")
                    # Export automatique des résultats
                    import os
                    safe_url = url.replace('://', '_').replace('/', '_').replace('?', '_').replace('&', '_').replace('=', '_')
                    export_base = os.path.join(os.getcwd(), f"fuzz_{safe_url}_{method.lower()}")
                    export_fuzz_results(results, url, method, params, export_base)
                    print_status(f"Résultats exportés :\n- {export_base}.json\n- {export_base}.md\n- {export_base}.html", 'info')
                else:
                    print_status("Aucun résultat suspect détecté.", 'success')
            elif fuzzing_choix == "2":
                print_status("Mode : Fuzzing FTP (commandes, injections, énumération)", 'scan')
                host = input(f"{Fore.CYAN}Cible FTP (IP ou domaine) : {Style.RESET_ALL}").strip()
                port = input(f"{Fore.CYAN}Port [21] : {Style.RESET_ALL}").strip()
                port = int(port) if port else 21
                user = input(f"{Fore.CYAN}Utilisateur [anonymous] : {Style.RESET_ALL}").strip() or 'anonymous'
                passwd = input(f"{Fore.CYAN}Mot de passe [anonymous@] : {Style.RESET_ALL}").strip() or 'anonymous@'
                from security_toolbox.fuzz.ftp_fuzzer import ftp_fuzz, export_ftp_fuzz_results
                print_status(f"Fuzzing FTP en cours sur {host}:{port}...", 'scan')
                fuzz_data = ftp_fuzz(host, port=port, user=user, passwd=passwd)
                results = fuzz_data.get('results', [])
                if results:
                    print(f"{Fore.MAGENTA}--- Résultats du fuzzing FTP ---{Style.RESET_ALL}")
                    for r in results:
                        print(f"[{r['type'].upper()}] Commande: {r['command']} | Réponse: {r['response']}")
                # Export automatique
                import os
                safe_host = host.replace('.', '_').replace(':', '_')
                export_base = os.path.join(os.getcwd(), f"fuzz_ftp_{safe_host}_{port}")
                export_ftp_fuzz_results(fuzz_data, export_base)
                print_status(f"Résultats exportés :\n- {export_base}.json\n- {export_base}.md\n- {export_base}.html", 'info')
            elif fuzzing_choix == "3":
                print_status("Mode : Fuzzing SMTP (commandes, injections, open relay)", 'scan')
                host = input(f"{Fore.CYAN}Cible SMTP (IP ou domaine) : {Style.RESET_ALL}").strip()
                port = input(f"{Fore.CYAN}Port [25] : {Style.RESET_ALL}").strip()
                port = int(port) if port else 25
                sender = input(f"{Fore.CYAN}Expéditeur (MAIL FROM) [pentest@local] : {Style.RESET_ALL}").strip() or 'pentest@local'
                recipient = input(f"{Fore.CYAN}Destinataire (RCPT TO) [test@target] : {Style.RESET_ALL}").strip() or 'test@target'
                from security_toolbox.fuzz.smtp_fuzzer import smtp_fuzz, export_smtp_fuzz_results
                print_status(f"Fuzzing SMTP en cours sur {host}:{port}...", 'scan')
                fuzz_data = smtp_fuzz(host, port=port, sender=sender, recipient=recipient)
                results = fuzz_data.get('results', [])
                if results:
                    print(f"{Fore.MAGENTA}--- Résultats du fuzzing SMTP ---{Style.RESET_ALL}")
                    for r in results:
                        print(f"[{r['type'].upper()}] Commande: {r['command']} | Réponse: {r['response']}")
                # Export automatique
                import os
                safe_host = host.replace('.', '_').replace(':', '_')
                export_base = os.path.join(os.getcwd(), f"fuzz_smtp_{safe_host}_{port}")
                export_smtp_fuzz_results(fuzz_data, export_base)
                print_status(f"Résultats exportés :\n- {export_base}.json\n- {export_base}.md\n- {export_base}.html", 'info')
            elif fuzzing_choix == "0":
                print_main_menu()
        elif choix == "5":
            print_osint_menu()
            osint_choix = input(f"{Fore.CYAN}Votre choix : {Style.RESET_ALL}").strip()
            if osint_choix == "1":
                print_status("Mode : Reconnaissance passive (Shodan/Censys)", 'scan')
                ip = input(f"{Fore.CYAN}Cible IP à interroger (Shodan/Censys) : {Style.RESET_ALL}").strip()
                shodan_api_key = config.get('shodan', {}).get('api_key')
                censys_id = config.get('censys', {}).get('api_id')
                censys_secret = config.get('censys', {}).get('api_secret')
                from security_toolbox.recon.shodan_recon import shodan_lookup
                from security_toolbox.recon.censys_recon import censys_lookup
                shodan_data = shodan_lookup(ip, shodan_api_key)
                censys_data = censys_lookup(ip, censys_id, censys_secret)
                print(f"\n{Fore.MAGENTA}--- Résultats Shodan ---{Style.RESET_ALL}")
                if shodan_data:
                    print(f"IP: {shodan_data.get('ip')}")
                    print(f"Ports: {shodan_data.get('ports')}")
                    print(f"Hostnames: {shodan_data.get('hostnames')}")
                    print(f"Org: {shodan_data.get('org')}")
                    print(f"OS: {shodan_data.get('os')}")
                    print(f"Vulns: {shodan_data.get('vulns')}")
                else:
                    print_status("Aucune donnée Shodan ou erreur API.", 'warn')
                print(f"\n{Fore.CYAN}--- Résultats Censys ---{Style.RESET_ALL}")
                if censys_data:
                    print(f"IP: {censys_data.get('ip')}")
                    print(f"Services: {censys_data.get('services')}")
                    print(f"AS: {censys_data.get('autonomous_system')}")
                    print(f"Localisation: {censys_data.get('location')}")
                    print(f"Vulns: {censys_data.get('vulns')}")
                else:
                    print_status("Aucune donnée Censys ou erreur API.", 'warn')
            elif osint_choix == "2":
                print_status("Mode : Recherche leaks/OSINT avancé", 'scan')
                print(f"{Fore.YELLOW}Cible unique ou batch ?{Style.RESET_ALL}")
                mode = input(f"{Fore.CYAN}1. Cible unique  2. Batch multi-cibles : {Style.RESET_ALL}").strip()
                if mode == "2":
                    batch_file = input(f"{Fore.CYAN}Fichier liste de cibles (1 par ligne) : {Style.RESET_ALL}").strip()
                    with open(batch_file, encoding='utf-8') as f:
                        batch_targets = [line.strip() for line in f if line.strip()]
                    ttype = input(f"{Fore.CYAN}Type de cible (email/domain/user/ip) : {Style.RESET_ALL}").strip().lower()
                    proxies = input(f"{Fore.CYAN}Proxy (ex: socks5://127.0.0.1:9050) [laisser vide si aucun] : {Style.RESET_ALL}").strip() or None
                    proxies_dict = {'http': proxies, 'https': proxies} if proxies else None
                    api_keys = config.get('osint_api_keys', {})
                    print_status(f"Recherche OSINT sur {len(batch_targets)} cibles...", 'scan')
                    results = run_osint(None, ttype, api_keys=api_keys, batch_targets=batch_targets, proxies=proxies_dict)
                    date_dir = datetime.datetime.now().strftime("%Y%m%d")
                    export_dir = os.path.join(os.getcwd(), "exports", date_dir, "osint")
                    os.makedirs(export_dir, exist_ok=True)
                    export_base = os.path.join(export_dir, f"osint_batch_{ttype}")
                    export_osint_global_report('batch', ttype, results, export_base)
                    print_status(f"\n{Fore.GREEN}{Style.BRIGHT}Rapport batch exporté :{Style.RESET_ALL}\n  - {export_base}.json\n  - {export_base}.md\n  - {export_base}.html", 'success')
                    # Affichage synthétique batch
                    print(f"\n{Fore.CYAN}{Style.BRIGHT}Résumé OSINT batch ({ttype}) :{Style.RESET_ALL}")
                    for tgt, tgt_results in results.items():
                        print(f"{Fore.LIGHTMAGENTA_EX}Cible : {tgt}{Style.RESET_ALL}")
                        for module, data in tgt_results.items():
                            if module in ('score', 'recommendations'):
                                continue
                            print(f"  {Fore.MAGENTA}- {module.capitalize()} :{Style.RESET_ALL}")
                            if isinstance(data, dict) and 'error' in data:
                                print(f"      {Fore.RED}Erreur : {data['error']}{Style.RESET_ALL}")
                            elif isinstance(data, list):
                                for entry in data[:3]:
                                    print(f"      {Fore.YELLOW}- {str(entry)[:120]}{Style.RESET_ALL}")
                                if len(data) > 3:
                                    print(f"      ... ({len(data)} résultats, voir rapport)")
                            elif isinstance(data, dict):
                                for k, v in data.items():
                                    print(f"      {k}: {str(v)[:100]}")
                            else:
                                print(f"      {str(data)[:120]}")
                        print(f"    {Fore.LIGHTBLUE_EX}Score : {tgt_results.get('score', 0)}/100{Style.RESET_ALL}")
                        print(f"    {Fore.LIGHTYELLOW_EX}Recommandations :{Style.RESET_ALL}")
                        for advice in tgt_results.get('recommendations', []):
                            print(f"      - {advice}")
                else:
                    target = input(f"{Fore.CYAN}Cible (email, domaine, user, IP) : {Style.RESET_ALL}").strip()
                    ttype = input(f"{Fore.CYAN}Type de cible (email/domain/user/ip) : {Style.RESET_ALL}").strip().lower()
                    proxies = input(f"{Fore.CYAN}Proxy (ex: socks5://127.0.0.1:9050) [laisser vide si aucun] : {Style.RESET_ALL}").strip() or None
                    proxies_dict = {'http': proxies, 'https': proxies} if proxies else None
                    api_keys = config.get('osint_api_keys', {})
                    print_status(f"Recherche OSINT sur {target}...", 'scan')
                    results = run_osint(target, ttype, api_keys=api_keys, proxies=proxies_dict)
                    date_dir = datetime.datetime.now().strftime("%Y%m%d")
                    export_dir = os.path.join(os.getcwd(), "exports", date_dir, "osint")
                    os.makedirs(export_dir, exist_ok=True)
                    export_base = os.path.join(export_dir, f"osint_{target.replace('.', '_')}_{ttype}")
                    export_osint_global_report(target, ttype, results[target], export_base)
                    print_status(f"\n{Fore.GREEN}{Style.BRIGHT}Rapport exporté :{Style.RESET_ALL}\n  - {export_base}.json\n  - {export_base}.md\n  - {export_base}.html", 'success')
                    # Affichage synthétique des résultats OSINT
                    print(f"\n{Fore.CYAN}{Style.BRIGHT}Résumé OSINT pour {target} ({ttype}) :{Style.RESET_ALL}")
                    for module, data in results[target].items():
                        if module in ('score', 'recommendations'):
                            continue
                        print(f"{Fore.MAGENTA}- {module.capitalize()} :{Style.RESET_ALL}")
                        if isinstance(data, dict) and 'error' in data:
                            print(f"    {Fore.RED}Erreur : {data['error']}{Style.RESET_ALL}")
                        elif isinstance(data, list):
                            for entry in data[:5]:
                                print(f"    {Fore.YELLOW}- {str(entry)[:200]}{Style.RESET_ALL}")
                            if len(data) > 5:
                                print(f"    ... ({len(data)} résultats, voir rapport)")
                        elif isinstance(data, dict):
                            for k, v in data.items():
                                print(f"    {k}: {str(v)[:100]}")
                        else:
                            print(f"    {str(data)[:200]}")
                    print(f"\n{Fore.LIGHTBLUE_EX}Score OSINT : {results[target].get('score', 0)}/100{Style.RESET_ALL}")
                    print(f"{Fore.LIGHTYELLOW_EX}Recommandations :{Style.RESET_ALL}")
                    for advice in results[target].get('recommendations', []):
                        print(f"  - {advice}")
                # Génération HTML automatique
                try:
                    from markdown2 import markdown
                    md_file = export_base + ".md"
                    html_file = export_base + ".html"
                    with open(md_file, encoding='utf-8') as f:
                        html = markdown(f.read())
                    with open(html_file, 'w', encoding='utf-8') as f:
                        f.write(html)
                    print_status(f"Rapport HTML généré : {html_file}", 'success')
                except Exception as e:
                    print_status(f"Erreur génération HTML : {e}", 'warn')
            elif osint_choix == "0":
                print_main_menu()
        elif choix == "6":
            print(f"\n{MENU_BORDER}")
            print(f"{Fore.CYAN}{Style.BRIGHT}Merci d'avoir utilisé HACKBOX ! À bientôt.{Style.RESET_ALL}")
            print(f"{MENU_BORDER}\n")
            break
        elif choix == "7":
            print_report_menu()
            report_choix = input(f"{Fore.CYAN}Votre choix : {Style.RESET_ALL}").strip()
            if report_choix == "1":
                print_status("Mode : Rapport global (scan, vuln, recon, fuzz)", 'scan')
                from security_toolbox.reporter import Reporter
                reporter = Reporter()
                # Récupérer tous les résultats disponibles en session
                data = {}
                if scan_results: data['scan'] = scan_results
                if vuln_results: data['vuln'] = vuln_results
                # Recherche passive : demander à l'utilisateur s'il veut inclure les derniers résultats
                recon = {}
                try:
                    from security_toolbox.recon.shodan_recon import shodan_lookup
                    from security_toolbox.recon.censys_recon import censys_lookup
                    shodan_api_key = config.get('shodan', {}).get('api_key')
                    censys_id = config.get('censys', {}).get('api_id')
                    censys_secret = config.get('censys', {}).get('api_secret')
                    target_ip = input(f"{Fore.CYAN}IP cible pour inclure la reconnaissance passive (laisser vide pour ignorer) : {Style.RESET_ALL}").strip()
                    if target_ip:
                        recon['shodan'] = shodan_lookup(target_ip, shodan_api_key)
                        recon['censys'] = censys_lookup(target_ip, censys_id, censys_secret)
                except Exception:
                    pass
                if recon: data['recon'] = recon
                # Fuzz HTTP
                import glob, os
                fuzz_http_files = glob.glob(os.path.join(os.getcwd(), 'fuzz_*_get.json')) + glob.glob(os.path.join(os.getcwd(), 'fuzz_*_post.json'))
                fuzz_http = [open(f, encoding='utf-8').read() for f in fuzz_http_files]
                if fuzz_http: data['fuzz_http'] = fuzz_http
                # Fuzz FTP
                fuzz_ftp_files = glob.glob(os.path.join(os.getcwd(), 'fuzz_ftp_*.json'))
                fuzz_ftp = [open(f, encoding='utf-8').read() for f in fuzz_ftp_files]
                if fuzz_ftp: data['fuzz_ftp'] = fuzz_ftp
                # Fuzz SMTP
                fuzz_smtp_files = glob.glob(os.path.join(os.getcwd(), 'fuzz_smtp_*.json'))
                fuzz_smtp = [open(f, encoding='utf-8').read() for f in fuzz_smtp_files]
                if fuzz_smtp: data['fuzz_smtp'] = fuzz_smtp
                # Génération du rapport global
                output_base = os.path.join(os.getcwd(), f"rapport_global_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
                reporter.generate_global_report(data, output_base)
                print_status(f"Rapport global généré :\n- {output_base}.json\n- {output_base}.md\n- {output_base}.html", 'success')
            elif report_choix == "2":
                print_status("Mode : Générer rapport personnalisé", 'scan')
                # TODO: implémenter cette fonctionnalité
                pass
            elif report_choix == "0":
                print_main_menu()
        elif choix == "8":
            print_offensive_menu()
            off_choix = input(f"{Fore.CYAN}Votre choix : {Style.RESET_ALL}").strip()
            if off_choix == "1":
                print_status("Mode : Lancer un exploit externe", 'scan')
                cmd = input(f"{Fore.CYAN}Commande exploit à lancer (ex: msfconsole -r script.rc) : {Style.RESET_ALL}").strip()
                from security_toolbox.offensive.exploit_launcher import run_exploit, export_exploit_result
                result = run_exploit(cmd)
                print(f"\n{Fore.YELLOW}--- Sortie standard ---{Style.RESET_ALL}\n{result['stdout']}")
                if result['stderr']:
                    print(f"\n{Fore.RED}--- Erreurs ---{Style.RESET_ALL}\n{result['stderr']}")
                # Export automatique
                import os
                export_base = os.path.join(os.getcwd(), f"exploit_result_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
                export_exploit_result(result, export_base)
                print_status(f"Résultat exporté :\n- {export_base}.txt\n- {export_base}.md", 'info')
            elif off_choix == "2":
                print_status("Mode : Générer un reverse shell", 'scan')
                lang = input(f"{Fore.CYAN}Langage (bash/python/php/nc/ncat/powershell/socat) : {Style.RESET_ALL}").strip().lower()
                lhost = input(f"{Fore.CYAN}LHOST (IP d'écoute) : {Style.RESET_ALL}").strip()
                lport = input(f"{Fore.CYAN}LPORT (port d'écoute) : {Style.RESET_ALL}").strip()
                from security_toolbox.offensive.reverse_shells import generate_reverse_shell, export_reverse_shell
                payload = generate_reverse_shell(lang, lhost, lport)
                print(f"\n{Fore.YELLOW}--- Reverse shell {lang} ---{Style.RESET_ALL}\n{payload}")
                # Export automatique
                import os
                export_base = os.path.join(os.getcwd(), f"reverse_shell_{lang}_{lhost}_{lport}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
                export_reverse_shell(payload, lang, lhost, lport, export_base)
                print_status(f"Reverse shell exporté :\n- {export_base}.txt\n- {export_base}.md", 'info')
            elif off_choix == "3":
                print_status("Mode : Générer un stager Empire/Metasploit", 'scan')
                stager_type = input(f"{Fore.CYAN}Type (powershell/cmd/macro/unix) : {Style.RESET_ALL}").strip().lower()
                lhost = input(f"{Fore.CYAN}LHOST (IP d'écoute) : {Style.RESET_ALL}").strip()
                lport = input(f"{Fore.CYAN}LPORT (port d'écoute) : {Style.RESET_ALL}").strip()
                from security_toolbox.offensive.stager_generator import generate_stager, export_stager
                payload = generate_stager(stager_type, lhost, lport)
                print(f"\n{Fore.YELLOW}--- Stager {stager_type} ---{Style.RESET_ALL}\n{payload}")
                # Export automatique
                import os
                export_base = os.path.join(os.getcwd(), f"stager_{stager_type}_{lhost}_{lport}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
                export_stager(payload, stager_type, lhost, lport, export_base)
                print_status(f"Stager exporté :\n- {export_base}.txt\n- {export_base}.md", 'info')
            elif off_choix == "0":
                print_main_menu()
        elif choix == "9":
            print_status("Mode : Loot automatique (fichiers sensibles, tokens, cookies)", 'scan')
            dirs = input(f"{Fore.CYAN}Répertoires à scanner (séparés par ,) [défaut: home, /etc, /var/www, /tmp] : {Style.RESET_ALL}").strip()
            patterns = input(f"{Fore.CYAN}Patterns fichiers (ex: *.env, *.git, *token*) [défaut: patterns standards] : {Style.RESET_ALL}").strip()
            max_files = input(f"{Fore.CYAN}Nombre max de fichiers à looter [50] : {Style.RESET_ALL}").strip()
            max_files = int(max_files) if max_files else 50
            from security_toolbox.offensive.loot_automation import find_sensitive_files, dump_files, extract_tokens_from_files, export_loot_report
            search_dirs = [d.strip() for d in dirs.split(',')] if dirs else None
            patterns_list = [p.strip() for p in patterns.split(',')] if patterns else None
            files = find_sensitive_files(search_dirs, patterns_list, max_files)
            print_status(f"{len(files)} fichiers sensibles trouvés.", 'info')
            output_dir = os.path.join(os.getcwd(), f"loot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
            dumped = dump_files(files, output_dir)
            print_status(f"{len(dumped)} fichiers copiés dans {output_dir}", 'info')
            tokens = extract_tokens_from_files(dumped)
            print_status(f"{len(tokens)} tokens/API keys/cookies extraits.", 'info')
            export_base = os.path.join(output_dir, "loot_report")
            export_loot_report(dumped, tokens, export_base)
            print_status(f"Rapport loot exporté :\n- {export_base}.md\n- {export_base}.json", 'info')
            print_main_menu()
        elif choix == "10":
            print_status("Mode : Escalade de privilèges & bypass", 'scan')
            from security_toolbox.offensive.escalation import detect_escalation_vectors, export_escalation_report
            results = detect_escalation_vectors()
            print_status("Résultats de la détection :", 'info')
            for r in results:
                print(f"\n{Fore.YELLOW}--- {r['check']} ---{Style.RESET_ALL}\n{r['result']}")
            output_dir = os.path.join(os.getcwd(), f"escalation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
            os.makedirs(output_dir, exist_ok=True)
            export_base = os.path.join(output_dir, "escalation_report")
            export_escalation_report(results, export_base)
            print_status(f"Rapport escalade exporté :\n- {export_base}.md\n- {export_base}.json", 'info')
            print_main_menu()
        elif choix == "11":
            print_status("Mode : OSINT avancé (Google Dorks)", 'scan')
            domain = input(f"{Fore.CYAN}Domaine ou cible à dorker : {Style.RESET_ALL}").strip()
            from security_toolbox.osint.google_dorks import generate_google_dorks, export_dorks_report
            dorks = generate_google_dorks(domain)
            print_status(f"{len(dorks)} dorks générés.", 'info')
            for d in dorks:
                print(f"- {d}")
            import os
            date_dir = datetime.datetime.now().strftime("%Y%m%d")
            export_dir = os.path.join(os.getcwd(), "exports", date_dir, "osint")
            os.makedirs(export_dir, exist_ok=True)
            export_base = os.path.join(export_dir, f"dorks_{domain}")
            export_dorks_report(domain, dorks, export_base, scrape=True)
            print_status(f"Rapport Google Dorks exporté (md/txt) dans exports/<date>/osint/", 'info')
            print_main_menu()
        elif choix.lower() == "h":
            print_status("Ouverture de la documentation dans le navigateur...", 'info')
            import os
            doc_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'HELP.html'))
            file_url = 'file:///' + doc_path.replace('\\', '/').replace(':', '|', 1) if os.name == 'nt' else 'file://' + doc_path
            try:
                if os.name == 'nt':
                    os.startfile(doc_path)
                else:
                    import webbrowser
                    webbrowser.open_new(file_url)
                print_status(f"Documentation ouverte : {doc_path}", 'success')
            except Exception as e:
                print_status(f"Erreur ouverture documentation : {e}", 'error')
        else:
            print_status("Choix invalide. Veuillez réessayer.", 'warn')

if __name__ == "__main__":
    main()
