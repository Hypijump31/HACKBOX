import time
import datetime
import os

def detect_lockout(results, protocol='ssh', lockout_threshold=3, lockout_window=60):
    """
    Détection intelligente de lockout/alertes sur brute-force/password spraying.
    Analyse les résultats pour détecter :
    - Blocage de compte (messages, délais, refus soudain)
    - Ralentissements ou délais anormaux
    - Codes d’erreur spécifiques (ex : 429, 403, 423, messages lockout)
    Retourne un rapport d’alerte.
    """
    alerts = []
    times = []
    error_counts = {}
    lockout_msgs = [
        'account locked', 'too many attempts', 'temporarily disabled',
        'locked out', 'try again later', 'rate limit', '429', '423', '403',
        'trop de tentatives', 'compte bloqué', 'verrouillé', 'delai', 'locked'
    ]
    last_time = None
    for r in results:
        t = r.get('timestamp', None)
        if t:
            times.append(t)
        msg = str(r.get('error', '')) + ' ' + str(r.get('response', ''))
        for lmsg in lockout_msgs:
            if lmsg in msg.lower():
                alerts.append({'type': 'lockout', 'msg': msg, 'entry': r})
        code = r.get('code', None)
        if code:
            error_counts[code] = error_counts.get(code, 0) + 1
            if str(code) in ['429', '423', '403']:
                alerts.append({'type': 'lockout', 'msg': f'Code {code}', 'entry': r})
    # Analyse des délais
    if len(times) >= 2:
        intervals = [float(times[i+1]) - float(times[i]) for i in range(len(times)-1)]
        slow = [iv for iv in intervals if iv > lockout_window]
        if slow:
            alerts.append({'type': 'delay', 'msg': f'Délais suspects détectés : {slow}'})
    # Analyse du taux d’échec
    fail_count = sum(1 for r in results if r.get('status') in ['fail', 'error'])
    if fail_count >= lockout_threshold:
        alerts.append({'type': 'threshold', 'msg': f'{fail_count} échecs consécutifs'})
    return {'date': datetime.datetime.now().isoformat(), 'alerts': alerts, 'fail_count': fail_count, 'error_counts': error_counts}


def export_lockout_alerts(alerts, export_base):
    """
    Exporte les alertes de lockout au format JSON et Markdown.
    """
    import json
    import os
    import datetime
    date_dir = datetime.datetime.now().strftime("%Y%m%d")
    base_dir = os.path.join(os.getcwd(), "exports", date_dir, "lockout_detection")
    os.makedirs(base_dir, exist_ok=True)
    export_base = os.path.join(base_dir, os.path.basename(export_base))
    # JSON
    with open(export_base + '.json', 'w', encoding='utf-8') as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)
    # Markdown
    with open(export_base + '.md', 'w', encoding='utf-8') as f:
        f.write(f"# Rapport Détection Lockout\n\n")
        f.write(f"Date : {alerts.get('date')}\n\n")
        f.write(f"**Échecs consécutifs** : {alerts.get('fail_count')}\n\n")
        f.write(f"**Codes d’erreur** : {alerts.get('error_counts')}\n\n")
        for a in alerts.get('alerts', []):
            f.write(f"- **Type** : {a['type']}\n  - **Message** : {a['msg']}\n  - **Entrée** : {a['entry']}\n\n")
