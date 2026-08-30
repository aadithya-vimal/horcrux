from __future__ import annotations

import shutil
from pathlib import Path


TOOLS = {
    "nmap": "Port/service discovery",
    "rustscan": "Fast TCP discovery",
    "masscan": "Very fast port discovery",
    "naabu": "Fast port discovery",
    "curl": "HTTP/manual interaction",
    "wget": "HTTP retrieval",
    "dig": "DNS enumeration",
    "nslookup": "DNS lookup",
    "host": "DNS lookup",
    "openssl": "TLS inspection",
    "httpx": "HTTP probing",
    "whatweb": "Web fingerprinting",
    "wafw00f": "WAF fingerprinting",
    "nikto": "Web checks",
    "gobuster": "Web/content/DNS discovery",
    "ffuf": "Web fuzzing",
    "feroxbuster": "Web discovery",
    "dirsearch": "Web discovery",
    "nuclei": "Template-based vulnerability checks",
    "smbclient": "SMB enumeration",
    "rpcclient": "RPC enumeration",
    "enum4linux-ng": "SMB/domain enumeration",
    "netexec": "SMB/LDAP/Kerberos/WinRM",
    "crackmapexec": "Legacy network enumeration",
    "ldapsearch": "LDAP enumeration",
    "ldapdomaindump": "LDAP/AD dumping",
    "snmpwalk": "SNMP enumeration",
    "onesixtyone": "SNMP community discovery",
    "smtp-user-enum": "SMTP user enumeration",
    "searchsploit": "Exploit/CVE lookup",
    "sqlmap": "SQL injection testing",
    "hydra": "Credential testing",
    "medusa": "Credential testing",
    "john": "Password hashes",
    "hashcat": "Password hashes",
    "responder": "Network credential capture",
    "impacket-secretsdump": "Windows credential extraction",
    "impacket-GetUserSPNs": "Kerberos/SPN enumeration",
    "impacket-GetNPUsers": "AS-REP enumeration",
    "impacket-psexec": "SMB execution tooling",
    "impacket-wmiexec": "WMI execution tooling",
    "evil-winrm": "WinRM client",
    "bloodhound-python": "AD collection",
    "kerbrute": "Kerberos enumeration",
    "redis-cli": "Redis inspection",
    "mysql": "MySQL",
    "psql": "PostgreSQL",
    "mongosh": "MongoDB",
    "sqlcmd": "MSSQL",
    "docker": "Docker inspection",
    "kubectl": "Kubernetes",
    "helm": "Kubernetes tooling",
    "linpeas": "Linux privilege enumeration",
    "pspy": "Linux process monitoring",
    "lse": "Linux privilege enumeration",
    "winpeas": "Windows privilege enumeration",
    "chisel": "Tunneling",
    "proxychains4": "Proxying",
    "msfconsole": "Metasploit",
    "msfvenom": "Metasploit payload generation",
}

WORDLISTS = [
    "rockyou.txt",
    "dirb/common.txt",
    "dirbuster/directory-list-2.3-small.txt",
    "dirbuster/directory-list-2.3-medium.txt",
    "dirbuster/directory-list-2.3-big.txt",
    "seclists/Discovery/Web-Content/common.txt",
    "seclists/Discovery/Web-Content/big.txt",
    "seclists/Discovery/Web-Content/quickhits.txt",
    "seclists/Discovery/Web-Content/raft-small-words.txt",
    "seclists/Discovery/Web-Content/raft-medium-words.txt",
    "seclists/Discovery/Web-Content/raft-large-words.txt",
    "seclists/Discovery/Web-Content/raft-small-directories.txt",
    "seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "seclists/Discovery/Web-Content/raft-large-directories.txt",
    "seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
    "seclists/Discovery/Web-Content/combined_directories.txt",
    "seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "seclists/Discovery/DNS/namelist.txt",
    "seclists/Fuzzing/SQLi/Generic-SQLi.txt",
    "seclists/Fuzzing/XSS/XSS-Jhaddix.txt",
    "seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    "seclists/Passwords/Common-Credentials/10-million-password-list-top-100000.txt",
    "seclists/Usernames/top-usernames-shortlist.txt",
    "seclists/Discovery/SNMP/common-snmp-community-strings.txt",
]

import sys

BASES = [
    Path("/usr/share/wordlists"),
    Path("/usr/share/seclists"),
    Path("/usr/share/SecLists"),
    Path("/opt/SecLists"),
    Path.home() / "SecLists",
    Path.home() / "wordlists",
    Path("C:/SecLists"),
    Path("C:/wordlists"),
]


INSTALL_GUIDES = {
    "nmap": {
        "win32": "winget install Insecure.Nmap  OR  choco install nmap",
        "linux": "sudo apt install nmap  OR  sudo pacman -S nmap",
        "darwin": "brew install nmap",
    },
    "ffuf": {
        "win32": "winget install ffuf.ffuf  OR  go install github.com/ffuf/ffuf/v2@latest",
        "linux": "sudo apt install ffuf  OR  go install github.com/ffuf/ffuf/v2@latest",
        "darwin": "brew install ffuf",
    },
    "nuclei": {
        "win32": "winget install ProjectDiscovery.Nuclei  OR  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "linux": "sudo apt install nuclei  OR  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "darwin": "brew install nuclei",
    },
    "searchsploit": {
        "win32": "git clone https://gitlab.com/exploit-database/exploitdb.git && add to PATH",
        "linux": "sudo apt install exploitdb",
        "darwin": "brew install exploitdb",
    },
    "gobuster": {
        "win32": "go install github.com/OJ/gobuster/v3@latest",
        "linux": "sudo apt install gobuster",
        "darwin": "brew install gobuster",
    },
}


def get_install_instruction(tool_name: str) -> str:
    platform_key = sys.platform
    if platform_key not in {"win32", "darwin"}:
        platform_key = "linux"
    guide = INSTALL_GUIDES.get(tool_name, {})
    return guide.get(platform_key, "Check package manager or vendor documentation.")


def find_wordlist(name: str):
    for base in BASES:
        for candidate in (base / name, base / "seclists" / name):
            if candidate.exists():
                return candidate
    return None


def check_tools():
    tool_rows = [
        (name, shutil.which(name), purpose, get_install_instruction(name))
        for name, purpose in TOOLS.items()
    ]
    word_rows = [
        (name, find_wordlist(name))
        for name in WORDLISTS
    ]
    return tool_rows, word_rows
