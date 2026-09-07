from __future__ import annotations

import shutil
from enum import Enum
from pathlib import Path
import sys


class ToolImportance(str, Enum):
    REQUIRED = "REQUIRED"
    RECOMMENDED = "RECOMMENDED"
    OPTIONAL = "OPTIONAL"
    ENVIRONMENT = "ENVIRONMENT-SPECIFIC"


TOOL_IMPORTANCE: dict[str, ToolImportance] = {
    # REQUIRED
    "python": ToolImportance.REQUIRED,
    "pip": ToolImportance.REQUIRED,
    "nmap": ToolImportance.REQUIRED,
    "curl": ToolImportance.REQUIRED,

    # RECOMMENDED
    "ffuf": ToolImportance.RECOMMENDED,
    "httpx": ToolImportance.RECOMMENDED,
    "nuclei": ToolImportance.RECOMMENDED,
    "searchsploit": ToolImportance.RECOMMENDED,
    "smbclient": ToolImportance.RECOMMENDED,
    "whatweb": ToolImportance.RECOMMENDED,

    # ENVIRONMENT-SPECIFIC
    "linpeas": ToolImportance.ENVIRONMENT,
    "winpeas": ToolImportance.ENVIRONMENT,
    "pspy": ToolImportance.ENVIRONMENT,
    "lse": ToolImportance.ENVIRONMENT,
    "docker": ToolImportance.ENVIRONMENT,
    "kubectl": ToolImportance.ENVIRONMENT,
    "helm": ToolImportance.ENVIRONMENT,
    "chisel": ToolImportance.ENVIRONMENT,
    "proxychains4": ToolImportance.ENVIRONMENT,
    "evil-winrm": ToolImportance.ENVIRONMENT,
}


def get_tool_importance(tool_name: str) -> ToolImportance:
    return TOOL_IMPORTANCE.get(tool_name, ToolImportance.OPTIONAL)


CATEGORIES = {
    "CORE": {
        "python": "Python runtime (3.10+ required)",
        "pip": "Python package manager",
    },
    "NETWORK": {
        "nmap": "Network port & service discovery (Primary)",
        "rustscan": "High-speed port discovery scanner",
        "masscan": "Very fast asynchronous port discovery",
        "naabu": "Fast SYN/CONNECT port scanner",
        "curl": "HTTP/manual protocol interaction",
        "wget": "File retrieval utility",
        "dig": "DNS resolution & zone transfers",
        "host": "DNS lookup utility",
        "openssl": "TLS/SSL cipher & certificate inspection",
    },
    "WEB": {
        "httpx": "Fast multi-purpose HTTP probing",
        "whatweb": "Next-generation web scanner & fingerprinting",
        "wafw00f": "Web Application Firewall fingerprinting",
        "nikto": "Web server configuration vulnerability scanner",
        "gobuster": "Directory/file & DNS brute-forcing",
        "ffuf": "Fast web fuzzer and endpoint discovery",
        "feroxbuster": "Fast, recursive content discovery",
        "dirsearch": "Web path discovery tool",
        "nuclei": "Fast template-based vulnerability scanner",
    },
    "SMB / AD": {
        "smbclient": "SMB share navigation and auditing",
        "rpcclient": "MS-RPC endpoint auditing",
        "enum4linux-ng": "SMB & Active Directory domain enumeration",
        "netexec": "Network service protocol execution (SMB/LDAP/WinRM)",
        "crackmapexec": "Network authentication & protocol auditing",
        "ldapsearch": "LDAP directory queries & naming contexts",
        "ldapdomaindump": "Active Directory information extraction via LDAP",
        "bloodhound-python": "Active Directory domain graph ingestor",
        "impacket-secretsdump": "Windows LSA & NTDS hash extraction",
        "kerbrute": "Kerberos username enumeration & AS-REP roasting",
        "evil-winrm": "Windows Remote Management (WinRM) shell client",
    },
    "NETWORK SERVICES": {
        "snmpwalk": "SNMP MIB tree query & enumeration",
        "onesixtyone": "Fast SNMP community string scanner",
        "smtp-user-enum": "SMTP VRFY/EXPN user enumeration",
    },
    "DATABASES": {
        "redis-cli": "Redis database client & diagnostics",
        "mysql": "MySQL database client",
        "psql": "PostgreSQL database client",
        "mongosh": "MongoDB shell client",
        "sqlcmd": "Microsoft SQL Server client",
    },
    "CREDENTIAL / PASSWORD": {
        "hydra": "Parallelized network login brute-forcer",
        "medusa": "Modular parallel network login brute-forcer",
        "john": "John the Ripper password cracker",
        "hashcat": "Advanced password recovery engine",
        "responder": "LLMNR, NBT-NS, and MDNS poisoner",
    },
    "EXPLOIT INTELLIGENCE": {
        "searchsploit": "Exploit-DB offline search archive",
        "msfconsole": "Metasploit Framework operator console",
        "msfvenom": "Metasploit standalone payload generator",
    },
    "LOCAL": {
        "linpeas": "Linux privilege escalation assistant",
        "pspy": "Linux unprivileged process monitor",
        "lse": "Linux Security Exploit suggester",
        "winpeas": "Windows privilege escalation assistant",
    },
    "TUNNELING": {
        "chisel": "Fast TCP/UDP tunnel over HTTP",
        "proxychains4": "Dynamic SOCKS proxy wrapper",
    },
    "CONTAINERS / ORCHESTRATION": {
        "docker": "Docker container runtime inspection",
        "kubectl": "Kubernetes cluster control CLI",
        "helm": "Kubernetes package management",
    },
}

TOOLS = {t: desc for cat in CATEGORIES.values() for t, desc in cat.items()}


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
        (name, shutil.which(name), purpose, get_install_instruction(name), get_tool_importance(name))
        for name, purpose in TOOLS.items()
    ]
    word_rows = [
        (name, find_wordlist(name))
        for name in WORDLISTS
    ]
    return tool_rows, word_rows
