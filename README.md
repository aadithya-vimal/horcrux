# HORCRUX 1.0

A wide-scoped offensive-security operator console for authorized labs, CTFs, THM/HTB, home labs, and systems you are explicitly authorized to assess.

The core workflow is:

DISCOVER → ENUMERATE → CORRELATE → VERIFY → EXPLOIT REVIEW

Horcrux invokes real external tools instead of pretending to replace them, stores their full output, keeps raw HTML/source out of the normal UI, correlates version evidence to SearchSploit/CVE candidates, and presents prioritized next actions.

## Install on Windows PowerShell

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1; python -m pip install --upgrade pip; python -m pip install -r requirements.txt; python -m pip install -e .
```

## Install on Kali/Linux

```bash
python3 -m venv .venv && source .venv/bin/activate && python -m pip install --upgrade pip && python -m pip install -r requirements.txt && python -m pip install -e .
```

## Start

```text
horcrux
horcrux --version
horcrux doctor
```

Bare `horcrux` opens the operator console. The only themed startup art is the large HORCRUX title plus the Elder Wand graphic. The title itself animates; other object ASCII art was intentionally removed.

## Console commands

```text
scan <target>
scan <target> --deep
scan <target> --verify
status
services
software
findings
next
creds
graph
web
cve
searchsploit
nuclei
exploit
local
doctor
tools
source <artifact>
report
help
exit
```

## Coverage

Network:
- Nmap TCP top ports
- Nmap full TCP with `--deep`
- UDP top ports
- service/version parsing
- software inventory
- OS/service evidence
- service-specific enumeration

Web:
- HTTP/HTTPS probing
- status/title/redirect/header capture
- technology fingerprinting
- common sensitive path probes
- content discovery with ffuf/gobuster/feroxbuster
- WAF identification where available
- Nuclei
- conservative credential-disclosure detection
- raw body/header artifact storage

Services:
- SSH
- FTP
- SMB/RPC
- LDAP
- Kerberos
- SNMP
- Redis
- SQL database identification
- SMTP
- DNS

Intelligence:
- Nmap software/version inventory
- SearchSploit JSON integration
- CVE extraction from returned exploit titles
- exploit candidate confidence
- applicability notes
- Nuclei artifact capture

Local/post-compromise:
- identity
- OS/kernel
- sudo
- SUID/SGID
- capabilities
- cron
- systemd
- processes
- network
- mounts
- Docker

## Exploitation

`exploit` is the final review stage: candidates discovered from version/CVE intelligence are consolidated for the operator. Horcrux does not silently fire arbitrary exploit code. This makes the workflow useful for labs while avoiding accidental destructive execution.

## Artifacts

Each target gets:

```text
workspaces/<target>/
  state.json
  raw/
  responses/
  headers/
  reports/
```

Use `source` only when you deliberately want a raw artifact.

## Doctor

`horcrux doctor` checks a large Kali-oriented tool inventory and a broad list of common SecLists/Dirb/Dirbuster wordlists.

## UI

`horcrux` and `horcrux --version` use the same large animated title. A static Elder Wand graphic is shown underneath it.

An optional Node example is included under `ascii_assets/` showing the requested `asciify-engine` `particles`/`starfield` style for future image-driven terminal/browser rendering.
