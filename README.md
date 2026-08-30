# HORCRUX

> **The fragments reveal the whole.**

**HORCRUX** is an operator-oriented offensive-security reconnaissance platform designed to turn the chaotic first stages of an assessment into a structured workflow.

It does not try to replace the tools security operators already know.

It **orchestrates them**.

HORCRUX discovers the attack surface, fingerprints services, launches the appropriate enumeration tooling, records evidence, correlates software versions with vulnerability and exploit intelligence, ranks what deserves attention next, and keeps the complete raw evidence available when the operator wants it.

```text
                    HORCRUX

        DISCOVER
            │
            ▼
       FINGERPRINT
            │
            ▼
       ENUMERATE
            │
            ▼
        CORRELATE
            │
            ▼
          VERIFY
            │
            ▼
      EXPLOIT REVIEW
            │
            ▼
      OPERATOR ACTION
```

It is designed for people who would otherwise spend the first 20–40 minutes of a lab manually typing the same commands into Nmap, Gobuster, FFUF, Nikto, SearchSploit, SMB tools, LDAP tools, Nuclei, and a dozen other utilities.

HORCRUX is meant to make that process **fast, repeatable, and evidence-driven**.

---

## Why HORCRUX?

Security tooling is fragmented.

A typical assessment might look like:

```text
nmap
    ↓
"Port 8080 is open"
    ↓
curl
    ↓
"Looks like a web application"
    ↓
whatweb
    ↓
"Framework/version identified"
    ↓
gobuster
    ↓
"Interesting endpoint found"
    ↓
manual inspection
    ↓
searchsploit
    ↓
"Possible exploit"
    ↓
manual verification
```

The knowledge exists.

The tools exist.

The problem is the **workflow between them**.

HORCRUX creates that workflow.

Instead of treating each tool as an isolated command, it builds a persistent picture of the target.

For example:

```text
TARGET
│
├── 22/tcp
│   └── OpenSSH 9.x
│
├── 80/tcp
│   ├── nginx
│   ├── login surface
│   ├── technology fingerprint
│   └── content discovery
│
├── 445/tcp
│   ├── SMB
│   ├── domain information
│   └── share enumeration
│
└── SOFTWARE
    └── nginx 1.x
         └── SearchSploit / CVE candidates
```

The result is not merely command output.

It is an **attack-surface model**.

---

# Core Philosophy

HORCRUX follows five principles.

### 1. Orchestrate, don't reinvent

HORCRUX is intentionally built around the tools operators already trust.

It invokes things such as:

* Nmap
* RustScan
* Masscan
* Gobuster
* FFUF
* Feroxbuster
* Nikto
* WhatWeb
* WAFW00F
* Nuclei
* SMBClient
* RPCClient
* Enum4linux-ng
* NetExec
* LDAPSearch
* SNMP tools
* Hydra
* SQLMap
* John
* Hashcat
* SearchSploit
* Metasploit
* Impacket tooling
* BloodHound tooling
* and more

HORCRUX coordinates the workflow around those tools instead of pretending there is one magic scanner that can replace them.

---

### 2. Evidence first

A finding is useful only when it can be traced back to evidence.

HORCRUX therefore preserves:

* command lines
* stdout
* stderr
* Nmap XML
* HTTP responses
* HTTP headers
* technology fingerprints
* enumeration output
* vulnerability output
* SearchSploit results
* generated reports

The operator sees the important information by default.

The complete raw material remains available underneath.

---

### 3. Don't bury the operator in output

A security tool can easily become unusable by printing 50,000 lines of HTML, Gobuster output, Nmap scripts, and HTTP responses into the terminal.

HORCRUX deliberately separates:

```text
WHAT MATTERS
```

from:

```text
EVERYTHING THE TOOLS RETURNED
```

The console shows concise findings and actions.

Raw evidence is saved to the workspace and can be requested intentionally.

---

### 4. Confidence matters

A software/version match is not automatically proof of vulnerability.

A SearchSploit result is not automatically proof that an exploit works.

A scanner finding is not automatically a compromise.

HORCRUX therefore treats findings and exploit candidates as evidence-backed candidates with confidence and applicability context.

The operator remains responsible for verification.

---

### 5. Exploitation is explicit

Reconnaissance should not unexpectedly become destructive execution.

HORCRUX can take the operator through the exploitation decision point, but the final transition into exploit execution remains deliberate.

That makes the tool appropriate for:

* TryHackMe
* Hack The Box
* CTFs
* penetration-testing labs
* home labs
* authorized assessments

---

# What HORCRUX Actually Does

## Network Discovery

HORCRUX starts with the network.

Depending on mode, it can orchestrate:

```text
Nmap TCP discovery
        │
        ├── service detection
        ├── version detection
        ├── default scripts
        ├── OS hints
        └── XML evidence
```

Normal scanning focuses on the common attack surface.

Deep scanning can expand into full TCP discovery.

UDP discovery is also part of the workflow.

The result becomes a normalized service inventory instead of raw Nmap text.

Example:

```text
PORT      SERVICE       PRODUCT          VERSION
22/tcp    ssh           OpenSSH          9.x
80/tcp    http          nginx            1.x
445/tcp   microsoft-ds
```

---

# Service-Aware Enumeration

HORCRUX does not treat every open port identically.

The detected service determines the next actions.

## HTTP / HTTPS

When a web service is detected, HORCRUX can perform:

* HTTP probing
* status detection
* title extraction
* redirect inspection
* header capture
* technology fingerprinting
* common sensitive-path checks
* login-surface detection
* Git metadata checks
* environment-file checks
* content discovery
* Nuclei integration

Example workflow:

```text
80/tcp detected
     │
     ├── HTTP fingerprint
     ├── technology detection
     ├── /login
     ├── /admin
     ├── /.git/HEAD
     ├── /.env
     ├── robots.txt
     ├── sitemap.xml
     └── content discovery
```

HORCRUX stores the complete responses while keeping normal console output clean.

---

## SMB / Windows

When SMB is detected, HORCRUX can orchestrate the surrounding enumeration stack:

```text
SMB
│
├── NetExec
├── CrackMapExec
├── SMBClient
├── RPCClient
└── Enum4linux-ng
```

This allows the operator to move naturally from:

```text
"SMB exists"
```

towards:

```text
shares
domain information
users
access conditions
enumeration evidence
```

---

## LDAP

LDAP exposure can trigger:

* LDAP root discovery
* RootDSE inspection
* naming-context discovery
* directory-service evidence collection

---

## Kerberos

Kerberos exposure becomes an explicit attack-surface signal and a candidate for domain/SPN-focused enumeration.

---

## FTP

FTP detection can trigger:

* service inspection
* anonymous-access checks
* system information enumeration

---

## SNMP

SNMP exposure can trigger community-based inspection and system-information enumeration when the appropriate tooling is available.

---

## Redis

Redis detection can trigger service inspection and information collection where the client is installed.

---

## Other Services

HORCRUX is designed around a service-dispatch architecture, so additional service modules can be added without rewriting the core operator workflow.

---

# Web Attack Surface

Web applications are treated as one part of the overall attack surface rather than the entire product.

HORCRUX can invoke multiple discovery engines depending on what's installed:

```text
FFUF
Gobuster
Feroxbuster
Dirsearch
```

The operator should not need to manually remember:

```text
"Which tool should I use?"

```

after identifying an HTTP service.

HORCRUX can select from the available toolchain and preserve the result as workspace evidence.

---

# Technology Fingerprinting

HORCRUX extracts technology signals from HTTP responses and headers.

Examples include:

```text
nginx
Apache
IIS
Gunicorn
Flask
Django
Express
PHP
Tomcat
Spring
Rails
WordPress
Drupal
GraphQL
```

Those signals become part of the target's normalized technology inventory.

That information can then contribute to the next-action queue and vulnerability research.

---

# Vulnerability Intelligence

One of the most important parts of HORCRUX is the transition from:

```text
"this service exists"
```

to:

```text
"this is the software/version"
```

and finally:

```text
"these vulnerability/exploit candidates are worth investigating"
```

HORCRUX therefore records software discovered from service fingerprinting.

Example:

```text
Software Inventory

OpenSSH
Version: 9.x
Source: Nmap
Confidence: 97%
```

That can feed the exploit-intelligence layer.

---

# CVE & SearchSploit Intelligence

HORCRUX integrates with **SearchSploit** when it is available.

The workflow becomes:

```text
Nmap
 │
 └── Software / Version
          │
          ▼
      SearchSploit
          │
          ▼
   Exploit Candidates
          │
          ▼
      Applicability
          │
          ▼
     Operator Review
```

HORCRUX does **not** treat every SearchSploit hit as automatically exploitable.

Instead, results contain context such as:

* product
* version
* CVE when extractable
* exploit title
* SearchSploit path
* confidence
* applicability notes

Example:

```text
CVE / SEARCHSPLOIT CANDIDATES

CONFIDENCE   CVE             PRODUCT       VERSION
----------------------------------------------------------
75%          CVE-XXXX-YYYY   ExampleApp    1.2.3
63%          CVE-XXXX-ZZZZ   ExampleApp    1.2.3
```

The operator decides what gets verified and what gets ignored.

---

# Nuclei Integration

HORCRUX can invoke Nuclei against discovered HTTP targets.

That gives the workflow another layer:

```text
HTTP discovery
      │
      ▼
Technology fingerprint
      │
      ▼
Nuclei templates
      │
      ▼
Potential vulnerabilities
      │
      ▼
Evidence / verification
```

Nuclei output is stored as an artifact rather than flooding the normal operator interface.

---

# Findings Engine

HORCRUX turns observations into structured findings.

Each finding can include:

```text
ID
Title
Category
Severity
Confidence
Status
Target
Evidence
Artifacts
Reproduction
Next Action
```

For example:

```text
HIGH
Exposed environment file

Confidence: 99%

Evidence:
    /.env returned HTTP 200

Artifact:
    responses/_env.body

Next action:
    Inspect the response for secrets.
```

This is significantly more useful than a line saying:

```text
[200] /.env
```

---

# Prioritized Next Actions

After reconnaissance, HORCRUX builds a queue of suggested actions.

Example:

```text
NEXT BEST ACTIONS

98  Resolve CVE / SearchSploit candidates
94  Review web attack surface
90  Review SMB shares/domain data
88  Review LDAP/domain data
87  Review Kerberos enumeration
82  Review FTP access
72  Review SSH exposure
```

This is one of the core ideas behind HORCRUX:

> **Don't just tell the operator what exists. Tell them what deserves attention next.**

---

# Local Enumeration

Once an operator has a shell in an authorized environment, HORCRUX can also act as a local-enumeration coordinator.

The local workflow can collect:

```text
identity
OS/kernel
sudo configuration
SUID binaries
SGID binaries
Linux capabilities
cron
systemd services
processes
network sockets
mounts
Docker information
environment
```

The goal is not to hide the commands from the operator.

The goal is to make the enumeration:

```text
repeatable
persistent
organized
searchable
```

---

# Persistent Workspaces

Every target gets its own workspace.

Example:

```text
workspaces/
└── 10.10.10.10/
    ├── state.json
    ├── raw/
    ├── responses/
    ├── headers/
    └── reports/
```

This means reconnaissance doesn't disappear when the terminal closes.

The operator can come back later and inspect:

```text
status
services
software
findings
next
creds
graph
source
report
```

---

# Raw Evidence

HORCRUX deliberately keeps raw data available.

For example:

```text
raw/
├── nmap-tcp.stdout
├── nmap-tcp.stderr
├── nmap-tcp.command
├── nmap.xml
├── nmap-udp.stdout
├── ffuf-80.stdout
└── nuclei.stdout
```

HTTP evidence is kept separately:

```text
responses/
├── root.body
├── login.body
├── admin.body
├── _env.body
└── _git_HEAD.body
```

and:

```text
headers/
├── root.txt
├── login.txt
└── admin.txt
```

The normal UI remains clean.

---

# Operator Console

Running:

```bash
horcrux
```

opens the interactive console.

The intent is closer to an operator environment than a conventional one-shot scanner.

Example:

```text
horcrux
```

```text
horcrux > scan 10.10.10.10
horcrux > services
horcrux > findings
horcrux > next
horcrux > cve
horcrux > searchsploit
horcrux > exploit
horcrux > report
```

Useful commands include:

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

---

# One-Shot Mode

HORCRUX can also be invoked directly.

```bash
horcrux 10.10.10.10
```

Deep scan:

```bash
horcrux 10.10.10.10 --deep
```

Conservative verification mode:

```bash
horcrux 10.10.10.10 --verify
```

---

# Doctor

HORCRUX includes a dedicated environment checker.

```bash
horcrux doctor
```

It checks the external security-tool ecosystem that HORCRUX can orchestrate.

Examples include:

```text
nmap
rustscan
masscan
naabu

gobuster
ffuf
feroxbuster
dirsearch
nikto
whatweb
wafw00f
nuclei

smbclient
rpcclient
enum4linux-ng
netexec

ldapsearch
ldapdomaindump

snmpwalk
onesixtyone

hydra
medusa
john
hashcat
sqlmap

searchsploit
msfconsole
msfvenom

impacket tooling
bloodhound-python
kerbrute
evil-winrm

linpeas
pspy
lse
winpeas

chisel
proxychains4

docker
kubectl
helm
```

The Doctor also checks common offensive-security wordlists.

---

# Wordlists

HORCRUX expects a serious operator workstation to have access to useful wordlists.

The Doctor therefore checks for resources from locations such as:

```text
/usr/share/wordlists
/usr/share/seclists
/usr/share/SecLists
/opt/SecLists
~/SecLists
```

The inventory includes common lists for:

### Web content

```text
common.txt
big.txt
raft-small-words.txt
raft-medium-words.txt
raft-large-words.txt
raft-small-directories.txt
raft-medium-directories.txt
raft-large-directories.txt
directory-list-2.3-small.txt
directory-list-2.3-medium.txt
directory-list-2.3-big.txt
quickhits.txt
```

### DNS

```text
subdomains-top1million-5000.txt
subdomains-top1million-20000.txt
namelist.txt
```

### Fuzzing

```text
Generic-SQLi.txt
XSS-Jhaddix.txt
```

### Credentials

```text
rockyou.txt
10-million-password-list-top-1000.txt
10-million-password-list-top-10000.txt
10-million-password-list-top-100000.txt
```

### Users

```text
top-usernames-shortlist.txt
```

The goal is that:

```bash
horcrux doctor
```

becomes the first command run on a new operator workstation.

---

# Installation

## Windows

HORCRUX can be installed without requiring a global Python installation.

From the repository:

```powershell
.\install.ps1
```

Or manually:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

Then:

```powershell
horcrux --version
```

---

## Linux / macOS

```bash
chmod +x install.sh
./install.sh
```

Or manually:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

Then:

```bash
horcrux --version
```

---

# Kali Linux

HORCRUX is particularly suited to a Kali workstation because the external toolchain already exists there.

The repository includes:

```text
scripts/install_kali.sh
```

Run:

```bash
chmod +x scripts/install_kali.sh
./scripts/install_kali.sh
```

Then:

```bash
horcrux doctor
```

---

# Example Operator Workflow

Suppose you receive:

```text
10.10.10.42
```

Start:

```bash
horcrux
```

Then:

```text
horcrux > scan 10.10.10.42
```

HORCRUX performs the initial discovery.

You then inspect:

```text
horcrux > services
```

You might discover:

```text
22/tcp   ssh
80/tcp   http
445/tcp  microsoft-ds
```

Next:

```text
horcrux > findings
```

Then:

```text
horcrux > next
```

HORCRUX may now suggest:

```text
Review web attack surface
Review SMB shares/domain data
Resolve CVE / SearchSploit candidates
Review SSH exposure
```

Then:

```text
horcrux > cve
```

The version inventory is passed through SearchSploit.

Then:

```text
horcrux > exploit
```

The operator gets the candidate exploit intelligence in one place.

Finally:

```text
horcrux > report
```

produces the assessment report.

---

# Designed Around Real Tools

HORCRUX is deliberately not a closed ecosystem.

If a tool is already installed and useful, HORCRUX should be able to invoke it.

The architecture is designed around a simple pattern:

```text
                 HORCRUX
                    │
        ┌───────────┼───────────┐
        │           │           │
      NMAP        HTTP        SMB
        │           │           │
     Scanner      FFUF      NetExec
     Scripts     Gobuster    RPCClient
     Version      Nuclei    Enum4linux
        │           │           │
        └───────────┼───────────┘
                    │
              NORMALIZED DATA
                    │
          ┌─────────┼─────────┐
          │         │         │
       FINDINGS    CVEs    ACTIONS
          │         │         │
          └─────────┼─────────┘
                    │
             OPERATOR REVIEW
```

---

# Architecture

The current codebase is intentionally small.

```text
horcrux/
│
├── horcrux/
│   ├── cli.py
│   │
│   ├── models.py
│   │
│   ├── core/
│   │   ├── doctor.py
│   │   ├── intel.py
│   │   ├── orchestrator.py
│   │   ├── parsers.py
│   │   ├── runner.py
│   │   └── storage.py
│   │
│   ├── intel/
│   │   └── search.py
│   │
│   ├── modules/
│   │   ├── local.py
│   │   ├── network.py
│   │   ├── services.py
│   │   └── web/
│   │       ├── discovery.py
│   │       └── scanner.py
│   │
│   ├── reporting/
│   │   └── reports.py
│   │
│   └── ui/
│       ├── ascii.py
│       └── console.py
│
├── ascii_assets/
├── scripts/
├── tests/
├── install.ps1
├── install.sh
├── pyproject.toml
└── requirements.txt
```

The separation is intentional:

```text
CLI
 ↓
ORCHESTRATOR
 ↓
MODULES
 ↓
RUNNER
 ↓
REAL EXTERNAL TOOLS
 ↓
PARSERS
 ↓
NORMALIZED STATE
 ↓
FINDINGS / INTEL / REPORTING
```

---

# UI

HORCRUX keeps the interface intentionally terminal-native.

Running:

```bash
horcrux
```

shows the large animated:

```text
HORCRUX
```

title.

The Elder Wand is displayed as the single additional graphic.

The title animation is cosmetic; it does not interfere with the operator console.

`--version` uses the same presentation:

```bash
horcrux --version
```

The UI is designed to feel like an operator tool rather than a generic Python CLI.

---

# Output Philosophy

HORCRUX separates three things:

### Operator output

The important information.

```text
[HIGH] Exposed environment file
[INFO] SMB exposed
[INFO] Login surface identified
```

### Evidence

The actual tool responses and HTTP artifacts.

```text
workspaces/<target>/raw/
workspaces/<target>/responses/
workspaces/<target>/headers/
```

### Intelligence

The interpreted data:

```text
services
software
findings
credentials
CVE candidates
exploit candidates
next actions
```

This separation keeps the tool usable when the underlying scanners become noisy.

---

# Reporting

Run:

```text
report
```

to generate a Markdown report.

The report includes:

* target
* service inventory
* software inventory
* findings
* confidence
* evidence
* CVE/SearchSploit candidates

The workspace remains the authoritative evidence store.

---

# Who Is HORCRUX For?

HORCRUX is built for:

### CTF players

Reduce repetitive recon and get to the interesting parts faster.

### TryHackMe / Hack The Box operators

Run a standardized discovery workflow across rooms instead of reinventing the first 10 commands every time.

### Penetration testers

Create a repeatable starting workflow and preserve evidence automatically.

### Security students

Learn how different tools fit together instead of learning them as isolated commands.

### Security researchers

Build a structured workspace around reconnaissance and vulnerability research.

---

# What HORCRUX Is Not

HORCRUX is not intended to be:

* an invisible autonomous attacker
* a replacement for Nmap
* a replacement for Metasploit
* a vulnerability database
* an exploit repository
* a magic "press one button and own the machine" framework

The value is the **operator workflow connecting those capabilities**.

---

# Current Capability

The current release provides the foundation for:

```text
REAL NETWORK DISCOVERY
        ↓
SERVICE FINGERPRINTING
        ↓
SERVICE-SPECIFIC ENUMERATION
        ↓
WEB DISCOVERY
        ↓
TECHNOLOGY IDENTIFICATION
        ↓
VULNERABILITY INTELLIGENCE
        ↓
SEARCHSPLOIT
        ↓
NUCLEI
        ↓
FINDINGS
        ↓
NEXT ACTIONS
        ↓
EXPLOIT REVIEW
        ↓
REPORT
```

It is deliberately designed so additional enumeration and exploitation modules can be added without changing the operator interface.

---

# Responsible Use

HORCRUX is an offensive-security tool.

Use it only against:

* systems you own
* systems you are explicitly authorized to test
* penetration-testing engagements where you have permission
* CTFs
* TryHackMe
* Hack The Box
* authorized training environments

Do not use HORCRUX to scan or exploit systems without authorization.

---

# Contributing

HORCRUX is designed around small, composable modules.

A useful contribution might be:

```text
new service module
new parser
new detection signature
new reporting format
new tool integration
new doctor check
new wordlist detection
new finding type
```

The important rule is:

> **Add intelligence to the workflow, not just another command wrapper.**

---

# License

See the repository license.

---

# The Goal

HORCRUX is ultimately trying to answer one question:

> **"I have a target. What should I do next?"**

Not:

> "Which 37 commands do I remember?"

Not:

> "Where did I save that Nmap output?"

Not:

> "Was that SearchSploit result actually relevant?"

Not:

> "Which wordlist did I use last time?"

The operator should be able to start with:

```bash
horcrux
```

and progressively move from:

```text
UNKNOWN TARGET
```

to:

```text
KNOWN ATTACK SURFACE
```

to:

```text
EVIDENCE-BACKED FINDINGS
```

to:

```text
CVE / EXPLOIT INTELLIGENCE
```

to:

```text
OPERATOR DECISION
```

That is HORCRUX.

**The fragments reveal the whole.**