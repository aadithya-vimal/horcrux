<div align="center">

# ⚡ H O R C R U X ⚡

### *The fragments reveal the whole.*

[![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&duration=3000&pause=1000&color=DA70D6&center=true&vCenter=true&width=650&lines=THE+FRAGMENTS+REVEAL+THE+WHOLE;AUTONOMOUS+ATTACK+SURFACE+ORCHESTRATION;EVIDENCE-FIRST+OPERATOR+INTELLIGENCE;NEXT+BEST+ACTION+RECOMMENDATION+ENGINE;7+HORCRUX+RELICS+AND+DEATHLY+HALLOWS)](https://git.io/typing-svg)

<p align="center">
  <img src="https://img.shields.io/badge/HORCRUX-v1.0.0-9932CC?style=for-the-badge&logo=target&logoColor=white" alt="Version" />
  <img src="https://img.shields.io/badge/Python-3.11+-8A2BE2?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/Platform-Kali%20%7C%20Linux%20%7C%20Windows-00FFFF?style=for-the-badge&logo=linux&logoColor=black" alt="Platform" />
  <img src="https://img.shields.io/badge/License-MIT-FF00FF?style=for-the-badge" alt="License" />
  <img src="https://img.shields.io/badge/Terminal-Rich%20%26%20ANSI%20Gradients-00FA9A?style=for-the-badge&logo=gnometerminal&logoColor=black" alt="Terminal UI" />
</p>

```text
            ██╗  ██╗ ██████╗ ██████╗  ██████╗██████╗ ██╗   ██╗██╗  ██╗
            ██║  ██║██╔═══██╗██╔══██╗██╔════╝██╔══██╗╚██╗ ██╔╝╚██╗██╔╝
            ███████║██║   ██║██████╔╝██║     ██████╔╝ ╚████╔╝  ╚███╔╝ 
            ██╔══██║██║   ██║██╔══██╗██║     ██╔══██╗  ╚██╔╝   ██╔██╗ 
            ██║  ██║╚██████╔╝██║  ██║╚██████╗██║  ██║   ██║   ██╔╝ ██╗
            ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
```

**An intelligent, operator-centric offensive-security orchestration platform.**  
*Transforming the fragmented first stages of security assessments into an evidence-driven, structured workflow.*

[Features](#-key-features) • [Quick Start](#-quick-start) • [Architecture](#-architecture--pipeline) • [Terminal UI](#-terminal-ui--animations) • [Artifacts Gallery](#-horcrux-artifacts-gallery) • [Doctor](#-doctor--prerequisites)

</div>

---

> [!NOTE]
> **HORCRUX** does not replace the security tools you trust. It **orchestrates** them. It executes network reconnaissance, service fingerprinting, content discovery, and vulnerability intelligence, recording every byte of raw evidence while presenting a prioritized **Next Best Action** roadmap.

---

## ✦ Orchestration Pipeline

```mermaid
flowchart TD
    classDef target fill:#4B0082,stroke:#00FFFF,stroke-width:2px,color:#FFFFFF
    classDef recon fill:#003366,stroke:#00FFFF,stroke-width:1px,color:#FFFFFF
    classDef intel fill:#4A0072,stroke:#FF00FF,stroke-width:1px,color:#FFFFFF
    classDef storage fill:#1A365D,stroke:#00FA9A,stroke-width:2px,color:#FFFFFF
    classDef action fill:#7A0000,stroke:#FFFF00,stroke-width:2px,color:#FFFFFF

    T([🎯 TARGET]):::target --> N[Nmap TCP & UDP Discovery]:::recon
    N --> S{Service Fingerprinting}:::recon

    S -->|HTTP / HTTPS| W[Web Engine: WhatWeb / FFUF / Nuclei]:::recon
    S -->|SMB 139 / 445| SMB[SMB Enumeration & Share Auditing]:::recon
    S -->|LDAP 389 / 636| LDAP[LDAP Domain Dump]:::recon
    S -->|SSH 22| SSH[SSH Ciphers & Banner Intel]:::recon
    S -->|Databases / Cache| DB[SQL & Redis Inspection]:::recon

    W --> E[(📁 WORKSPACE RAW EVIDENCE)]:::storage
    SMB --> E
    LDAP --> E
    SSH --> E
    DB --> E

    E --> C[SearchSploit & CVE Correlation]:::intel
    E --> CR[Credential Secret Harvester]:::intel
    E --> G[Attack Surface Tree Graph]:::intel

    C --> A{⚡ NEXT-ACTION ENGINE}:::action
    CR --> A
    G --> A

    A --> O([👑 RANKED OPERATOR ACTIONS]):::action
```

---

## ⚡ Key Features

* **Deterministic-First Authority**: Real tools remain authoritative. Real deterministic parsers and validators produce facts. AI operates as a contextual reasoning layer on top of verified evidence, never hallucinating services, versions, credentials, or vulnerabilities.
* **Separation of Surface vs. Audit vs. Findings**:
  * `surface`: Network attack surface (open ports & protocols). *Open ports are not vulnerabilities.*
  * `audit`: Audited & hardened controls (e.g. protected `.env`, rejected SMB null sessions, HTTP 403 admin panels, soft-404 pages).
  * `findings`: Verified vulnerabilities with reproducible proof (e.g. leaked credentials, unauthenticated Redis, confirmed CVEs).
* **Centralized Service-to-Module Router**: Intelligently inspects protocols, ports, products, and versions to dispatch tailored enumeration modules (HTTP, SMB, LDAP, Kerberos, SSH, FTP, SMTP, DNS, SNMP, Databases, NFS, WinRM, RDP) without blind tool spam.
* **Universal Web Enumeration & Response Validation Pipeline**:
  * Automatically invokes best available fuzzing tools (**FFUF**, **Gobuster**, **Feroxbuster**, or built-in native prober) with smart wordlist resolution and fallback tracking.
  * Every discovered candidate path passes through the baseline engine: Soft-404, SPA fallback, and generic error templates are suppressed as false positives; confirmed sensitive content (e.g. `.env`, Git metadata, SQL dumps, directory listings, credentials, debug traces) is promoted to verified findings.
* **State-Aware Next Best Action Engine & Subsystem Tracking**:
  * Tracks live subsystem states (`web_discovery`, `web_validation`, `cve_intelligence`, `smb_enum`, `ldap_enum`, etc.).
  * Eliminates blind fixed scores and stale recommendations. If CVE correlation yielded 0 candidates, it never repeats the recommendation and suggests relevant service review instead (`subsystems` / `next`).
* **Multi-Provider AI Intelligence Core**:
  * Native support for **Groq** (`llama-3.3-70b-versatile`), **OpenAI** (`gpt-4o`), **Anthropic** (`claude-3-5-sonnet`), and **Google AI Studio / Gemini** (`gemini-2.5-flash`).
  * Intelligent exploit candidate triage, contextual Next-Best-Action ranking, attack-path synthesis, and operator Q&A (`ask <question>`).
  * Deterministic offline fallback if AI is disabled or unconfigured.
  * Strict token efficiency with SHA-256 request caching.
* **Pluggable Web Validation Engine**: Baseline response fingerprinting, Soft-404/SPA catch-all detection, and content-length drift heuristics (<15%).
* **Persistent Settings & Key Management**: Cross-platform configuration persistence with OS keychain (`keyring`) storage and secure credential masking (`gsk_••••••••9F31`).
* **Deep Finding Inspector**: Instant reproduction commands (`curl ...`), evidence snippets, and tactical rationale for every finding (`inspect <id>`).
* **Platform-Aware Doctor**: Comprehensive 12-category dependency audit across Core, Network, Web, SMB/AD, Databases, Credentials, Exploit Intel, Local, Tunneling, Containers, and AI Engine.
* **Persistent Workspaces**: Every assessment gets an isolated workspace tracking structured state (`state.json`), raw command logs, headers, and HTTP responses.
* **Attack Surface Tree Graph**: Interactive Rich visual hierarchy linking targets, open ports, fingerprinted services, vulnerabilities, and leaked credentials.
* **Horcrux Artifact Gallery**: Built-in showcase of thematic ASCII relics representing the 7 Horcruxes and Deathly Hallows.


---

## 🚀 Quick Start

### 1. Installation

#### Linux / Kali Linux
```bash
git clone https://github.com/aadithya-vimal/horcrux.git
cd horcrux
chmod +x install.sh
./install.sh
```

#### Windows (PowerShell)
```powershell
git clone https://github.com/aadithya-vimal/horcrux.git
cd horcrux
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install.ps1
```

#### Manual Python Setup
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
```

---

### 2. Basic Usage

```bash
# Launch interactive operator console
horcrux

# One-shot reconnaissance against a target
horcrux 10.10.10.10

# Deep port scanning and aggressive enumeration
horcrux 10.10.10.10 --deep

# Check installed tools, wordlists, and AI configuration
horcrux doctor

# Configure AI provider key securely
horcrux settings provider groq <your-api-key>

# Ask AI security analyst with target context
horcrux ask "What is the primary attack vector?" --target 10.10.10.10

# Generate Markdown engagement report
horcrux report 10.10.10.10
```

---

## ⚙️ AI Configuration & Settings

HORCRUX stores configuration persistently in platform-appropriate locations (`~/.config/horcrux/` on Linux, `%APPDATA%\Horcrux\` on Windows, `~/Library/Application Support/horcrux/` on macOS). API keys are stored in the OS keychain via `keyring` and displayed masked:

```text
┌─────────────────────────── ✦ HORCRUX SETTINGS ✦ ────────────────────────────┐
│                                                                             │
│  AI PROVIDERS                                                               │
│                                                                             │
│    ① Groq                     ● CONFIGURED (gsk_••••••••9F31)               │
│       Model: llama-3.3-70b-versatile                                        │
│                                                                             │
│    ② OpenAI                   ○ NOT CONFIGURED                              │
│       Model: gpt-4o                                                         │
│                                                                             │
│    ③ Anthropic / Claude       ○ NOT CONFIGURED                              │
│       Model: claude-3-5-sonnet-latest                                       │
│                                                                             │
│    ④ Google AI Studio / Gemini ○ NOT CONFIGURED                             │
│       Model: gemini-2.5-flash                                               │
│                                                                             │
│  Default Provider: GROQ                                                     │
│  Default Model:    llama-3.3-70b-versatile                                  │
│  AI Engine Status: ENABLED                                                  │
│                                                                             │
│  💡 Tip: Model availability may vary by region or account. Use 'settings    │
│  model' to select or switch.                                                │
│                                                                             │
│  Commands:                                                                  │
│    settings provider <groq|openai|anthropic|google> [key]                   │
│    settings model [provider] [model_name]  (select or change model)         │
│    settings models [provider]              (list available regional models) │
│    settings default <provider>                                              │
│    settings test [provider]                                                 │
│    settings remove <provider>                                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

> [!TIP]
> **Regional & Account Model Flexibility**: Model availability and API naming conventions often differ across geographical regions (e.g. EU vs. US) and enterprise tenants. Run `horcrux settings model <provider>` or `settings model` inside the console to dynamically discover available models for your account or enter a custom model name (e.g. `gemini-1.5-flash`, `llama-3.1-8b-instant`, `claude-3-7-sonnet-latest`, or private deployment IDs).


---

## 🖥 Terminal UI & Operator Workflow

HORCRUX delivers a terminal experience with animated feedback, shimmering headers, and visual data structures.

### Live Status Dashboard (`status`)

```text
╭─────────────────────────────────────────────────────────────────────────────╮
│ ❖ TARGET WORKSPACE: 10.10.10.10  |  STORAGE: workspaces/10.10.10.10         │
╰─────────────────────────────────────────────────────────────────────────────╯
╭ 🌐 SERVICES ╮ ╭ 🛡 AUDITED ╮ ╭ ⚡ FINDINGS ╮ ╭ 📦 SOFTWARE ╮ ╭ 🔑 CREDS ╮ ╭ 🎯 EXPLOITS ╮
│      3      │ │     4      │ │      1      │ │      2      │ │    1     │ │      2      │
│    Open     │ │  Audited   │ │   Recorded  │ │ Identified  │ │ Captured │ │ Correlated  │
╰─────────────╯ ╰────────────╯ ╰─────────────╯ ╰─────────────╯ ╰──────────╯ ╰─────────────╯

╭──────────────────────── ⬡ DETECTED WEB TECHNOLOGIES ────────────────────────╮
│  nginx  •  PHP 8.1  •  WordPress 6.2                                        │
╰─────────────────────────────────────────────────────────────────────────────╯

╔═══════════════════════════ ★ NEXT BEST ACTION ★ ════════════════════════════╗
│  ⚡ Test database credentials from exposed backup                           ║
│  Reason: DB_PASSWORD recovered from /backup.sql  • Score: 99                ║
╚═════════════════════════════════════════════════════════════════════════════╝
```

---

### Separation of Attack Surface vs. Audited Controls vs. Findings

#### 1. Attack Surface (`surface`)
*Open ports are not vulnerabilities. They represent the active perimeter.*
```text
                      ✦ NETWORK ATTACK SURFACE — 10.10.10.10 ✦                     
┌──────┬───────┬──────────────┬─────────┬─────────┬───────────────────────────────┐
│ Port │ Proto │ Service      │ Product │ Version │ Exposure Role                 │
├──────┼───────┼──────────────┼─────────┼─────────┼───────────────────────────────┤
│ 22   │ TCP   │ ssh          │ OpenSSH │ 8.9p1   │ Domain / Auth                 │
│ 80   │ TCP   │ http         │ nginx   │ 1.18.0  │ Web Application               │
│ 445  │ TCP   │ microsoft-ds │ Samba   │ 4.15.5  │ Domain / Auth                 │
└──────┴───────┴──────────────┴─────────┴─────────┴───────────────────────────────┘
```

#### 2. Audited & Hardened Controls (`audit`)
*Records defensive checks that were tested and verified secure.*
```text
                  ✦ AUDITED & HARDENED CONTROLS — 10.10.10.10 ✦                   
┌──────────────┬──────────────────────────────┬───────────────────────────────┬───────────────────────────────────────────┐
│ Status       │ Asset / Scope                │ Check / Rule                  │ Reason / Observation                      │
├──────────────┼──────────────────────────────┼───────────────────────────────┼───────────────────────────────────────────┤
│  🛡 HARDENED │ http://10.10.10.10/.env       │ Environment File Disclosure   │ Returned HTTP 404; protected against leak │
│  🛡 HARDENED │ 10.10.10.10:445              │ SMB Anonymous Authentication  │ Anonymous/null session rejected           │
│   ✔ AUDITED  │ http://10.10.10.10/admin     │ Administrative Interface Surface│ HTTP 403 Forbidden; access restricted     │
│   ✔ AUDITED  │ http://10.10.10.10/robots.txt│ Robots Endpoint Discovery     │ Clean directives; no sensitive paths      │
└──────────────┴──────────────────────────────┴───────────────────────────────┴───────────────────────────────────────────┘
```

#### 3. Real Security Findings (`findings`) & Inspector (`inspect <id>`)
*Confirmed exposures with actionable evidence and reproduction commands.*
```text
                      ✦ SECURITY FINDINGS — 10.10.10.10 ✦                      
┌────────────┬──────────────┬──────────────────────────────────┬──────────────────┬─────────────────────────────┬─────────────┐
│  Severity  │  Confidence  │ Title                            │ Validation State │ Asset                       │ Finding ID  │
├────────────┼──────────────┼──────────────────────────────────┼──────────────────┼─────────────────────────────┼─────────────┤
│ ✖ CRITICAL │ ████████ 95% │ Exposed Database Credentials in  │    CONFIRMED     │ http://10.10.10.10/backup.sql│ web-backup-1│
│            │              │ Backup Archive                   │                  │                             │             │
└────────────┴──────────────┴──────────────────────────────────┴──────────────────┴─────────────────────────────┴─────────────┘
```

Inspecting a finding (`inspect web-backup-1`):
```text
┌───────────────────────────────── ✦ ✖ CRITICAL ✦ ────────────────────────────────┐
│ FINDING: Exposed Database Credentials in Backup Archive                         │
│ Asset: http://10.10.10.10/backup.sql  |  Port: 80  |  Protocol: TCP             │
│ Confidence: 95%  |  State: confirmed                                            │
└─────────────────────────────────────────────────────────────────────────────────┘
┌──────────────────────── ⚡ WHY IT MATTERS (IMPACT) ──────────────────────────────┐
│ Direct unauthorized database takeover; leaked administrative credentials.       │
└─────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────── 🔍 VERIFIED EVIDENCE ─────────────────────────────┐
│ • DB_PASSWORD=SuperSecretAdminPassword123!                                      │
│ • DB_USER=root                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
┌─────────────────────────── 🚀 REPRODUCTION COMMAND ─────────────────────────────┐
│ curl -s http://10.10.10.10/backup.sql | grep -E "(DB_USER|DB_PASSWORD)"        │
└─────────────────────────────────────────────────────────────────────────────────┘
┌──────────────────────── 🎯 RECOMMENDED OPERATOR ACTION ─────────────────────────┐
│ Connect to exposed database listener or test administrative credential reuse.   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

### Exploit Intelligence & AI Triage (`cve`, `exploit`, `intel`)

```text
                  ✦ CVE / SEARCHSPLOIT CANDIDATES ✦                   
┌──────────────┬────────────────┬─────────┬─────────┬──────────────────────┬────────────────┬─────────────────────────────┐
│ Confidence   │ CVE            │ Product │ Version │ Relevance / Decision │ Exploitability │ Title                       │
├──────────────┼────────────────┼─────────┼─────────┼──────────────────────┼────────────────┼─────────────────────────────┤
│ ████████ 92% │ CVE-2021-41773 │ Apache  │ 2.4.49  │  ★ HIGHLY RELEVANT   │ HIGH (REMOTE)  │ Path Traversal & RCE        │
│ ████░░░░ 40% │ -              │ Apache  │ 2.4.49  │     ✖ REJECTED       │ LOW (DOS)      │ Denial of Service PoC       │
└──────────────┴────────────────┴─────────┴─────────┴──────────────────────┴────────────────┴─────────────────────────────┘
```

---

### Operator AI Security Advisor (`ask <question>`)

```text
horcrux@10.10.10.10 ❯ ask "What is the quickest path to a shell?"

┌───────────────── ⚡ HORCRUX AI ADVISOR — 'What is the quickest path to a shell?' ──────────────────┐
│                                                                                                    │
│ OBSERVATION:                                                                                       │
│ Recovered database credentials ('root' / 'SuperSecretAdminPassword123!') from                      │
│ http://10.10.10.10/backup.sql. Port 3306 (MySQL) and Port 22 (SSH) are open.                       │
│                                                                                                    │
│ REASONING:                                                                                         │
│ Administrative credentials often share passwords with the local system account or can be used      │
│ via MySQL SELECT INTO OUTFILE to drop a PHP web shell into /var/www/html/.                         │
│                                                                                                    │
│ RECOMMENDATION:                                                                                    │
│ 1. Test SSH authentication: ssh root@10.10.10.10                                                   │
│ 2. Test MySQL login: mysql -u root -p'SuperSecretAdminPassword123!' -h 10.10.10.10                 │
│                                                                                                    │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
```


---

## 🏛 Horcrux Artifacts Gallery

HORCRUX weaves the lore of ancient artifacts into its terminal identity. View the full gallery at any time with `horcrux gallery`.

<details>
<summary><b>View Artifacts (The 7 Horcruxes & Relics)</b></summary>

### 1. The Elder Wand · *Deathly Hallow*
```text
           · ✦ ·
             │
            ░█░
             │
           ▓███▓
          ░█████░
           ▓███▓
             │
            ╲█╱
           ░▓█▓░
             │
           ▓███▓
             ▾
```
> *The Deathstick. Wand of Destiny. Unyielding conduit of raw power.*

---

### 2. Tom Riddle's Diary · *Horcrux I*
```text
         ._____________________.
        /  _________________  /|
       /  /  T.M. RIDDLE   / / |
      /  /                / /  |
     /  /     ╭──────╮   / /   |
    |  |      │ ✦ ✦  │  | |    |
    |  |      │  ▼   │  | |    |
    |  |      ╰──────╯  | |   /
    |  |   ink bleeds   | |  /
    |  |________________|/  /
    |______________________/
```
> *Blank parchment drenched in memory and dark enchantments.*

---

### 3. Marvolo Gaunt's Ring · *Horcrux II*
```text
             .─────────.
           .'    ___    '.
          /    .'   '.    \
         |    /   ▲   \    |
         |   |  / ┃ \  |   |
         |    \ ━━┻━━ /    |
          \    '.___.'    /
           '.           .'
             '─────────'
              │ ✦ ✦ ✦ │
               \_____/
```
> *Ancient gold band holding the Resurrection Stone signet.*

---

### 4. Salazar Slytherin's Locket · *Horcrux III*
```text
              ╱╲_____╱╲
             │  \___/  │
              ╲   │   ╱
             .─┴──────┴─.
            /  ╭─────╮   \
           |   │  S  │    |
           |   │ ╭─╯ │    |
           |   │ ╰─╮ │    |
            \  ╰─────╯   /
             '.   ✦   .'
               '─────'
```
> *Heavy golden medallion emblazoned with the serpentine crest.*

---

### 5. Helga Hufflepuff's Cup · *Horcrux IV*
```text
           \╲  ✦ ✦ ✦  ╱/
            \╲_______╱/
             |       |
            (| ╭───╮ |)
             | │ ✦ │ |
             | ╰───╯ |
              \     /
               )   (
              /     \
             /_______\
```
> *Two-handled golden chalice engraved with the steadfast badger.*

---

### 6. Rowena Ravenclaw's Diadem · *Horcrux V*
```text
              .─.     .─.
             /   \ ✦ /   \
            /  /\ \ / /\  \
           /  /  \_V_/  \  \
          /  /           \  \
         (__(    ╭───╮    )__)
              \  │ ♦ │  /
               \ ╰───╯ /
                '─────'
```
> *Wit beyond measure is man's greatest treasure.*

---

### 7. Nagini the Serpent · *Horcrux VI*
```text
             .-==-._
            /  ✦ ✦  \
           |   (oo)  |
            \   ==  /
             '._  _.'
                ||
            _.-'  '-._
          .'  _...._  '.
         /  .'      '.  \
        |  /          \  |
         \ '.________.' /
          '._        _.'
             `''''''`
```
> *The great venomous serpent woven into Voldemort's soul.*

---

### 8. The Seventh Fragment · *The Scar*
```text
              \     /
               \   /
                \ /
                 V
                / \
               /   \
                 \
             .---.   .---.
            /     \ /     \
           |   O   X   O   |
            \     / \     /
             '---'   '---'
```
> *The curse that rebounded, leaving a lightning bolt etched in fate.*

---

### 9. The Deathly Hallows · *Master of Death*
```text
                 ▲
                /│\
               / │ \
              /  │  \
             /  ╭●╮  \
            /  │ │ │  \
           /   │ │ │   \
          /     ╰●╯     \
         /_______│_______\
```
> *The Wand, the Stone, and the Cloak. Together, conquerors of mortality.*

</details>

---

## 🩺 Doctor & Platform Dependency Audit

HORCRUX includes an automated environment auditor to check external binaries, Kali SecLists wordlists, and configured AI providers:

```bash
horcrux doctor
```

```text
                     ✦ HORCRUX PLATFORM & TOOL ECOSYSTEM AUDIT ✦                      
┌────────────────────────────┬───────────┬───────────┬────────────────────────────────┐
│ Category                   │ Tool      │ Status    │ Purpose                        │
├────────────────────────────┼───────────┼───────────┼────────────────────────────────┤
│ CORE                       │ python    │   ✔ OK    │ Python runtime (3.10+)         │
│ CORE                       │ pip       │   ✔ OK    │ Python package manager         │
│ NETWORK                    │ nmap      │   ✔ OK    │ Primary port/service discovery │
│ WEB                        │ httpx     │   ✔ OK    │ Fast HTTP probing              │
│ WEB                        │ ffuf      │   ✔ OK    │ Web fuzzer & path discovery    │
│ WEB                        │ nuclei    │   ✔ OK    │ Template vulnerability scanner │
│ SMB / AD                   │ smbclient │   ✔ OK    │ SMB share navigation & auditing│
│ EXPLOIT INTELLIGENCE       │ searchsp… │   ✔ OK    │ Exploit-DB offline lookup      │
└────────────────────────────┴───────────┴───────────┴────────────────────────────────┘

                        ✦ AI ENGINE & KEYCHAIN AUDIT ✦                         
┌────────────┬──────────────────┬──────────────────────────┬──────────────────┐
│ Provider   │      Status      │ Default Model            │ Key Availability │
├────────────┼──────────────────┼──────────────────────────┼──────────────────┤
│ GROQ       │   ✔ CONFIGURED   │ llama-3.3-70b-versatile  │ gsk_••••••••9F31 │
│ OPENAI     │ ○ NOT CONFIGURED │ gpt-4o                   │ NOT CONFIGURED   │
│ ANTHROPIC  │ ○ NOT CONFIGURED │ claude-3-5-sonnet-latest │ NOT CONFIGURED   │
│ GOOGLE     │ ○ NOT CONFIGURED │ gemini-2.5-flash         │ NOT CONFIGURED   │
└────────────┴──────────────────┴──────────────────────────┴──────────────────┘

                         ✦ WORDLIST DISCOVERY AUDIT ✦                          
┌───────────────────────────────────────────────┬───────────┬─────────────────┐
│ Wordlist                                      │  Status   │ Location / Path │
├───────────────────────────────────────────────┼───────────┼─────────────────┤
│ rockyou.txt                                   │  ✔ FOUND  │ /usr/share/w... │
│ seclists/Discovery/Web-Content/common.txt     │  ✔ FOUND  │ /usr/share/s... │
│ seclists/Discovery/Web-Content/raft-medium... │  ✔ FOUND  │ /usr/share/s... │
└───────────────────────────────────────────────┴───────────┴─────────────────┘
```

> [!TIP]
> Missing tools do **not** break HORCRUX. The orchestrator automatically skips unavailable tools or falls back to alternate discovery mechanisms.

---

## 📂 Workspace Structure

Every assessment is cleanly quarantined under its target identifier:

```text
workspaces/
└── 10.10.10.10/
    ├── state.json           # Machine-readable attack state
    ├── commands.log         # Complete log of executed commands
    ├── raw/                 # Raw tool outputs (nmap.xml, stdout, stderr)
    │   ├── nmap-tcp.stdout
    │   ├── nmap.xml
    │   └── ffuf-80.stdout
    ├── responses/           # Full HTTP response bodies
    │   ├── root.body
    │   └── wp-login.body
    ├── headers/             # Raw HTTP response headers
    └── reports/             # Generated Markdown engagement reports
```

To retrieve raw artifacts directly from the terminal without polluting your console:
```bash
horcrux source raw/nmap.xml
horcrux source responses/root.body
```

---

## 🛡 Responsible Use

> [!CAUTION]
> **HORCRUX** is designed exclusively for authorized penetration testing, security assessments, CTFs, and educational training in controlled lab environments (Hack The Box, TryHackMe, Proving Grounds, home labs). Operators must obtain explicit authorization before testing any network or system.

---

## 📜 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for more information.

<div align="center">

**⚡ The fragments reveal the whole. ⚡**

</div>
