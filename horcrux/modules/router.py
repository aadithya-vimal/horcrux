from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field

from horcrux.models import Finding, ScanProfile, Service
from horcrux.modules.web.scanner import WEB_PORTS



class ServiceRoute(BaseModel):
    service: Service
    protocol: str = "tcp"
    product: str = ""
    version: str = ""
    port: int
    confidence: float = 0.90
    applicable_modules: list[str] = Field(default_factory=list)
    required_tools: list[str] = Field(default_factory=list)
    optional_tools: list[str] = Field(default_factory=list)
    wordlists: list[str] = Field(default_factory=list)
    timeout_budget: int = 180
    risk_level: str = "safe"  # safe, low, medium


class ServiceRouter:
    """
    Centralized, extensible router that examines discovered services
    and generates tailored enumeration execution plans based on profile and tool availability.
    """

    @classmethod
    def route(cls, service: Service, profile: ScanProfile) -> ServiceRoute:
        port = service.port
        proto = service.protocol.lower()
        svc_name = service.service.lower()
        prod = service.product
        ver = service.version

        applicable: list[str] = []
        required_tools: list[str] = []
        optional_tools: list[str] = []
        wordlists: list[str] = []
        timeout = profile.command_timeout
        risk = "safe"

        # 1. HTTP / Web Surface
        if port in WEB_PORTS or svc_name in {"http", "https", "ssl/http"}:
            applicable.append("web_probe")
            if "web_discovery" in profile.enabled_modules or profile.expensive_checks:
                applicable.append("web_discovery")
                wordlists.append(profile.wordlist_strategy)
            applicable.append("web_fingerprint")
            optional_tools.extend(["ffuf", "gobuster", "whatweb", "httpx", "nuclei", "nikto"])

        # 2. SMB / NetBIOS
        elif port in {139, 445} or svc_name in {"microsoft-ds", "netbios-ssn", "smb"}:
            applicable.append("smb_enum")
            optional_tools.extend(["netexec", "crackmapexec", "smbclient", "enum4linux-ng"])

        # 3. LDAP / Active Directory
        elif port in {389, 636, 3268, 3269} or "ldap" in svc_name:
            applicable.append("ldap_enum")
            optional_tools.extend(["ldapsearch", "ldapdomaindump"])

        # 4. Kerberos
        elif port == 88 or "kerberos" in svc_name:
            applicable.append("kerberos_enum")
            optional_tools.extend(["nmap", "impacket", "kerbrute"])

        # 5. SSH
        elif port == 22 or svc_name == "ssh":
            applicable.append("ssh_enum")
            optional_tools.extend(["nmap", "ssh"])

        # 6. FTP
        elif port == 21 or svc_name == "ftp":
            applicable.append("ftp_enum")
            optional_tools.extend(["nmap"])

        # 7. SMTP
        elif port in {25, 465, 587} or svc_name == "smtp":
            applicable.append("smtp_enum")
            optional_tools.extend(["nmap", "smtp-user-enum"])

        # 8. DNS
        elif port == 53 or svc_name in {"dns", "domain"}:
            applicable.append("dns_enum")
            optional_tools.extend(["dig", "host", "nslookup"])

        # 9. SNMP
        elif port == 161 or svc_name == "snmp" or proto == "udp" and port == 161:
            applicable.append("snmp_enum")
            optional_tools.extend(["snmpwalk", "onesixtyone"])

        # 10. Databases
        elif port in {3306, 5432, 1433, 6379, 27017} or svc_name in {"mysql", "postgresql", "redis", "mongodb", "ms-sql-s"}:
            applicable.append("database_enum")
            optional_tools.extend(["redis-cli", "mysql", "psql"])

        # 11. Remote Access / Management (NFS, Telnet, RDP, WinRM, VNC)
        elif port in {23, 111, 2049, 3389, 5900, 5985, 5986} or svc_name in {"telnet", "nfs", "rdp", "winrm", "vnc", "ms-wbt-server"}:
            applicable.append("remote_enum")
            optional_tools.extend(["showmount"])

        return ServiceRoute(
            service=service,
            protocol=proto,
            product=prod,
            version=ver,
            port=port,
            confidence=0.95 if ver else 0.80,
            applicable_modules=applicable,
            required_tools=required_tools,
            optional_tools=optional_tools,
            wordlists=wordlists,
            timeout_budget=timeout,
            risk_level=risk,
        )

    @classmethod
    def dispatch(cls, ws, runner, target: str, route: ServiceRoute, profile: ScanProfile) -> list[Finding]:
        """
        Executes applicable enumeration modules for a route without blind duplication.
        """
        from horcrux.modules.services.databases import enumerate_databases
        from horcrux.modules.services.dns import enumerate_dns
        from horcrux.modules.services.ftp import enumerate_ftp
        from horcrux.modules.services.kerberos import enumerate_kerberos
        from horcrux.modules.services.ldap import enumerate_ldap
        from horcrux.modules.services.remote import enumerate_remote_services
        from horcrux.modules.services.smb import enumerate_smb
        from horcrux.modules.services.smtp import enumerate_smtp
        from horcrux.modules.services.snmp import enumerate_snmp
        from horcrux.modules.services.ssh import enumerate_ssh

        findings: list[Finding] = []
        port = route.port
        svc_name = route.service.service


        for mod in route.applicable_modules:
            if mod == "smb_enum":
                f_list, _ = enumerate_smb(ws, runner, target, port)
                findings.extend(f_list)
            elif mod == "ldap_enum":
                f_list, _ = enumerate_ldap(ws, runner, target, port)
                findings.extend(f_list)
            elif mod == "kerberos_enum":
                f_list, _ = enumerate_kerberos(ws, runner, target, port)
                findings.extend(f_list)
            elif mod == "ssh_enum":
                f_list, _ = enumerate_ssh(ws, runner, target, port)
                findings.extend(f_list)
            elif mod == "ftp_enum":
                f_list, _ = enumerate_ftp(ws, runner, target, port)
                findings.extend(f_list)
            elif mod == "smtp_enum":
                f_list, _ = enumerate_smtp(ws, runner, target, port)
                findings.extend(f_list)
            elif mod == "dns_enum":
                f_list, _ = enumerate_dns(ws, runner, target, port)
                findings.extend(f_list)
            elif mod == "snmp_enum":
                f_list, _ = enumerate_snmp(ws, runner, target, port)
                findings.extend(f_list)
            elif mod == "database_enum":
                f_list, _ = enumerate_databases(ws, runner, target, port, svc_name)
                findings.extend(f_list)
            elif mod == "remote_enum":
                f_list, _ = enumerate_remote_services(ws, runner, target, port, svc_name)
                findings.extend(f_list)

        return findings
