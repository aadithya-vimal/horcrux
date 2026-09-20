"""Offline component and service vulnerability knowledge base.

Provides high-fidelity offline CVE, CWE, and CVSS mappings for common
server software, services, frameworks, and runtimes discovered during VAPT.
"""

from __future__ import annotations

import re
from typing import Any
from pydantic import BaseModel, Field


class ComponentVulnerability(BaseModel):
    cve: str
    cves: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    cvss: float = 7.5
    cvss_vector: str = ""
    vendor: str = ""
    product: str
    version_pattern: str  # regex or version range expression
    title: str
    description: str
    severity: str = "high"
    exploitability: str = "PUBLIC_EXPLOIT_AVAILABLE"
    exploit_refs: list[str] = Field(default_factory=list)
    remediation: str = ""

    def matches_version(self, version: str) -> bool:
        if not version:
            return False
        v_clean = version.strip().lower()
        pat = self.version_pattern.strip().lower()

        # Direct equality or regex match
        if pat == v_clean:
            return True
        try:
            if re.search(pat, v_clean):
                return True
        except re.error:
            pass

        # Check version prefixes (e.g., "1.3.5" matches "1.3.5a")
        if v_clean.startswith(pat) or pat.startswith(v_clean):
            return True

        return False


# Curated offline database of high-impact service and framework flaws
KNOWN_VULNERABILITIES: list[ComponentVulnerability] = [
    ComponentVulnerability(
        cve="CVE-2015-3306",
        cves=["CVE-2015-3306"],
        cwes=["CWE-284"],
        cvss=9.8,
        cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        vendor="proftpd",
        product="proftpd",
        version_pattern=r"^1\.3\.5(?:[a-z0-9._-]*)?$",
        title="ProFTPD 1.3.5 mod_copy Arbitrary File Copy / Remote Command Execution",
        description="The mod_copy module in ProFTPD 1.3.5 allows unauthenticated remote attackers to read and write arbitrary files via the SITE CPFR and SITE CPTO commands.",
        severity="critical",
        exploitability="HIGH (REMOTE)",
        exploit_refs=["EDB-ID:36742", "EDB-ID:49908"],
        remediation="Upgrade ProFTPD to version 1.3.5a or newer, or disable mod_copy in proftpd.conf.",
    ),
    ComponentVulnerability(
        cve="CVE-2021-41773",
        cves=["CVE-2021-41773", "CVE-2021-42013"],
        cwes=["CWE-22"],
        cvss=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        vendor="apache",
        product="apache",
        version_pattern=r"^2\.4\.49(?:[a-z0-9._-]*)?$",
        title="Apache HTTP Server 2.4.49 Path Traversal and Remote Code Execution",
        description="A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives.",
        severity="critical",
        exploitability="HIGH (REMOTE)",
        exploit_refs=["EDB-ID:50383"],
        remediation="Upgrade Apache HTTP Server to version 2.4.51 or later.",
    ),
    ComponentVulnerability(
        cve="CVE-2021-42013",
        cves=["CVE-2021-42013"],
        cwes=["CWE-22"],
        cvss=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        vendor="apache",
        product="apache",
        version_pattern=r"^2\.4\.50(?:[a-z0-9._-]*)?$",
        title="Apache HTTP Server 2.4.50 Incomplete Fix Path Traversal and RCE",
        description="Incomplete fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 allowed path traversal and remote code execution if mod_cgi is enabled.",
        severity="critical",
        exploitability="HIGH (REMOTE)",
        exploit_refs=["EDB-ID:50406"],
        remediation="Upgrade Apache HTTP Server to version 2.4.51 or later.",
    ),
    ComponentVulnerability(
        cve="CVE-2018-15473",
        cves=["CVE-2018-15473"],
        cwes=["CWE-200"],
        cvss=5.3,
        cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        vendor="openbsd",
        product="openssh",
        version_pattern=r"^(?:[1-6]\.|7\.[0-7])(?:p\d+)?",
        title="OpenSSH < 7.7 Username Enumeration",
        description="OpenSSH through 7.7 is prone to a user enumeration vulnerability due to different response timings and message structures for valid vs invalid usernames.",
        severity="medium",
        exploitability="REMOTE ENUMERATION",
        exploit_refs=["EDB-ID:45233", "EDB-ID:45939"],
        remediation="Upgrade OpenSSH to version 7.7 or newer.",
    ),
    ComponentVulnerability(
        cve="CVE-2022-22965",
        cves=["CVE-2022-22965"],
        cwes=["CWE-94"],
        cvss=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        vendor="vmware",
        product="spring_framework",
        version_pattern=r"^(?:5\.[0-2]\.|5\.3\.(?:[0-9]|1[0-7])\b)",
        title="Spring Framework Remote Code Execution (Spring4Shell)",
        description="Spring MVC and Spring WebFlux applications running on JDK 9+ may be vulnerable to remote code execution via data binding access to ClassLoader.",
        severity="critical",
        exploitability="HIGH (REMOTE)",
        exploit_refs=["EDB-ID:50873"],
        remediation="Upgrade Spring Framework to 5.3.18+ or 5.2.20+.",
    ),
    ComponentVulnerability(
        cve="CVE-2021-44228",
        cves=["CVE-2021-44228"],
        cwes=["CWE-502"],
        cvss=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        vendor="apache",
        product="log4j",
        version_pattern=r"^2\.(?:[0-9]|1[0-4])(?:\.[0-9]+)?$",
        title="Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        description="Apache Log4j2 2.0-beta9 through 2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        severity="critical",
        exploitability="HIGH (REMOTE)",
        exploit_refs=["EDB-ID:50592"],
        remediation="Upgrade Log4j to 2.17.1 or newer.",
    ),
    ComponentVulnerability(
        cve="CVE-2024-23897",
        cves=["CVE-2024-23897"],
        cwes=["CWE-22"],
        cvss=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        vendor="jenkins",
        product="jenkins",
        version_pattern=r"^(?:2\.(?:[0-9]|[1-3][0-9]|4[0-3][0-9]|44[0-1])\b)",
        title="Jenkins CLI Arbitrary File Read and RCE",
        description="Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents.",
        severity="critical",
        exploitability="HIGH (REMOTE)",
        exploit_refs=["EDB-ID:51993"],
        remediation="Upgrade Jenkins to 2.442, LTS 2.426.3 or newer, or disable CLI access.",
    ),
    ComponentVulnerability(
        cve="CVE-2022-29078",
        cves=["CVE-2022-29078"],
        cwes=["CWE-94"],
        cvss=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        vendor="ejs",
        product="ejs",
        version_pattern=r"^(?:[1-2]\.|3\.(?:0\.|1\.[0-6]\b))",
        title="EJS Server-Side Template Injection / Remote Code Execution",
        description="The package ejs before 3.1.7 is vulnerable to Server-Side Template Injection (SSTI) via the settings[view options][outputFunctionName] parameter.",
        severity="critical",
        exploitability="HIGH (REMOTE)",
        exploit_refs=[],
        remediation="Upgrade ejs to version 3.1.7 or later.",
    ),
    ComponentVulnerability(
        cve="CVE-2017-5941",
        cves=["CVE-2017-5941"],
        cwes=["CWE-502"],
        cvss=9.8,
        cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        vendor="nodejs",
        product="node-serialize",
        version_pattern=r"^0\.0\.[1-4]$",
        title="node-serialize Insecure Deserialization Remote Code Execution",
        description="Untrusted input passed into unserialize() function in node-serialize allows execution of arbitrary JavaScript code via Immediately Invoked Function Expressions (IIFE).",
        severity="critical",
        exploitability="HIGH (REMOTE)",
        exploit_refs=["EDB-ID:49585"],
        remediation="Avoid using node-serialize; migrate to safe JSON serialization.",
    ),
    ComponentVulnerability(
        cve="CVE-2014-0160",
        cves=["CVE-2014-0160"],
        cwes=["CWE-119"],
        cvss=7.5,
        cvss_vector="CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:N/A:N",
        vendor="openssl",
        product="openssl",
        version_pattern=r"^1\.0\.1[a-f]?$",
        title="OpenSSL TLS Heartbeat Information Disclosure (Heartbleed)",
        description="The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, allowing remote attackers to obtain sensitive process memory.",
        severity="high",
        exploitability="HIGH (REMOTE)",
        exploit_refs=["EDB-ID:32745", "EDB-ID:32764"],
        remediation="Upgrade OpenSSL to 1.0.1g or newer, or recompile with -DOPENSSL_NO_HEARTBEATS.",
    ),
]
