import tempfile
from pathlib import Path
from horcrux.core.storage import Workspace
from horcrux.models import AuditEntry, AuditStatus, Finding, Service, Severity, ValidationState
from horcrux.modules.services import enumerate_services
from horcrux.reporting.reports import markdown


def test_network_and_services_create_audit_entries_not_findings():
    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Workspace("10.10.10.10", base=tmpdir)
        
        # Mock services where SMB (445) and LDAP (389) are open
        ws.upsert_services([
            Service(host="10.10.10.10", port=445, protocol="tcp", service="microsoft-ds"),
            Service(host="10.10.10.10", port=389, protocol="tcp", service="ldap"),
        ])

        # Mock runner with no tools available so anonymous checks fail safely
        class MockRunner:
            def which(self, cmd):
                return False
            def run(self, *args, **kwargs):
                class Res:
                    returncode = 1
                    stdout = ""
                    stderr = ""
                return Res()

        enumerate_services(ws, MockRunner(), "10.10.10.10")
        st = ws.load()

        # Open ports 445 and 389 must NOT create false positive findings
        assert len(st.findings) == 0
        # Audit entries recorded for tested SMB and LDAP controls
        assert len(st.audit) >= 1


def test_markdown_report_structure():
    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Workspace("10.10.10.20", base=tmpdir)
        st = ws.load()
        st.audit.append(
            AuditEntry(
                id="audit-env",
                category="web",
                asset="http://10.10.10.20/.env",
                check_name="env_endpoint_protection",
                status=AuditStatus.hardened,
                reason="Returned 404; protected against leakage",
            )
        )
        st.findings.append(
            Finding(
                id="finding-backup",
                category="web",
                target="10.10.10.20",
                title="Exposed Database Credentials in Backup",
                severity=Severity.critical,
                confidence=0.95,
                validation_state=ValidationState.confirmed,
                affected_asset="http://10.10.10.20/backup.sql",
                evidence=["DB_PASSWORD=SuperSecretAdminPassword123!"],
                why_it_matters="Direct unauthorized database takeover",
                recommended_next_action="Remove public database backup archive immediately",
            )
        )
        ws.save(st)

        report_file = markdown(ws)
        assert report_file.exists()
        content = report_file.read_text(encoding="utf-8")

        # Verify key sections
        assert "## Executive Risk Summary" in content
        assert "## Attack Surface" in content
        assert "## Confirmed Findings" in content
        assert "## Audited / Hardened Controls" in content
        assert "Exposed Database Credentials in Backup" in content
        assert "[hardened]" in content.lower()

