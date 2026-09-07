import time
from rich.console import Console

from horcrux.intel.search import is_reliable_software_evidence
from horcrux.models import PROFILES, ScanProfile, Software, get_profile
from horcrux.ui.progress import ScanProgressManager, StageState


def test_scan_profiles():
    # Verify all mandatory profiles exist
    expected = ["quick", "standard", "deep", "network", "web", "service", "intel", "local"]
    for name in expected:
        p = get_profile(name)
        assert p.name == name

    # Verify deep profile has full TCP ports and expensive checks
    deep = get_profile("deep")
    assert deep.port_spec == "full"
    assert deep.expensive_checks is True

    # Verify quick profile has top100 ports and no UDP
    quick = get_profile("quick")
    assert quick.port_spec == "top100"
    assert quick.include_udp is False

    # Verify intel profile has CVE correlation enabled
    intel = get_profile("intel")
    assert intel.cve_correlation is True

    # Standard scan does NOT enable CVE flood by default
    standard = get_profile("standard")
    assert standard.cve_correlation is False


def test_progress_manager_lifecycle():
    console = Console(record=True)
    with ScanProgressManager(console, "127.0.0.1", "standard") as mgr:
        mgr.start_stage("reachability")
        assert mgr.stages["reachability"].state == StageState.RUNNING

        mgr.on_command_start(["nmap", "-Pn", "127.0.0.1"])
        assert mgr.active_tool == "nmap"

        mgr.on_command_finish(["nmap"], 0)
        assert mgr.active_tool == ""

        mgr.complete_stage("reachability")
        assert mgr.stages["reachability"].state == StageState.COMPLETED

        mgr.skip_stage("intel", "Gated by profile")
        assert mgr.stages["intel"].state == StageState.SKIPPED


def test_evidence_gating_for_searchsploit():
    # Reject weak guesses like ppp or unknown
    weak_software = Software(
        product="ppp",
        version="",
        service="80/tcp",
        source="nmap",
        confidence=0.4,
    )
    assert is_reliable_software_evidence(weak_software) is False

    # Reject generic products without version
    generic_software = Software(
        product="Apache",
        version="",
        service="80/tcp",
        source="nmap",
        confidence=0.6,
    )
    assert is_reliable_software_evidence(generic_software) is False

    # Accept confirmed product with version
    strong_software = Software(
        product="OpenSSH",
        version="8.9p1",
        service="22/tcp",
        source="nmap",
        confidence=0.95,
    )
    assert is_reliable_software_evidence(strong_software) is True


def test_ai_progress_manager_display():
    from horcrux.ui.progress import AIProgressManager

    console = Console(record=True)
    mgr = AIProgressManager(console, provider="Google", model="gemini-2.5-flash")
    mgr.set_phase("Consulting Google")

    display_group = mgr._build_display()
    assert display_group is not None
    # Check rendered text by rendering to console
    console.print(display_group)
    rendered_text = console.export_text()

    # Verify no raw markup tags leaked
    assert "[bold" not in rendered_text
    assert "[dim" not in rendered_text
    assert "[/bold" not in rendered_text
    assert "[/dim" not in rendered_text

    # Verify provider is not redundantly duplicated
    assert "Consulting Google... (gemini-2.5-flash)" in rendered_text
    assert "[Google" not in rendered_text

