from horcrux import __version__
from horcrux.core.parsers import parse_nmap
from horcrux.core.runner import Runner, CommandRunner
from horcrux.ui.ascii import TITLE, ELDER_WAND, GRAPHIC_DATA, generate_gradient, PALETTES
from horcrux.ui.console import get_severity_badge, get_confidence_meter, get_status_badge


def test_version():
    assert __version__ == "1.0.0"


def test_runner_alias():
    assert Runner is CommandRunner


def test_nmap_parser():
    xml = """<nmaprun><host><ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="9.6"/>
    </port>
    </ports></host></nmaprun>"""
    services, software = parse_nmap(xml, "127.0.0.1")
    assert services[0].port == 22
    assert software[0].product == "OpenSSH"


def test_ui():
    assert "HORCRUX" in TITLE
    assert "ELDER" not in ELDER_WAND


def test_graphics_gallery():
    assert len(GRAPHIC_DATA) >= 10
    for item in GRAPHIC_DATA:
        assert "name" in item
        assert "category" in item
        assert "art" in item
        assert "color" in item


def test_gradient():
    grad = generate_gradient(PALETTES["horcrux"], 20)
    assert len(grad) == 20
    assert grad[0].startswith("#")


def test_badges():
    assert "CRITICAL" in get_severity_badge("critical")
    assert "HIGH" in get_severity_badge("high")
    assert "95%" in get_confidence_meter(0.95)
    assert "VERIFIED" in get_status_badge("verified")
