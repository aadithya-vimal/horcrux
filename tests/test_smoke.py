from horcrux import __version__
from horcrux.core.parsers import parse_nmap
from horcrux.core.runner import Runner, CommandRunner
from horcrux.ui.ascii import TITLE, ELDER_WAND


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
