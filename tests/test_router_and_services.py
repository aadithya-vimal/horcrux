from __future__ import annotations

from horcrux.models import ScanProfile, Service, get_profile
from horcrux.modules.router import ServiceRouter


def test_service_router_http():
    profile = get_profile("standard")
    svc = Service(host="10.0.0.1", port=80, protocol="tcp", service="http")
    route = ServiceRouter.route(svc, profile)

    assert "web_probe" in route.applicable_modules
    assert "web_fingerprint" in route.applicable_modules
    assert route.port == 80
    assert route.protocol == "tcp"


def test_service_router_smb():
    profile = get_profile("standard")
    svc = Service(host="10.0.0.1", port=445, protocol="tcp", service="microsoft-ds")
    route = ServiceRouter.route(svc, profile)

    assert "smb_enum" in route.applicable_modules
    assert "smbclient" in route.optional_tools or "netexec" in route.optional_tools


def test_service_router_ldap():
    profile = get_profile("standard")
    svc = Service(host="10.0.0.1", port=389, protocol="tcp", service="ldap")
    route = ServiceRouter.route(svc, profile)

    assert "ldap_enum" in route.applicable_modules


def test_service_router_ssh():
    profile = get_profile("standard")
    svc = Service(host="10.0.0.1", port=22, protocol="tcp", service="ssh", product="OpenSSH", version="8.9p1")
    route = ServiceRouter.route(svc, profile)

    assert "ssh_enum" in route.applicable_modules
    assert route.product == "OpenSSH"
    assert route.version == "8.9p1"


def test_service_router_ftp():
    profile = get_profile("standard")
    svc = Service(host="10.0.0.1", port=21, protocol="tcp", service="ftp")
    route = ServiceRouter.route(svc, profile)

    assert "ftp_enum" in route.applicable_modules


def test_service_router_databases():
    profile = get_profile("standard")
    redis_svc = Service(host="10.0.0.1", port=6379, protocol="tcp", service="redis")
    route_redis = ServiceRouter.route(redis_svc, profile)
    assert "database_enum" in route_redis.applicable_modules

    mysql_svc = Service(host="10.0.0.1", port=3306, protocol="tcp", service="mysql")
    route_mysql = ServiceRouter.route(mysql_svc, profile)
    assert "database_enum" in route_mysql.applicable_modules


def test_service_router_dns_and_snmp():
    profile = get_profile("standard")
    dns_svc = Service(host="10.0.0.1", port=53, protocol="tcp", service="domain")
    assert "dns_enum" in ServiceRouter.route(dns_svc, profile).applicable_modules

    snmp_svc = Service(host="10.0.0.1", port=161, protocol="udp", service="snmp")
    assert "snmp_enum" in ServiceRouter.route(snmp_svc, profile).applicable_modules
