from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from horcrux.models import Service, Software


def parse_nmap(xml: str, target: str):
    services: list[Service] = []
    software: list[Software] = []

    if not xml.strip():
        return services, software

    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return services, software

    for port in root.findall(".//port"):
        state = port.find("state")
        svc = port.find("service")
        if state is None or state.attrib.get("state") != "open":
            continue

        svc = svc if svc is not None else ET.Element("service")

        item = Service(
            host=target,
            port=int(port.attrib["portid"]),
            protocol=port.attrib.get("protocol", "tcp"),
            service=svc.attrib.get("name", ""),
            product=svc.attrib.get("product", ""),
            version=svc.attrib.get("version", ""),
            extrainfo=svc.attrib.get("extrainfo", ""),
        )
        services.append(item)

        product = item.product or item.service
        if product or item.version:
            software.append(
                Software(
                    product=product,
                    version=item.version,
                    service=f"{item.port}/{item.protocol}",
                    source="nmap",
                    confidence=.97,
                )
            )

    return services, software


def detect_technologies(headers: str, body: str):
    text = f"{headers}\n{body}".lower()
    signatures = {
        "nginx": [r"\bnginx\b"],
        "apache": [r"\bapache\b"],
        "iis": [r"microsoft-iis"],
        "gunicorn": [r"\bgunicorn\b"],
        "flask": [r"\bflask\b", r"werkzeug"],
        "django": [r"\bdjango\b"],
        "express": [r"\bexpress\b"],
        "php": [r"\bphp\b"],
        "tomcat": [r"\btomcat\b"],
        "spring": [r"\bspring\b"],
        "rails": [r"ruby on rails"],
        "wordpress": [r"wp-content", r"wordpress"],
        "drupal": [r"\bdrupal\b"],
        "graphql": [r"\bgraphql\b"],
    }
    return [
        name
        for name, patterns in signatures.items()
        if any(re.search(pattern, text) for pattern in patterns)
    ]
