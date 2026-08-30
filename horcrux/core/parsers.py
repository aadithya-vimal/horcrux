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

        raw_service = svc.attrib.get("name", "").strip().lower()
        product = svc.attrib.get("product", "").strip()
        version = svc.attrib.get("version", "").strip()
        cpe_el = svc.find(".//cpe")
        cpe = cpe_el.text.strip() if cpe_el is not None and cpe_el.text else ""

        # Normalize weak/ambiguous service mappings
        port_num = int(port.attrib["portid"])
        if raw_service in {"ppp", "unknown", "tcpwrapped"} and port_num in {80, 443, 8000, 8080, 8443, 8888, 3000, 5000}:
            # Underlying port is standard HTTP/HTTPS; don't report ppp
            service_name = "http" if port_num != 443 else "https"
        else:
            service_name = raw_service

        item = Service(
            host=target,
            port=port_num,
            protocol=port.attrib.get("protocol", "tcp"),
            service=service_name,
            product=product,
            version=version,
            extrainfo=svc.attrib.get("extrainfo", ""),
            cpe=cpe,
        )
        services.append(item)

        # Software normalization: Only establish software records when meaningful product or version exists
        # Never establish generic 'ppp' software entries without evidence
        if product and product.lower() not in {"tcpwrapped", "unknown", "ppp"}:
            confidence = 0.95 if version else 0.70
            software.append(
                Software(
                    product=product,
                    version=version,
                    service=f"{item.port}/{item.protocol}",
                    source="nmap",
                    cpe=cpe,
                    confidence=confidence,
                    evidence=[f"Nmap version scan on port {item.port} ({item.protocol}) identified {product} {version}".strip()],
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
