"""Web and Network Technology Fingerprinting Engine (Headers, Cookies, Meta tags, Frameworks, and Open Ports)."""
from __future__ import annotations
import asyncio
import re
from typing import Any, Mapping
import httpx

# Precompiled signature rules
SIGNATURES = [
    # ── Web Servers & Reverse Proxies ──
    {
        "name": "Nginx",
        "category": "Web Server",
        "header_rules": [("server", re.compile(r"\bnginx(?:/([0-9.]+))?", re.I))],
    },
    {
        "name": "Apache HTTP Server",
        "category": "Web Server",
        "header_rules": [("server", re.compile(r"\bapache(?!-coyote)(?:/([0-9.]+))?", re.I))],
    },
    {
        "name": "Microsoft IIS",
        "category": "Web Server",
        "header_rules": [("server", re.compile(r"\bMicrosoft-IIS(?:/([0-9.]+))?", re.I))],
    },
    {
        "name": "LiteSpeed",
        "category": "Web Server",
        "header_rules": [("server", re.compile(r"\bLiteSpeed\b", re.I))],
    },
    {
        "name": "OpenResty",
        "category": "Web Server",
        "header_rules": [("server", re.compile(r"\bopenresty(?:/([0-9.]+))?", re.I))],
    },
    {
        "name": "Caddy",
        "category": "Web Server",
        "header_rules": [("server", re.compile(r"\bCaddy\b", re.I))],
    },
    {
        "name": "Envoy",
        "category": "Web Server",
        "header_rules": [("server", re.compile(r"\benvoy\b", re.I))],
    },
    {
        "name": "Traefik",
        "category": "Web Server",
        "header_rules": [("server", re.compile(r"\btraefik\b", re.I))],
    },
    {
        "name": "Apache Tomcat",
        "category": "Application Server",
        "header_rules": [
            ("server", re.compile(r"\bApache-Coyote(?:/([0-9.]+))?", re.I)),
            ("x-powered-by", re.compile(r"\bTomcat(?:/([0-9.]+))?", re.I)),
        ],
    },
    {
        "name": "Gunicorn",
        "category": "WSGI Server",
        "header_rules": [("server", re.compile(r"\bgunicorn(?:/([0-9.]+))?", re.I))],
    },
    {
        "name": "Uvicorn",
        "category": "ASGI Server",
        "header_rules": [("server", re.compile(r"\buvicorn\b", re.I))],
    },

    # ── CDN, WAF & Cloud Infrastructure ──
    {
        "name": "Cloudflare",
        "category": "CDN / WAF",
        "header_rules": [
            ("server", re.compile(r"\bcloudflare\b", re.I)),
            ("cf-ray", re.compile(r".+")),
            ("cf-cache-status", re.compile(r".+")),
        ],
    },
    {
        "name": "AWS CloudFront",
        "category": "CDN",
        "header_rules": [
            ("server", re.compile(r"\bCloudFront\b", re.I)),
            ("x-amz-cf-id", re.compile(r".+")),
        ],
    },
    {
        "name": "Akamai",
        "category": "CDN",
        "header_rules": [
            ("server", re.compile(r"\bAkamaiGHost\b", re.I)),
            ("x-akamai-transformed", re.compile(r".+")),
        ],
    },
    {
        "name": "Fastly",
        "category": "CDN",
        "header_rules": [
            ("x-fastly-request-id", re.compile(r".+")),
            ("fastly-restarts", re.compile(r".+")),
        ],
    },
    {
        "name": "Varnish",
        "category": "Cache Proxy",
        "header_rules": [
            ("x-varnish", re.compile(r".+")),
            ("via", re.compile(r"\bvarnish\b", re.I)),
        ],
    },

    # ── Runtimes & Server Frameworks ──
    {
        "name": "PHP",
        "category": "Programming Language",
        "header_rules": [
            ("x-powered-by", re.compile(r"\bPHP(?:/([0-9.]+))?", re.I)),
            ("set-cookie", re.compile(r"\bPHPSESSID\b")),
        ],
    },
    {
        "name": "ASP.NET",
        "category": "Framework",
        "header_rules": [
            ("x-powered-by", re.compile(r"\bASP\.NET\b", re.I)),
            ("x-aspnet-version", re.compile(r"([0-9.]+)")),
            ("set-cookie", re.compile(r"\bASP\.NET_SessionId\b")),
        ],
    },
    {
        "name": "ASP.NET Core",
        "category": "Framework",
        "header_rules": [
            ("x-powered-by", re.compile(r"\bASP\.NET Core\b", re.I)),
        ],
    },
    {
        "name": "Node.js",
        "category": "Runtime",
        "header_rules": [
            ("x-powered-by", re.compile(r"\bNode\.js\b", re.I)),
        ],
    },
    {
        "name": "Express",
        "category": "Web Framework",
        "header_rules": [
            ("x-powered-by", re.compile(r"\bExpress\b", re.I)),
            ("set-cookie", re.compile(r"\bconnect\.sid\b")),
        ],
    },
    {
        "name": "Next.js",
        "category": "Web Framework",
        "header_rules": [("x-powered-by", re.compile(r"\bNext\.js\b", re.I))],
        "body_rules": [re.compile(r"__NEXT_DATA__"), re.compile(r"/_next/static/")],
    },
    {
        "name": "Nuxt.js",
        "category": "Web Framework",
        "header_rules": [("x-powered-by", re.compile(r"\bNuxt\b", re.I))],
        "body_rules": [re.compile(r"__NUXT__"), re.compile(r"/_nuxt/")],
    },
    {
        "name": "Laravel",
        "category": "PHP Framework",
        "header_rules": [
            ("x-powered-by", re.compile(r"\bLaravel\b", re.I)),
            ("set-cookie", re.compile(r"\blaravel_session\b")),
        ],
    },
    {
        "name": "Django",
        "category": "Python Framework",
        "header_rules": [
            ("set-cookie", re.compile(r"\bcsrftoken\b")),
            ("set-cookie", re.compile(r"\bdjango_session\b")),
        ],
    },
    {
        "name": "Ruby on Rails",
        "category": "Ruby Framework",
        "header_rules": [
            ("x-powered-by", re.compile(r"\bRuby on Rails\b", re.I)),
            ("set-cookie", re.compile(r"\b_rails_session\b")),
        ],
    },
    {
        "name": "Spring Boot",
        "category": "Java Framework",
        "header_rules": [("set-cookie", re.compile(r"\bJSESSIONID\b"))],
        "body_rules": [
            re.compile(r"Whitelabel Error Page", re.I),
            re.compile(r"There was an unexpected error \(type=Not Found", re.I),
        ],
    },

    # ── Frontend Libraries & UI ──
    {
        "name": "React",
        "category": "UI Library",
        "body_rules": [
            re.compile(r"data-reactroot"),
            re.compile(r"react\.production\.min\.js"),
            re.compile(r"/react@[0-9.]+/"),
        ],
    },
    {
        "name": "Vue.js",
        "category": "UI Framework",
        "body_rules": [
            re.compile(r"data-v-[a-f0-9]+"),
            re.compile(r"vue(?:\.runtime)?\.min\.js"),
        ],
    },
    {
        "name": "Angular",
        "category": "UI Framework",
        "body_rules": [
            re.compile(r"ng-version=[\"']([0-9.]+)[\"']"),
            re.compile(r"\bng-app\b"),
        ],
    },
    {
        "name": "jQuery",
        "category": "JavaScript Library",
        "body_rules": [
            re.compile(r"jquery(?:-([0-9.]+))?\.min\.js", re.I),
            re.compile(r"jQuery v([0-9.]+)", re.I),
        ],
    },
    {
        "name": "Bootstrap",
        "category": "UI Framework",
        "body_rules": [
            re.compile(r"bootstrap(?:\.bundle)?(?:-([0-9.]+))?\.min\.(?:css|js)", re.I),
        ],
    },
    {
        "name": "Tailwind CSS",
        "category": "UI Framework",
        "body_rules": [
            re.compile(r"/tailwind(?:-([0-9.]+))?\.min\.css", re.I),
            re.compile(r"tailwindcss", re.I),
        ],
    },

    # ── CMS & E-Commerce ──
    {
        "name": "WordPress",
        "category": "CMS",
        "header_rules": [
            ("x-powered-by", re.compile(r"\bWordPress\b", re.I)),
            ("set-cookie", re.compile(r"\bwordpress_\b")),
        ],
        "body_rules": [
            re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']WordPress(?: ([0-9.]+))?[\"']", re.I),
            re.compile(r"/wp-content/"),
            re.compile(r"/wp-includes/"),
        ],
    },
    {
        "name": "Drupal",
        "category": "CMS",
        "header_rules": [
            ("x-generator", re.compile(r"\bDrupal(?: ([0-9.]+))?", re.I)),
            ("x-drupal-cache", re.compile(r".+")),
        ],
        "body_rules": [
            re.compile(r"Drupal\.settings"),
            re.compile(r"/sites/default/files/"),
        ],
    },
    {
        "name": "Joomla",
        "category": "CMS",
        "body_rules": [
            re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Joomla!(?: ([0-9.]+))?[\"']", re.I),
            re.compile(r"/media/system/js/core\.js"),
        ],
    },
    {
        "name": "Shopify",
        "category": "E-Commerce",
        "header_rules": [
            ("x-shopid", re.compile(r".+")),
            ("x-shopify-stage", re.compile(r".+")),
        ],
        "body_rules": [re.compile(r"cdn\.shopify\.com"), re.compile(r"Shopify\.theme")],
    },
    {
        "name": "Magento",
        "category": "E-Commerce",
        "header_rules": [("set-cookie", re.compile(r"\bfrontend\b"))],
        "body_rules": [re.compile(r"/skin/frontend/"), re.compile(r"/static/version[0-9]+/frontend/")],
    },
    {
        "name": "Elementor",
        "category": "Page Builder",
        "body_rules": [
            re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Elementor(?: ([0-9.]+))?[\"']", re.I),
            re.compile(r"/wp-content/plugins/elementor/"),
        ],
    },

    # ── Admin & DevOps (8080, 8443, 9000, 3000, etc.) ──
    {
        "name": "Jenkins",
        "category": "CI/CD",
        "header_rules": [
            ("x-jenkins", re.compile(r"([0-9.]+)?")),
            ("x-hudson", re.compile(r".+")),
        ],
        "title_rules": [re.compile(r"Dashboard \[Jenkins\]", re.I)],
    },
    {
        "name": "Grafana",
        "category": "Observability",
        "header_rules": [("set-cookie", re.compile(r"\bgrafana_session\b"))],
        "title_rules": [re.compile(r"\bGrafana\b", re.I)],
    },
    {
        "name": "Kibana",
        "category": "Observability",
        "header_rules": [("kbn-name", re.compile(r".+"))],
        "title_rules": [re.compile(r"\bKibana\b", re.I)],
    },
    {
        "name": "phpMyAdmin",
        "category": "Database Administration",
        "header_rules": [("set-cookie", re.compile(r"\bpma_session\b"))],
        "title_rules": [re.compile(r"\bphpMyAdmin\b", re.I)],
    },
    {
        "name": "Portainer",
        "category": "Container Management",
        "title_rules": [re.compile(r"\bPortainer\b", re.I)],
    },
    {
        "name": "cPanel / WHM",
        "category": "Hosting Control Panel",
        "header_rules": [("server", re.compile(r"\bcpsrvd(?:/([0-9.]+))?", re.I))],
        "title_rules": [re.compile(r"\bcPanel\b|\bWebHost Manager\b", re.I)],
    },
    {
        "name": "Webmin",
        "category": "System Administration",
        "header_rules": [("server", re.compile(r"\bMiniServ(?:/([0-9.]+))?", re.I))],
        "title_rules": [re.compile(r"\bWebmin\b", re.I)],
    },
]

KNOWN_PORT_SERVICES = {
    445: ("SMB (Server Message Block)", "Microsoft Windows SMB / Samba file sharing"),
    139: ("NetBIOS Session Service", "Windows NetBIOS file & print sharing"),
    135: ("Microsoft MSRPC", "RPC Endpoint Mapper"),
    3389: ("Microsoft RDP", "Remote Desktop Protocol"),
    22: ("SSH", "Secure Shell remote access"),
    21: ("FTP", "File Transfer Protocol"),
    25: ("SMTP", "Simple Mail Transfer Protocol"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Hypertext Transfer Protocol"),
    443: ("HTTPS", "HTTP over TLS/SSL"),
    8080: ("HTTP-Alt", "Web proxy / alternate HTTP server"),
    8443: ("HTTPS-Alt", "Web management / alternate HTTPS server"),
    8000: ("HTTP-Dev", "Web development / REST API service"),
    8888: ("HTTP-Admin", "Web management portal / API server"),
    3000: ("Node/React Dev", "Node.js / React / Grafana web service"),
    5000: ("Flask/API", "Python Flask / Docker Registry / API"),
    9000: ("Web Admin / SonarQube", "FastCGI / Portainer / SonarQube service"),
    3306: ("MySQL", "MySQL / MariaDB database service"),
    5432: ("PostgreSQL", "PostgreSQL database service"),
    6379: ("Redis", "Redis in-memory key-value store"),
    27017: ("MongoDB", "MongoDB document database"),
    9200: ("Elasticsearch", "Elasticsearch search cluster REST API"),
}

def detect_technologies(
    headers: Mapping[str, str] | None = None,
    html: str = "",
    title: str = "",
    port: int | None = None,
    service_hint: str = "",
    product_hint: str = "",
) -> list[str]:
    """Analyze HTTP response headers, cookies, HTML DOM markers, and network service banners to detect technologies."""
    detected = []
    headers = {k.lower(): v for k, v in (headers or {}).items()}

    # 1. Match signature rules
    for sig in SIGNATURES:
        name = sig["name"]
        matched = False
        version = None

        # Check header rules
        for hdr_name, pattern in sig.get("header_rules", []):
            hdr_val = headers.get(hdr_name.lower(), "")
            if hdr_val:
                m = pattern.search(hdr_val)
                if m:
                    matched = True
                    if m.groups() and m.group(1):
                        version = m.group(1)
                    break

        # Check title rules
        if not matched and title:
            for pattern in sig.get("title_rules", []):
                m = pattern.search(title)
                if m:
                    matched = True
                    if m.groups() and m.group(1):
                        version = m.group(1)
                    break

        # Check body rules
        if not matched and html:
            for pattern in sig.get("body_rules", []):
                m = pattern.search(html)
                if m:
                    matched = True
                    if m.groups() and m.group(1):
                        version = m.group(1)
                    break

        if matched:
            label = f"{name} {version}" if version else name
            detected.append(label)

    # 2. Port-specific technology identification
    if port and port in KNOWN_PORT_SERVICES:
        svc_name, svc_desc = KNOWN_PORT_SERVICES[port]

        # Port 445: SMB
        if port == 445 or "smb" in service_hint.lower() or "microsoft-ds" in service_hint.lower():
            if product_hint:
                detected.append(f"Microsoft SMB ({product_hint})")
            else:
                detected.append("SMB (Server Message Block)")

        # Port 8080 / 8443
        elif port in (8080, 8443):
            if not any("Tomcat" in d or "Jenkins" in d for d in detected):
                detected.append(f"{svc_name} (Port {port})")

        # Other non-standard ports
        elif port not in (80, 443):
            if product_hint:
                detected.append(f"{svc_name} ({product_hint})")
            elif not detected:
                detected.append(f"{svc_name} (Port {port})")

    # 3. Product hint enrichment (from Shodan / Censys)
    if product_hint and not any(product_hint.lower() in d.lower() for d in detected):
        detected.append(product_hint)

    return list(dict.fromkeys(detected))

async def probe_web_port(
    ip: str,
    port: int,
    client: httpx.AsyncClient,
    timeout: float = 3.5,
) -> dict[str, Any]:
    """Attempt a rapid HTTP/HTTPS probe on an open web port to fingerprint technologies."""
    schemes = ("https://", "http://") if port in (443, 8443, 9443) else ("http://", "https://")
    for scheme in schemes:
        url = f"{scheme}{ip}:{port}"
        try:
            r = await client.get(url, timeout=timeout, follow_redirects=True)
            body = r.text[:80_000]
            title_m = re.search(r"<title[^>]*>(.*?)</title", body, re.I | re.S)
            title = re.sub(r"\s+", " ", title_m.group(1)).strip()[:100] if title_m else ""
            techs = detect_technologies(
                headers=dict(r.headers),
                html=body,
                title=title,
                port=port,
            )
            return {
                "url": str(r.url),
                "status": r.status_code,
                "title": title,
                "server": r.headers.get("server", ""),
                "technologies": techs,
            }
        except Exception:
            continue
    return {}

async def enrich_network_services(
    services: list[dict[str, Any]],
    client: httpx.AsyncClient | None = None,
    cfg: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Enrich discovered open ports and network services with detailed technology fingerprinting."""
    if not services:
        return []

    # Common web ports that can be active-probed if a client is available
    web_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000}

    async def _enrich_one(item: dict[str, Any]):
        ip = item.get("ip", "")
        port = item.get("port")
        service = item.get("service", "")
        product = item.get("product", "")

        # Initial technology identification from metadata
        techs = detect_technologies(
            port=port,
            service_hint=service,
            product_hint=product,
        )

        # If it is an open web port and client is available, probe live for richer fingerprinting
        if client and port in web_ports and ip:
            probe_res = await probe_web_port(ip, port, client)
            if probe_res.get("technologies"):
                for t in probe_res["technologies"]:
                    if t not in techs:
                        techs.append(t)
            if probe_res.get("title") and not item.get("title"):
                item["title"] = probe_res["title"]
            if probe_res.get("server") and not item.get("server"):
                item["server"] = probe_res["server"]

        item["technologies"] = list(dict.fromkeys(techs))
        item["tech_summary"] = ", ".join(item["technologies"])
        return item

    tasks = [_enrich_one(dict(s)) for s in services]
    return await asyncio.gather(*tasks)
