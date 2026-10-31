"""Perimeter Gateway & Remote Access Fingerprinting for external attack surface management."""
from __future__ import annotations
import asyncio
import re
from typing import Any, Mapping
from urllib.parse import urlparse
import httpx
from reconx.core.cache import get_cache
from reconx.utils.session import async_get_with_retry

GATEWAY_SIGNATURES = [
    {
        "vendor": "Palo Alto Networks",
        "product": "GlobalProtect Portal",
        "paths": ["/global-protect/login.esp", "/ssl-vpn/login.esp"],
        "title_re": re.compile(r"GlobalProtect\s+(?:Portal|Login)", re.I),
        "body_re": re.compile(r"/global-protect/|var\s+portal_config|GlobalProtect", re.I),
        "header_re": re.compile(r"PanWeb", re.I),
    },
    {
        "vendor": "Citrix Systems",
        "product": "Citrix NetScaler Gateway",
        "paths": ["/vpn/index.html", "/logon/LogonPoint/index.html"],
        "title_re": re.compile(r"Citrix\s+Gateway|NetScaler\s+Gateway", re.I),
        "body_re": re.compile(r"/vpn/images/|Citrix\s+Gateway|NSC_AAAC", re.I),
        "header_re": re.compile(r"NSC_AAAC|NSC_TEMP|Citrix", re.I),
    },
    {
        "vendor": "Fortinet",
        "product": "FortiGate SSL VPN",
        "paths": ["/remote/login", "/remote/logincheck"],
        "title_re": re.compile(r"FortiGate\s+-\s+SSL\s+VPN|FortiClient", re.I),
        "body_re": re.compile(r"/remote/login|fortigate|sslvpn_login", re.I),
        "header_re": re.compile(r"FortiGate", re.I),
    },
    {
        "vendor": "Cisco Systems",
        "product": "Cisco AnyConnect / ASA SSL VPN",
        "paths": ["/+CSCOE+/logon.html", "/+CSCOT+/translation-table"],
        "title_re": re.compile(r"Cisco\s+(?:AnyConnect|ASA|SSL\s+VPN)", re.I),
        "body_re": re.compile(r"/+CSCOE+/|webvpn|CSCO_WebVPN", re.I),
        "header_re": re.compile(r"Cisco\s+ASA|webvpn", re.I),
    },
    {
        "vendor": "Ivanti / Pulse Secure",
        "product": "Pulse Connect Secure",
        "paths": ["/dana-na/auth/url_default/welcome.cgi", "/dana-na/"],
        "title_re": re.compile(r"Pulse\s+Secure|Ivanti\s+Connect\s+Secure|Junos\s+Pulse", re.I),
        "body_re": re.compile(r"/dana-na/|DSID=|DSSIGNIN", re.I),
        "header_re": re.compile(r"DSID|DSSIGNIN", re.I),
    },
    {
        "vendor": "SonicWall",
        "product": "SonicWall SMA / NetExtender",
        "paths": ["/cgi-bin/welcome", "/auth.html"],
        "title_re": re.compile(r"SonicWALL\s+-\s+SSL-VPN|NetExtender", re.I),
        "body_re": re.compile(r"SonicWALL|NetExtender", re.I),
        "header_re": re.compile(r"SonicWALL", re.I),
    },
]

CANDIDATE_KEYWORDS = ("vpn", "remote", "portal", "access", "gateway", "connect", "ssl", "citrix", "pulse", "fw", "login")

async def fingerprint_gateways(
    probed_hosts: list[dict[str, Any]],
    client: httpx.AsyncClient,
    cfg: Mapping[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Inspect probed responses and probe candidate endpoints to fingerprint enterprise remote access portals."""
    detected: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    # Phase 1: Inspect already-probed responses
    for host_data in probed_hosts:
        host = host_data.get("host", "")
        title = host_data.get("title", "")
        server = host_data.get("server", "")
        url = host_data.get("url", "")

        for sig in GATEWAY_SIGNATURES:
            matched = False
            match_reason = ""
            if title and sig["title_re"].search(title):
                matched = True
                match_reason = f"Title matched '{title}'"
            elif server and sig["header_re"].search(server):
                matched = True
                match_reason = f"Server header matched '{server}'"

            if matched:
                key = f"{host}:{sig['product']}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    detected.append({
                        "host": host,
                        "url": url,
                        "vendor": sig["vendor"],
                        "product": sig["product"],
                        "status": host_data.get("status", 200),
                        "evidence": match_reason,
                        "source": "gateway_fingerprint",
                    })

    # Phase 2: Identify candidate hosts for targeted path probing
    candidate_hosts: list[str] = []
    for host_data in probed_hosts:
        h = host_data.get("host", "").lower()
        if any(kw in h for kw in CANDIDATE_KEYWORDS):
            candidate_hosts.append(h)

    # Dedup and limit to top 10 candidates to keep scan bounded and fast
    candidate_hosts = list(dict.fromkeys(candidate_hosts))[:10]

    sem = asyncio.Semaphore(4)

    async def probe_candidate(host: str, sig: dict[str, Any], path: str):
        key = f"{host}:{sig['product']}"
        if key in seen_keys:
            return
        url = f"https://{host}{path}"
        async with sem:
            try:
                r = await async_get_with_retry(client, url, retries=1)
                body = r.text[:200_000]
                matched = False
                reason = ""
                if r.status_code in (200, 301, 302, 401, 403):
                    if sig["title_re"].search(body) or sig["body_re"].search(body):
                        matched = True
                        reason = f"Path {path} returned HTTP {r.status_code} with matching signature"
                    elif any(sig["header_re"].search(v) for v in r.headers.values()):
                        matched = True
                        reason = f"Path {path} returned matching response header"

                if matched:
                    seen_keys.add(key)
                    detected.append({
                        "host": host,
                        "url": str(r.url),
                        "vendor": sig["vendor"],
                        "product": sig["product"],
                        "status": r.status_code,
                        "evidence": reason,
                        "source": "gateway_fingerprint",
                    })
            except Exception:
                pass

    tasks = []
    for host in candidate_hosts:
        for sig in GATEWAY_SIGNATURES:
            for path in sig["paths"]:
                tasks.append(probe_candidate(host, sig, path))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    return detected, {"status": "ok", "items_returned": str(len(detected))}
