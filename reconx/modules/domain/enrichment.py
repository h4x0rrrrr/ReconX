"""Bounded active enrichment: extracts JS endpoints, secret indicators, public metadata, and favicons."""
from __future__ import annotations
import asyncio
import base64
import re
from urllib.parse import urljoin, urlparse
from typing import Any
import httpx
from reconx.core.plugins import deduplicate, RateGate
from reconx.utils.session import create_async_client, async_get_with_retry

SECRET_PATTERNS = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key_marker", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_api_key_assignment", re.compile(r"(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*['\"][^'\"]{12,}['\"]")),
]

ENDPOINT_PATTERN = re.compile(
    r"""["'`]((?:https?://[^"'\s<>]+|/(?:api|v[0-9]+|rest|graphql|wp-json|wp-admin|ajax|oauth|auth|login|admin|user|users|account|service|webhook|cart|checkout|upload|feed|data|config)[/a-zA-Z0-9_\-?=&%.#]*))["'`]""",
    re.I,
)

ENDPOINT_KEYWORDS = (
    "api/", "graphql", "auth", "oauth", "v1/", "v2/", "v3/",
    "rest/", "swagger", "openapi", "login", "admin", "dashboard",
    "users", "account", "webhook", "config", "token", "session",
    "endpoint", "query", "mutation", "callback", "service", "wp-json", "admin-ajax",
)

def _extract_endpoints_from_text(text: str, base_url: str) -> list[dict[str, str]]:
    found = []
    seen = set()
    for m in ENDPOINT_PATTERN.finditer(text):
        val = m.group(1).strip()
        if not val or val in ("/", "//", "#"):
            continue
        if val.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot")):
            continue
        full_url = urljoin(base_url, val) if val.startswith("/") else val
        if full_url.lower() not in seen:
            seen.add(full_url.lower())
            found.append({"url": full_url, "js_source": base_url, "source": "js_endpoint_extraction"})

    # Secondary scan for string literals with API keywords
    for m in re.finditer(r"""["'`]((?:https?://|/)[a-zA-Z0-9_\-?=&%.#/:]{3,250})["'`]""", text):
        val = m.group(1).strip()
        if val.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot")):
            continue
        if any(kw in val.lower() for kw in ENDPOINT_KEYWORDS):
            full_url = urljoin(base_url, val) if val.startswith("/") else val
            if full_url.lower() not in seen:
                seen.add(full_url.lower())
                found.append({"url": full_url, "js_source": base_url, "source": "js_endpoint_extraction"})
    return found

async def enrich_hosts(probes: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
    endpoints = []
    indicators = []
    metadata = []
    favicons = []
    cloud = []
    sem = asyncio.Semaphore(max(1, min(6, cfg.get("concurrency", 6))))
    gates = {}

    async def paced_get(client, url, host):
        await gates.setdefault(host.casefold(), RateGate(cfg.get("rate_seconds", 0.25))).wait()
        return await client.get(url)

    async with create_async_client(cfg, timeout=cfg.get("request_timeout", 12.0)) as client:
        async def enrich(row):
            root = row.get("url")
            if not root:
                return
            host = row.get("host", root)
            async with sem:
                try:
                    r = await paced_get(client, root, host)
                    html = r.text[:800_000]
                except Exception:
                    return

                # Check public metadata paths
                for path in ("/robots.txt", "/.well-known/security.txt", "/security.txt", "/.well-known/openid-configuration", "/saml/metadata", "/FederationMetadata/2007-06/FederationMetadata.xml"):
                    try:
                        mr = await paced_get(client, urljoin(root, path), host)
                        if mr.status_code == 200 and len(mr.text) < 500_000 and not re.search(r"<title>.*404|not found", mr.text[:3000], re.I):
                            metadata.append({"url": str(mr.url), "status": mr.status_code, "content_type": mr.headers.get("content-type", ""), "source": "public_metadata_check"})
                    except Exception:
                        pass

                # 1. Extract endpoints from inline script tags in HTML
                inline_scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE)
                for script_body in inline_scripts:
                    if len(script_body) > 10:
                        inline_eps = _extract_endpoints_from_text(script_body, root)
                        endpoints.extend(inline_eps)

                # 2. Extract external script tags and fetch them
                js_urls = set()
                for m in re.finditer(r"(?i)\bsrc\s*=\s*[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']", html):
                    js_urls.add(urljoin(root, m.group(1)))

                for jsurl in list(js_urls)[:15]:
                    try:
                        jr = await paced_get(client, jsurl, host)
                        if jr.status_code != 200:
                            continue
                        body = jr.text[:1_200_000]
                        eps = _extract_endpoints_from_text(body, jsurl)
                        endpoints.extend(eps)

                        for label, pattern in SECRET_PATTERNS:
                            if pattern.search(body):
                                indicators.append({"type": label, "js_source": jsurl, "match_preview": "[REDACTED: potential secret pattern detected]", "source": "js_pattern_scan"})

                        for match in re.findall(r"https?://[^\s\"'<>]*(?:s3[.-][a-z0-9-]+\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com)[^\s\"'<>]*", body, re.I):
                            cloud.append({"url": match, "source": "js_cloud_reference"})
                    except Exception:
                        continue

                # 3. Favicon mmh3 hash
                try:
                    fr = await paced_get(client, urljoin(root, "/favicon.ico"), host)
                    if fr.status_code == 200 and fr.content:
                        try:
                            import mmh3
                            favicons.append({"host": host, "mmh3": mmh3.hash(base64.b64encode(fr.content).decode()), "source": "favicon_hash"})
                        except ImportError:
                            pass
                except Exception:
                    pass

        await asyncio.gather(*(enrich(x) for x in probes[:30]))

    return {
        "js_endpoints": deduplicate(endpoints, key_fields=("url",)),
        "js_secret_indicators": deduplicate(indicators, key_fields=("js_source", "type")),
        "public_metadata": deduplicate(metadata, key_fields=("url",)),
        "favicon_hashes": deduplicate(favicons, key_fields=("host", "mmh3")),
        "cloud_references": deduplicate(cloud, key_fields=("url",)),
    }
