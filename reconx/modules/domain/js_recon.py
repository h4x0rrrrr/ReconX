"""
Fetches JS files referenced by live hosts and scans them for
embedded endpoints and likely secrets/API keys using regex patterns.
This catches dead-code endpoints and hardcoded keys that never show
up in any public documentation.
"""

import re

from reconx.utils import logger
from reconx.utils.session import get_session, safe_get

JS_SRC_RE = re.compile(r'src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
ENDPOINT_RE = re.compile(r'["\'](/[a-zA-Z0-9_\-/{}.]{3,80})["\']')

SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Generic API Key": re.compile(r"(?i)api[_-]?key[\"'\s:=]+[A-Za-z0-9\-_]{16,}"),
    "Bearer Token": re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.]{20,}"),
    "Slack Token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Private Key Block": re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
}


def find_js_urls(live_hosts: list, session=None) -> set:
    session = session or get_session()
    js_urls = set()
    for h in live_hosts:
        url = h.get("url")
        if not url:
            continue
        resp = safe_get(session, url)
        if resp is None or resp.status_code != 200:
            continue
        for match in JS_SRC_RE.findall(resp.text):
            if match.startswith("http"):
                js_urls.add(match)
            elif match.startswith("/"):
                js_urls.add(url.rstrip("/") + match)
    return js_urls


def scan_js_files(js_urls: set, session=None) -> dict:
    logger.info(f"Fetching + scanning {len(js_urls)} JS file(s) for endpoints/secrets...")
    session = session or get_session()
    endpoints = set()
    secrets_found = []

    for js_url in js_urls:
        resp = safe_get(session, js_url)
        if resp is None or resp.status_code != 200:
            continue
        body = resp.text

        for ep in ENDPOINT_RE.findall(body):
            endpoints.add(ep)

        for label, pattern in SECRET_PATTERNS.items():
            for match in pattern.findall(body):
                secrets_found.append({
                    "type": label,
                    "match_preview": (match[:60] + "...") if len(match) > 60 else match,
                    "source": js_url,
                })

    if secrets_found:
        logger.warn(f"{len(secrets_found)} potential secret(s) found in JS — verify manually!")
    logger.ok(f"{len(endpoints)} unique endpoint(s) extracted from JS")
    return {"endpoints": sorted(endpoints), "secrets": secrets_found}
