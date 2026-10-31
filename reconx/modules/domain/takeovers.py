"""Dangling DNS & Subdomain Takeover Risk Auditor."""
from __future__ import annotations
import asyncio
import re
from typing import Any, Mapping
import httpx
from reconx.utils.session import async_get_with_retry

TAKEOVER_SIGNATURES = [
    {
        "provider": "GitHub Pages",
        "cname_re": re.compile(r"\.github\.io\.?$", re.I),
        "fingerprint": re.compile(r"There isn't a GitHub Pages site here|For root URLs \(like http://example\.com/\) you must provide an index\.html file", re.I),
    },
    {
        "provider": "AWS S3 Bucket",
        "cname_re": re.compile(r"\.s3(?:-website)?(?:[.-][a-z0-9-]+)?\.amazonaws\.com\.?$", re.I),
        "fingerprint": re.compile(r"<Code>NoSuchBucket</Code>|The specified bucket does not exist", re.I),
    },
    {
        "provider": "Heroku",
        "cname_re": re.compile(r"\.herokuapp\.com\.?|\.herokudns\.com\.?$", re.I),
        "fingerprint": re.compile(r"No such app|herokucdn\.com/error-pages/no-such-app\.html", re.I),
    },
    {
        "provider": "Microsoft Azure",
        "cname_re": re.compile(r"\.(?:azurewebsites\.net|cloudapp\.net|trafficmanager\.net)\.?$", re.I),
        "fingerprint": re.compile(r"404 Web Site not found|Microsoft Azure App Service - Error 404", re.I),
    },
    {
        "provider": "Zendesk",
        "cname_re": re.compile(r"\.zendesk\.com\.?$", re.I),
        "fingerprint": re.compile(r"Help Center Closed|this help center no longer exists", re.I),
    },
    {
        "provider": "Shopify",
        "cname_re": re.compile(r"\.myshopify\.com\.?$", re.I),
        "fingerprint": re.compile(r"Sorry, this shop is currently unavailable|Only one step left to start selling", re.I),
    },
    {
        "provider": "Fastly",
        "cname_re": re.compile(r"\.fastly\.net\.?$", re.I),
        "fingerprint": re.compile(r"Fastly error: unknown domain", re.I),
    },
    {
        "provider": "Pantheon",
        "cname_re": re.compile(r"\.pantheonsite\.io\.?$", re.I),
        "fingerprint": re.compile(r"The gods are wise, but do not know of the site which you seek|404 error unknown site", re.I),
    },
    {
        "provider": "WordPress.com",
        "cname_re": re.compile(r"\.wordpress\.com\.?$", re.I),
        "fingerprint": re.compile(r"Do you want to register|doesn't exist", re.I),
    },
    {
        "provider": "Ghost",
        "cname_re": re.compile(r"\.ghost\.io\.?$", re.I),
        "fingerprint": re.compile(r"The thing you were looking for is no longer here|404 Not Found", re.I),
    },
    {
        "provider": "Surge.sh",
        "cname_re": re.compile(r"\.surge\.sh\.?$", re.I),
        "fingerprint": re.compile(r"project not found", re.I),
    },
]

async def audit_subdomain_takeovers(
    subdomains: list[str],
    client: httpx.AsyncClient,
    cfg: Mapping[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Audit subdomains for dangling CNAME pointers and unclaimed cloud service signatures."""
    try:
        import dns.resolver
    except ImportError:
        return [], {"status": "unavailable", "message": "dnspython required for CNAME resolution"}

    clean_subs = list(dict.fromkeys(s.strip().lower().rstrip(".") for s in subdomains if s.strip()))[:150]
    cname_map: dict[str, str] = {}

    def resolve_cnames():
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        for sub in clean_subs:
            try:
                ans = resolver.resolve(sub, "CNAME")
                for rdata in ans:
                    target = str(rdata.target).strip().lower().rstrip(".")
                    if target:
                        cname_map[sub] = target
            except Exception:
                pass

    await asyncio.to_thread(resolve_cnames)

    candidates: list[tuple[str, str, dict[str, Any]]] = []
    for sub, cname in cname_map.items():
        for sig in TAKEOVER_SIGNATURES:
            if sig["cname_re"].search(cname):
                candidates.append((sub, cname, sig))
                break

    findings: list[dict[str, Any]] = []
    sem = asyncio.Semaphore(4)

    async def verify_candidate(sub: str, cname: str, sig: dict[str, Any]):
        async with sem:
            for scheme in ("https://", "http://"):
                url = f"{scheme}{sub}"
                try:
                    r = await async_get_with_retry(client, url, retries=1)
                    body = r.text[:200_000]
                    if sig["fingerprint"].search(body):
                        findings.append({
                            "subdomain": sub,
                            "cname": cname,
                            "provider": sig["provider"],
                            "status": r.status_code,
                            "url": url,
                            "evidence": f"CNAME {cname} matched {sig['provider']} with verified unclaimed signature",
                            "confidence": "High",
                            "source": "subdomain_takeover_audit",
                        })
                        break
                except Exception:
                    continue

    if candidates:
        await asyncio.gather(*(verify_candidate(s, c, sig) for s, c, sig in candidates))

    return findings, {"status": "ok", "items_returned": str(len(findings))}
