"""Domain registration intelligence via RDAP (Registration Data Access Protocol) and WHOIS.

Queries modern, standardized ICANN RDAP endpoints over HTTPS with caching,
extracting registrar, lifecycle dates, status flags, and registrant organization.
"""
from __future__ import annotations
import re
from typing import Any
from reconx.core.cache import get_cache
from reconx.utils.session import create_async_client, async_get_with_retry

RDAP_BASE_URL = "https://rdap.org/domain"

def _parse_rdap_response(data: dict[str, Any], domain: str) -> dict[str, Any]:
    events: dict[str, str] = {}
    for ev in data.get("events", []):
        action = ev.get("eventAction", "")
        date = ev.get("eventDate", "")
        if action and date:
            events[action] = date

    registrar = ""
    registrant = {}
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [])
        fn = ""
        org = ""
        country = ""
        if len(vcard) > 1 and isinstance(vcard[1], list):
            for prop in vcard[1]:
                if isinstance(prop, list) and len(prop) > 3:
                    field_name = prop[0]
                    if field_name == "fn":
                        fn = prop[3]
                    elif field_name == "org":
                        org = prop[3] if isinstance(prop[3], str) else ""
                    elif field_name == "adr" and isinstance(prop[3], list):
                        # Country is often the last element in adr array
                        country = prop[3][-1] if prop[3] else ""

        if "registrar" in roles:
            registrar = fn or org or registrar
        if "registrant" in roles:
            registrant = {"name": fn, "organization": org, "country": country}

    nameservers = []
    for ns in data.get("nameservers", []):
        ns_name = ns.get("ldhName", "")
        if ns_name:
            nameservers.append(ns_name.lower())

    status_flags = data.get("status", [])

    return {
        "domain": domain.lower(),
        "registrar": registrar,
        "registrant": registrant,
        "created_date": events.get("registration", ""),
        "expiration_date": events.get("expiration", ""),
        "updated_date": events.get("last changed", events.get("last update of RDAP database", "")),
        "nameservers": nameservers,
        "status": status_flags,
        "dnssec": data.get("secureDNS", {}).get("delegationSigned", False),
        "source": "rdap",
    }

async def query_whois(domain: str, cfg: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Query domain registration intelligence via RDAP with caching."""
    clean_domain = domain.strip().lower().lstrip(".").rstrip(".")
    # Remove leading subdomains for whois lookup if appropriate, but keep domain as requested
    parts = clean_domain.split(".")
    if len(parts) > 2 and parts[-2] not in ("co", "com", "org", "net", "gov", "edu", "ac"):
        query_target = ".".join(parts[-2:])
    else:
        query_target = clean_domain

    cache = get_cache(enabled=cfg.get("cache_enabled", True))
    cached = cache.get("whois_intel", query_target)
    if cached is not None:
        return cached.get("data", {}), cached.get("status", {"status": "cached", "message": "Returned from cache"})

    url = f"{RDAP_BASE_URL}/{query_target}"

    try:
        async with create_async_client(cfg, timeout=min(float(cfg.get("request_timeout", 10.0)), 8.0)) as client:
            resp = await async_get_with_retry(client, url, retries=2, backoff_factor=1.5)
            if resp.status_code == 200:
                data = resp.json()
                parsed = _parse_rdap_response(data, query_target)
                status = {"status": "ok", "message": f"RDAP resolved registrar: {parsed.get('registrar', 'Unknown')}"}
                cache.set("whois_intel", query_target, {"data": parsed, "status": status}, ttl=cfg.get("cache_ttl", 86400))
                return parsed, status
            elif resp.status_code == 404:
                status = {"status": "clean", "message": "Domain RDAP record not found"}
                return {}, status
            else:
                return {}, {"status": "warning", "message": f"RDAP returned HTTP {resp.status_code}"}
    except Exception as exc:
        return {}, {"status": "error", "message": f"RDAP query failed: {type(exc).__name__}: {str(exc)}"}
