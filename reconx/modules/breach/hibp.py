"""HaveIBeenPwned breach intelligence integration.

Queries HIBP v3 API with rate-pacing, caching, and source attribution.
Secrets and unredacted credentials are never returned or recorded.
"""
from __future__ import annotations
import asyncio
from typing import Any
import urllib.parse
from reconx.core.cache import get_cache
from reconx.utils.session import create_async_client, async_get_with_retry

HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"

async def check_breaches(account: str, cfg: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Check HaveIBeenPwned for breached accounts.
    
    Returns (findings_list, source_status_dict).
    """
    account = account.strip()
    if not account:
        return [], {"status": "skipped", "message": "Empty account query"}

    api_key = cfg.get("hibp_api_key", "").strip()
    if not api_key:
        return [], {
            "status": "unconfigured",
            "message": "HIBP_API_KEY environment variable is not set. Set HIBP_API_KEY for breach intelligence.",
        }

    cache = get_cache(enabled=cfg.get("cache_enabled", True))
    cached = cache.get("hibp_breaches", account)
    if cached is not None:
        return cached.get("items", []), cached.get("status", {"status": "cached", "message": "Returned from local cache"})

    headers = {
        "hibp-api-key": api_key,
        "User-Agent": cfg.get("user_agent", "ReconX-OSINT/0.3 (+authorized research)"),
    }

    url = f"{HIBP_BASE_URL}/breachedaccount/{urllib.parse.quote(account)}?truncateResponse=false"

    try:
        async with create_async_client(cfg, headers=headers) as client:
            resp = await async_get_with_retry(client, url, retries=2, backoff_factor=2.0)
            if resp.status_code == 200:
                data = resp.json()
                breaches = []
                for entry in data:
                    breaches.append({
                        "name": entry.get("Name", ""),
                        "title": entry.get("Title", entry.get("Name", "")),
                        "domain": entry.get("Domain", ""),
                        "breach_date": entry.get("BreachDate", ""),
                        "pwn_count": entry.get("PwnCount", 0),
                        "data_classes": entry.get("DataClasses", []),
                        "is_verified": entry.get("IsVerified", False),
                        "is_fabricated": entry.get("IsFabricated", False),
                        "is_sensitive": entry.get("IsSensitive", False),
                        "source": "HaveIBeenPwned",
                    })
                status = {"status": "ok", "message": f"Found {len(breaches)} breach records"}
                cache.set("hibp_breaches", account, {"items": breaches, "status": status}, ttl=cfg.get("cache_ttl", 86400))
                return breaches, status
            elif resp.status_code == 404:
                status = {"status": "clean", "message": "No breaches found on HaveIBeenPwned"}
                cache.set("hibp_breaches", account, {"items": [], "status": status}, ttl=cfg.get("cache_ttl", 86400))
                return [], status
            elif resp.status_code in (401, 403):
                return [], {"status": "error", "message": f"HIBP authentication failed (HTTP {resp.status_code}). Check HIBP_API_KEY."}
            elif resp.status_code == 429:
                return [], {"status": "rate_limited", "message": "HIBP rate limit exceeded"}
            else:
                return [], {"status": "error", "message": f"HIBP returned HTTP {resp.status_code}"}
    except Exception as exc:
        return [], {"status": "error", "message": f"HIBP query error: {type(exc).__name__}: {str(exc)}"}
