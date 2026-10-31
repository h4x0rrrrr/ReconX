"""HTTP session utilities supporting proxy routing, OPSEC User-Agents, and retry with exponential backoff."""
from __future__ import annotations
import asyncio
import os
from typing import Any, Mapping
import httpx
from reconx.core.config import load_config
from reconx.utils import logger

DEFAULT_USER_AGENT = "ReconX-OSINT/0.3 (+authorized security research)"

def get_proxy(cfg: Mapping[str, Any] | None = None) -> str | None:
    if cfg and cfg.get("proxy"):
        return str(cfg["proxy"]).strip()
    env_proxy = (
        os.getenv("RECONX_PROXY", "")
        or os.getenv("ALL_PROXY", "")
        or os.getenv("HTTPS_PROXY", "")
        or os.getenv("HTTP_PROXY", "")
    ).strip()
    return env_proxy or None

def create_async_client(
    cfg: Mapping[str, Any] | None = None,
    proxy: str | None = None,
    timeout: float | None = None,
    follow_redirects: bool = True,
    limits: httpx.Limits | None = None,
    headers: Mapping[str, str] | None = None,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """Create an httpx.AsyncClient with proxy support, User-Agent, and sane defaults."""
    resolved_cfg = cfg or load_config()
    target_proxy = proxy or get_proxy(resolved_cfg)

    client_headers = {
        "User-Agent": resolved_cfg.get("user_agent", DEFAULT_USER_AGENT),
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if headers:
        client_headers.update(headers)

    req_timeout = timeout if timeout is not None else float(resolved_cfg.get("request_timeout", 12.0))

    client_kwargs: dict[str, Any] = {
        "verify": True,
        "follow_redirects": follow_redirects,
        "timeout": req_timeout,
        "headers": client_headers,
    }
    if limits:
        client_kwargs["limits"] = limits
    if target_proxy:
        client_kwargs["proxy"] = target_proxy

    client_kwargs.update(kwargs)
    return httpx.AsyncClient(**client_kwargs)

async def async_get_with_retry(
    client: httpx.AsyncClient,
    url: str,
    retries: int = 3,
    backoff_factor: float = 1.5,
    retry_statuses: tuple[int, ...] = (429, 502, 503, 504),
    **kwargs: Any,
) -> httpx.Response:
    """Perform an async GET request with exponential backoff on 429/5xx status codes."""
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            resp = await client.get(url, **kwargs)
            if resp.status_code in retry_statuses and attempt < retries:
                # Respect Retry-After if present
                retry_after = resp.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    delay = min(float(retry_after), 15.0)
                else:
                    delay = backoff_factor * (2 ** attempt)
                await asyncio.sleep(delay)
                continue
            return resp
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            last_exc = exc
            if attempt < retries:
                delay = backoff_factor * (2 ** attempt)
                await asyncio.sleep(delay)
                continue
            raise
    if last_exc:
        raise last_exc
    raise RuntimeError(f"Request failed after {retries} retries: {url}")
