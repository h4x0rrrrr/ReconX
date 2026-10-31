"""Bounded, opt-in HTTP Host-header virtual-host candidate discovery.

Results are heuristic candidates, not proof that a virtual host is valid.
Uses baseline fingerprinting to detect host-specific routing.
"""
from __future__ import annotations
import asyncio
import re
from pathlib import Path
from typing import Any
import httpx
from reconx.core.plugins import RateGate
from reconx.utils.session import create_async_client

DEFAULT_LABELS = [
    "www", "api", "dev", "test", "stage", "staging", "uat", "qa", "beta",
    "admin", "portal", "app", "mail", "vpn", "remote", "internal", "intranet",
    "support", "status", "monitor", "grafana", "jenkins", "git", "gitlab",
    "legacy", "old", "backup", "blog", "shop", "cdn",
]

def _load_labels(wordlist: str | None = None) -> list[str]:
    labels = list(DEFAULT_LABELS)
    if wordlist:
        path = Path(wordlist).expanduser()
        if not path.is_file():
            raise ValueError(f"Vhost wordlist does not exist: {path}")
        labels = [line.strip().lower() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()]
    valid = []
    seen = set()
    for label in labels:
        label = label.strip().rstrip(".")
        if not label or label.startswith("#") or "." in label:
            continue
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            continue
        if label not in seen:
            seen.add(label)
            valid.append(label)
        if len(valid) >= 500:
            break
    return valid

def _fingerprint(response: httpx.Response) -> dict[str, Any]:
    body = response.text[:200_000]
    title_match = re.search(r"<title[^>]*>(.*?)</title", body, re.I | re.S)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip().lower()[:160] if title_match else ""
    return {
        "status": response.status_code,
        "title": title,
        "server": response.headers.get("server", "").lower(),
        "location": response.headers.get("location", "")[:250],
        "body_length_bucket": len(body) // 512,
    }

async def discover_vhosts(domain: str, cfg: dict[str, Any], wordlist: str | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Compare a baseline response with a bounded set of HTTP Host-header candidates."""
    labels = _load_labels(wordlist)
    timeout = min(float(cfg.get("request_timeout", 8.0)), 6.0)
    gate = RateGate(max(float(cfg.get("rate_seconds", 0.5)), 0.2))
    headers = {"User-Agent": cfg.get("user_agent", "ReconX-OSINT/0.3 (+authorized research)")}

    async with create_async_client(cfg, timeout=timeout, follow_redirects=False, headers=headers) as client:
        try:
            await gate.wait()
            baseline_response = await client.get(f"http://{domain}/", headers={**headers, "Host": domain})
            baseline = _fingerprint(baseline_response)
        except Exception as exc:
            return [], {
                "status": "error",
                "message": f"Baseline HTTP request failed: {type(exc).__name__}",
                "candidates_tested": 0,
            }

        sem = asyncio.Semaphore(4)

        async def check(label: str):
            host = f"{label}.{domain}"
            async with sem:
                try:
                    await gate.wait()
                    response = await client.get(f"http://{domain}/", headers={**headers, "Host": host})
                    fp = _fingerprint(response)
                    if fp == baseline:
                        return None
                    return {
                        "host": host,
                        "url": f"http://{host}/",
                        "status": response.status_code,
                        "title": fp["title"],
                        "server": fp["server"],
                        "location": fp["location"],
                        "baseline_status": baseline["status"],
                        "baseline_title": baseline["title"],
                        "confidence": "low",
                        "status_label": "candidate",
                        "source": "http_host_header_comparison",
                        "evidence": "HTTP response fingerprint differs from root-domain baseline; manually verify",
                    }
                except Exception:
                    return None

        results = await asyncio.gather(*(check(label) for label in labels))

    found = [x for x in results if x]
    return found, {
        "status": "completed",
        "message": "Heuristic HTTP Host-header comparison; candidates require manual verification",
        "candidates_tested": len(labels),
        "baseline_status": baseline["status"],
    }
