"""
Probes a list of subdomains to find which are actually alive, using
async requests for speed (hundreds of hosts in seconds instead of
minutes). Falls back to httpx binary if installed for richer tech
fingerprinting, otherwise does basic title/server-header detection
natively — never returns empty just because httpx is missing.
"""

import asyncio
import re
import shutil

from reconx.core import runner
from reconx.utils import logger

try:
    import httpx as httpx_lib  # python httpx client library (not the Go binary)
    HAS_HTTPX_LIB = True
except ImportError:
    HAS_HTTPX_LIB = False

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(html: str) -> str:
    match = TITLE_RE.search(html or "")
    return match.group(1).strip()[:120] if match else ""


async def _probe_one(client, host: str) -> dict:
    for scheme in ("https://", "http://"):
        url = f"{scheme}{host}"
        try:
            resp = await client.get(url, timeout=6, follow_redirects=True)
            return {
                "host": host,
                "url": str(resp.url),
                "status": resp.status_code,
                "title": _extract_title(resp.text),
                "tech": resp.headers.get("Server", ""),
            }
        except Exception:
            continue
    return {"host": host, "url": None, "status": None, "title": "", "tech": ""}


async def _probe_all_native(hosts: list) -> list:
    if not HAS_HTTPX_LIB:
        return []
    results = []
    async with httpx_lib.AsyncClient(verify=True) as client:
        tasks = [_probe_one(client, h) for h in hosts]
        for coro in asyncio.as_completed(tasks):
            results.append(await coro)
    return results


def probe_with_go_httpx(hosts: list) -> list:
    """If the Go `httpx` binary is installed, prefer it — much richer tech detection."""
    if not shutil.which("httpx"):
        return []
    stdin_data = "\n".join(hosts)
    import subprocess
    try:
        proc = subprocess.run(
            ["httpx", "-title", "-tech-detect", "-status-code", "-silent", "-json"],
            input=stdin_data, capture_output=True, text=True, timeout=180,
        )
        import json
        results = []
        for line in proc.stdout.splitlines():
            try:
                obj = json.loads(line)
                results.append({
                    "host": obj.get("input"),
                    "url": obj.get("url"),
                    "status": obj.get("status_code"),
                    "title": obj.get("title", ""),
                    "tech": ",".join(obj.get("tech", [])),
                })
            except Exception:
                continue
        return results
    except Exception:
        logger.warn("Go httpx binary failed — falling back to native async probe.")
        return []


def probe_live_hosts(hosts: list) -> list:
    logger.info(f"Probing {len(hosts)} hosts for liveness + tech stack...")

    go_results = probe_with_go_httpx(hosts)
    if go_results:
        live = [r for r in go_results if r.get("status")]
        logger.ok(f"{len(live)} live hosts (via Go httpx binary)")
        return live

    if not HAS_HTTPX_LIB:
        logger.warn("Neither Go httpx nor python 'httpx' package available — "
                     "install with: pip install httpx")
        return []

    results = asyncio.run(_probe_all_native(hosts))
    live = [r for r in results if r.get("status")]
    logger.ok(f"{len(live)} live hosts (via native async probe)")
    return live
