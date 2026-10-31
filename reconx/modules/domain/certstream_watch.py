"""Real-time Certificate Transparency stream monitor via CertStream.

Listens to wss://certstream.calidog.io/ and streams newly issued SSL/TLS certificates
matching the target domain in real time.
"""
from __future__ import annotations
import asyncio
import json
import time
from typing import Any, Callable
import websockets
from reconx.utils.logger import info, ok, warn

CERTSTREAM_URL = "wss://certstream.calidog.io/"

def _matches_target(cert_domain: str, target: str) -> bool:
    c = cert_domain.lower().lstrip("*.")
    t = target.lower().lstrip("*.")
    return c == t or c.endswith("." + t)

async def watch_certstream(
    target: str,
    timeout: float | None = None,
    callback: Callable[[dict[str, Any]], None] | None = None,
    max_matches: int | None = None,
) -> list[dict[str, Any]]:
    """Stream Certificate Transparency log updates for target domain.
    
    Runs until timeout seconds pass, max_matches is reached, or cancelled.
    """
    clean_target = target.strip().lower().lstrip(".").rstrip(".")
    info(f"Connecting to CertStream (wss://certstream.calidog.io/)...")
    info(f"Monitoring real-time certificate issuances for *.{clean_target}")

    matches: list[dict[str, Any]] = []
    start_time = time.time()

    while True:
        if timeout and (time.time() - start_time) >= timeout:
            info(f"CertStream watch timeout ({timeout}s) reached.")
            break
        if max_matches and len(matches) >= max_matches:
            break

        try:
            async with websockets.connect(CERTSTREAM_URL, ping_interval=20, ping_timeout=20) as ws:
                ok("CertStream connection established. Awaiting matching certificates...")
                while True:
                    if timeout and (time.time() - start_time) >= timeout:
                        break
                    if max_matches and len(matches) >= max_matches:
                        break

                    try:
                        message = await asyncio.wait_for(ws.recv(), timeout=5.0)
                    except asyncio.TimeoutError:
                        continue

                    data = json.loads(message)
                    if data.get("message_type") != "certificate_update":
                        continue

                    leaf = data.get("data", {}).get("leaf_cert", {})
                    all_domains = leaf.get("all_domains", [])
                    matched_domains = [d for d in all_domains if _matches_target(d, clean_target)]

                    if matched_domains:
                        issuer = leaf.get("issuer", {}).get("O") or leaf.get("issuer", {}).get("CN") or "Unknown Issuer"
                        record = {
                            "timestamp": data.get("data", {}).get("seen", time.time()),
                            "target": clean_target,
                            "matched_domains": matched_domains,
                            "all_domains": all_domains,
                            "issuer": issuer,
                            "fingerprint": leaf.get("fingerprint", ""),
                            "source": "certstream",
                        }
                        matches.append(record)
                        if callback:
                            callback(record)
                        else:
                            ok(f"[NEW CERT] Domains: {', '.join(matched_domains)} | Issuer: {issuer}")

        except (websockets.ConnectionClosed, OSError, Exception) as exc:
            warn(f"CertStream connection issue ({type(exc).__name__}). Reconnecting in 3 seconds...")
            await asyncio.sleep(3.0)

    return matches
