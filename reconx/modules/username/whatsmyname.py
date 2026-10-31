"""WhatsMyName username candidate provider.

Generates candidate URLs from curated platform definitions.
All candidates are strictly validated through ReconX's independent verifier.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

def get_wmn_candidates(username: str) -> list[dict[str, Any]]:
    """Generate candidate profile objects for the given username using WhatsMyName definitions."""
    config_path = Path(__file__).resolve().parents[2] / "config" / "wmn_sites.json"
    if not config_path.is_file():
        return []

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    candidates: list[dict[str, Any]] = []
    seen = set()
    for site in data:
        name = site.get("name", "Unknown")
        uri_pattern = site.get("uri_check", "")
        if not uri_pattern or "{account}" not in uri_pattern:
            continue
        url = uri_pattern.replace("{account}", username)
        if url.lower() not in seen:
            seen.add(url.lower())
            candidates.append({
                "platform": name,
                "url": url,
                "source": "WhatsMyName",
            })
    return candidates
