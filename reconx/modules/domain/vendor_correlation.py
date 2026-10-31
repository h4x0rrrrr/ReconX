"""Supply chain and vendor correlation module via web tracker and analytics IDs.

Extracts unique provider IDs (Google Analytics, GTM, AdSense, Meta Pixel, Hotjar, Sentry)
from HTML and JavaScript bodies to discover shared infrastructure and undisclosed subsidiaries.
"""
from __future__ import annotations
import re
from typing import Any

TRACKER_PATTERNS = {
    "google_analytics_4": (re.compile(r"\b(G-[A-Z0-9]{8,12})\b"), "Google Analytics 4"),
    "google_universal_analytics": (re.compile(r"\b(UA-[0-9]{4,10}-[0-9]{1,4})\b"), "Google Universal Analytics"),
    "google_tag_manager": (re.compile(r"\b(GTM-[A-Z0-9]{4,10})\b"), "Google Tag Manager"),
    "google_adsense": (re.compile(r"\b(?:ca-)?(pub-[0-9]{10,20})\b"), "Google AdSense"),
    "hotjar": (re.compile(r"hjid\s*[:=]\s*['\"]?([0-9]{5,10})['\"]?"), "Hotjar Site ID"),
    "meta_pixel": (re.compile(r"fbq\('init',\s*['\"]([0-9]{10,20})['\"]"), "Meta Pixel ID"),
    "cloudflare_analytics": (re.compile(r"beacon\.min\.js.*['\"]token['\"]\s*:\s*['\"]([a-f0-9]{32})['\"]"), "Cloudflare Web Analytics"),
    "intercom": (re.compile(r"app_id['\"]\s*:\s*['\"]([a-z0-9]{8,12})['\"]"), "Intercom App ID"),
    "sentry_public": (re.compile(r"https://([a-f0-9]{24,36})@o?[0-9]*\.ingest\.sentry\.io"), "Sentry Public Key"),
}

def extract_vendor_trackers(
    pages: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], dict[str, list[str]], dict[str, Any]]:
    """Extract tracking codes from a list of page objects ({'url': ..., 'body': ...}).
    
    Returns (findings_list, grouped_by_tracker_id, source_status).
    """
    findings: list[dict[str, Any]] = []
    seen = set()
    grouped: dict[str, list[str]] = {}

    for page in pages:
        url = page.get("url", "")
        body = page.get("body", "")
        if not body:
            continue

        for key, (pattern, label) in TRACKER_PATTERNS.items():
            for match in pattern.finditer(body):
                tracker_id = match.group(1).strip()
                if not tracker_id:
                    continue
                pair = (label, tracker_id, url)
                if pair not in seen:
                    seen.add(pair)
                    findings.append({
                        "vendor": label,
                        "tracker_id": tracker_id,
                        "url": url,
                        "source": "vendor_correlation",
                    })
                    grouped.setdefault(f"{label} ({tracker_id})", []).append(url)

    status = {
        "status": "ok" if findings else "clean",
        "message": f"Identified {len(findings)} vendor tracking indicator(s) across {len(pages)} inspected response(s)",
        "unique_trackers": len(grouped),
    }

    return findings, grouped, status
