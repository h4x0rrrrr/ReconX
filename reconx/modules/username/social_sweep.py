"""Conservative username enumeration: only independently verified profiles are returned as matches."""
from __future__ import annotations
import asyncio
import json
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse
import httpx
from reconx.core.runner import run
from reconx.utils.logger import info, ok, warn
from reconx.core.config import load_config
from reconx.core.plugins import deduplicate, RateGate
from reconx.utils.session import create_async_client
from reconx.modules.username.whatsmyname import get_wmn_candidates
from reconx.modules.breach.hibp import check_breaches

NOT_FOUND = re.compile(
    r"user (?:does not exist|not found|suspended|deleted)|"
    r"profile (?:not found|doesn't exist|does not exist|unavailable)|"
    r"page (?:not found|doesn't exist|does not exist|could not be found|unavailable)|"
    r"sorry, nobody on reddit goes by that name|"
    r"the specified (?:profile|user|channel) could not be found|"
    r"account (?:may have been removed|has been suspended|does not exist|doesn't exist)|"
    r"this page isn't available|this account doesn't exist|no such user|member not found|"
    r"the page you requested (?:was not found|could not be found)|"
    r"404 not found|<title>404|404: not found|error 404|http 404|status 404|"
    r"oops! that page can’t be found|oops! that page can't be found|"
    r"the profile you are trying to view does not exist",
    re.I,
)
GENERIC_HOSTS = {
    "discord.com", "www.discord.com", "www.instagram.com", "instagram.com",
    "www.youtube.com", "youtube.com", "github.com", "gitlab.com",
}

def _parse_sherlock(output: str, username: str) -> list[dict]:
    results = []
    seen = set()
    for line in output.splitlines():
        m = re.match(r"^\s*\[\+\]\s*(.+?):\s*(https?://\S+)", line)
        if not m:
            continue
        platform, url = m.group(1).strip(), m.group(2).rstrip(".,;)")
        if (platform.casefold(), url.casefold()) not in seen:
            seen.add((platform.casefold(), url.casefold()))
            results.append({"platform": platform, "url": url, "source": "Sherlock"})
    return results

def _candidate_urls(username: str) -> list[dict]:
    templates = []
    config_path = Path(__file__).resolve().parents[2] / "config" / "sites.json"
    try:
        for site in json.loads(config_path.read_text(encoding="utf-8")):
            if site.get("name") and site.get("url_format"):
                templates.append((site["name"], site["url_format"].format(username=username)))
    except (OSError, ValueError, KeyError):
        pass
    templates.extend([
        ("GitHub", f"https://github.com/{username}"),
        ("GitLab", f"https://gitlab.com/{username}"),
        ("Reddit", f"https://www.reddit.com/user/{username}"),
        ("Mastodon (mastodon.social)", f"https://mastodon.social/@{username}"),
        ("TryHackMe", f"https://tryhackme.com/p/{username}"),
        ("YouTube", f"https://www.youtube.com/@{username}"),
        ("Twitch", f"https://www.twitch.tv/{username}"),
        ("HackerOne", f"https://hackerone.com/{username}"),
        ("Keybase", f"https://keybase.io/{username}"),
    ])
    seen = set()
    result = []
    for name, url in templates:
        if url not in seen:
            seen.add(url)
            result.append({"platform": name, "url": url, "source": "native"})
    return result

async def _verify_one(client: httpx.AsyncClient, candidate: dict, username: str, sem: asyncio.Semaphore, gates=None, rate_seconds: float = 0.25):
    url = candidate["url"]
    parsed = urlparse(url)
    platform = candidate.get("platform", "unknown")

    path_and_query = (parsed.path + "?" + parsed.query).casefold()
    if parsed.netloc.casefold() in GENERIC_HOSTS and username.casefold() not in path_and_query:
        return None, "generic_homepage"
    if username.casefold() not in path_and_query:
        return None, "url_not_username_specific"

    async with sem:
        try:
            if gates is not None:
                await gates.setdefault(parsed.netloc.casefold(), RateGate(rate_seconds)).wait()
            r = await client.get(url, follow_redirects=True, timeout=10.0)
        except Exception as exc:
            return None, "request_error:" + type(exc).__name__

    final = urlparse(str(r.url))
    # 1. Strict HTTP status check: reject 404, 410, and any non-200 code
    if r.status_code in (404, 410):
        return None, "not_found_http_404"
    if r.status_code in (401, 403, 429) or r.status_code >= 500:
        return None, "blocked_or_unavailable"
    if r.status_code != 200:
        return None, f"unexpected_http_{r.status_code}"

    # 2. Redirect checks: reject redirects to error, login, or generic homepages
    final_path = final.path.casefold()
    if any(err_path in final_path for err_path in ("/404", "/notfound", "/not-found", "/error", "/users/sign_in", "/login", "/register", "/signup")):
        return None, "redirected_to_error_or_login"
    if final.netloc.casefold() in GENERIC_HOSTS and username.casefold() not in (final.path + "?" + final.query).casefold():
        return None, "redirected_to_homepage"

    body = (r.text or "")[:800_000]

    # 3. Soft-404 title check: reject pages with 404 / not found in the HTML title
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if title_match:
        title_text = title_match.group(1).casefold()
        if any(err in title_text for err in ("404", "not found", "page not found", "user not found", "doesn't exist", "does not exist")):
            return None, "soft_404_title"

    # 4. Soft-404 body content check: reject pages matching missing profile signatures
    if NOT_FOUND.search(body):
        return None, "not_found_body_marker"

    # 5. Cross-check username presence in both canonical URL and page content
    body_l = body.casefold()
    user_l = username.casefold()
    canonical_match = user_l in str(r.url).casefold()
    content_match = bool(re.search(r"(?<![a-z0-9_])" + re.escape(user_l) + r"(?![a-z0-9_])", body_l))
    if not (canonical_match and content_match):
        return None, "username_not_confirmed_in_page"

    return {
        "platform": platform,
        "url": str(r.url),
        "found": True,
        "status": "verified",
        "source": candidate.get("source", "unknown"),
        "http_status": r.status_code,
        "evidence": "HTTP 200 confirmed; username cross-checked in URL and page content; 404/soft-404 eliminated",
    }, "verified"

async def _verify(candidates: list[dict], username: str, config: dict):
    limits = httpx.Limits(max_connections=12, max_keepalive_connections=6)
    sem = asyncio.Semaphore(max(1, min(12, int(config.get("concurrency", 6)))))
    gates = {}
    async with create_async_client(config, limits=limits) as client:
        checked = await asyncio.gather(*[_verify_one(client, c, username, sem, gates, config.get("rate_seconds", 0.25)) for c in candidates[:600]])
    verified = [item for item, reason in checked if item]
    counts = {}
    for item, reason in checked:
        counts[reason] = counts.get(reason, 0) + 1
    return deduplicate(verified), counts

def enumerate_username(username: str) -> dict:
    username = username.strip().lstrip("@").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{2,64}", username):
        raise ValueError("Username must be 2–64 characters and contain only letters, numbers, dot, underscore or hyphen.")
    info(f"=== USERNAME RECON: {username} ===")
    config = load_config()

    candidates: list[dict] = []
    engines = []

    # 1. Sherlock if installed
    if shutil.which("sherlock"):
        raw = run(["sherlock", username, "--print-found", "--timeout", "10"], timeout=150) or ""
        sherlock_candidates = _parse_sherlock(raw, username)
        if sherlock_candidates:
            candidates.extend(sherlock_candidates)
            engines.append("sherlock")

    # 2. WhatsMyName candidate provider
    wmn_candidates = get_wmn_candidates(username)
    if wmn_candidates:
        candidates.extend(wmn_candidates)
        engines.append("whatsmyname")

    # 3. Native sites
    native_candidates = _candidate_urls(username)
    candidates.extend(native_candidates)
    engines.append("native")

    # Merge candidates by URL
    seen_urls = set()
    deduped_candidates = []
    for cand in candidates:
        u_norm = cand["url"].lower().rstrip("/")
        if u_norm not in seen_urls:
            seen_urls.add(u_norm)
            deduped_candidates.append(cand)

    info(f"Checking {len(deduped_candidates)} candidates across {', '.join(engines)}...")
    verified, counts = asyncio.run(_verify(deduped_candidates, username, config))
    ok(f"Verified profiles: {len(verified)} (unverified or ambiguous candidates are omitted)")

    # 4. Breach intelligence check (HIBP)
    breaches, breach_status = asyncio.run(check_breaches(username, config))
    if breaches:
        ok(f"Breach records found: {len(breaches)} breach(es) associated with '{username}'")

    engine_str = "+".join(engines) + "+verifier"

    return {
        "username": username,
        "engine": engine_str,
        "results": verified,
        "verified_count": len(verified),
        "checked_candidate_count": len(deduped_candidates),
        "verification_summary": counts,
        "breaches": breaches,
        "breach_status": breach_status,
        "note": "Only profiles independently verified by conservative HTTP/content checks appear in results. Blocked, ambiguous and unconfirmed candidates are omitted, so zero results does not prove account absence.",
    }
