"""
Computes the mmh3 hash of a target's favicon the same way Shodan
does, so you can pivot to find every other server on the internet
using the same favicon (shared CMS, shared panel, sister infra that
never showed up in subdomain enum).
"""

import base64

from reconx.utils import logger
from reconx.utils.session import get_session, safe_get

try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False


def get_favicon_hash(live_hosts: list, session=None) -> dict:
    if not HAS_MMH3:
        logger.warn("mmh3 not installed — install with: pip install mmh3")
        return {}
    if not live_hosts:
        return {}

    session = session or get_session()
    target = live_hosts[0]
    base_url = (target.get("url") or f"https://{target.get('host')}").rstrip("/")
    favicon_url = f"{base_url}/favicon.ico"

    resp = safe_get(session, favicon_url)
    if resp is None or resp.status_code != 200 or not resp.content:
        logger.warn("Could not fetch favicon.ico — skipping hash pivot.")
        return {}

    b64_content = base64.encodebytes(resp.content)
    favicon_hash = mmh3.hash(b64_content)

    logger.ok(f"Favicon hash: {favicon_hash}")
    logger.info(f"  Shodan dork:  http.favicon.hash:{favicon_hash}")
    logger.info(f"  Censys dork:  services.http.response.favicons.md5_hash:<md5-equivalent>")

    return {
        "source": favicon_url,
        "mmh3_hash": favicon_hash,
        "shodan_dork": f"http.favicon.hash:{favicon_hash}",
        "zoomeye_dork": f"iconhash:\"{favicon_hash}\"",
    }
