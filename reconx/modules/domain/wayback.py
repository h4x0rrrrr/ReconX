"""
Historical URL mining via the Wayback Machine CDX API (free, no key).
Flags URLs matching patterns that have historically turned up backups,
configs, and leftover admin paths.
"""

import re

from reconx.utils import logger
from reconx.utils.session import get_session, safe_get

INTERESTING_PATTERN = re.compile(
    r"\.(sql|bak|env|log|zip|xls|xlsx|config|old|swp|git)(\?|$)", re.IGNORECASE
)


def get_wayback_urls(domain: str, session=None) -> list:
    logger.info("Mining historical URLs from Wayback Machine...")
    session = session or get_session(timeout=30)
    url = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=20000"
    )
    resp = safe_get(session, url)
    if resp is None or resp.status_code != 200:
        logger.warn("Wayback CDX query failed — skipping.")
        return []
    urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
    logger.ok(f"{len(urls)} historical URLs retrieved")
    return urls


def flag_interesting(urls: list) -> list:
    flagged = [u for u in urls if INTERESTING_PATTERN.search(u)]
    if flagged:
        logger.warn(f"{len(flagged)} URLs flagged as potentially sensitive "
                     "(.sql/.bak/.env/.log/.config/.git)")
    return flagged
