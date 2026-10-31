"""
Subdomain enumeration — combines whichever external tools are
installed (subfinder, amass, assetfinder) with a direct, dependency-free
call to the crt.sh certificate-transparency API. The crt.sh call always
runs, even with zero external tools installed, so the tool never
returns completely empty-handed.
"""

from reconx.core import runner
from reconx.utils import logger
from reconx.utils.session import get_session, safe_get


def from_crtsh(domain: str, session=None) -> set:
    """Free, no-key cert-transparency lookup. Always available."""
    session = session or get_session()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    resp = safe_get(session, url)
    found = set()
    if resp is not None and resp.status_code == 200:
        try:
            for entry in resp.json():
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lstrip("*.")
                    if line.endswith(domain):
                        found.add(line.lower())
        except (ValueError, KeyError):
            logger.warn("crt.sh returned unparseable data — skipping.")
    else:
        logger.warn("crt.sh lookup failed or rate-limited.")
    return found


def from_subfinder(domain: str) -> set:
    out = runner.run(["subfinder", "-d", domain, "-all", "-silent"], timeout=180)
    return {line.strip().lower() for line in out.splitlines() if line.strip()}


def from_amass(domain: str) -> set:
    out = runner.run(["amass", "enum", "-passive", "-d", domain, "-silent"], timeout=180)
    return {line.strip().lower() for line in out.splitlines() if line.strip()}


def from_assetfinder(domain: str) -> set:
    out = runner.run(["assetfinder", "--subs-only", domain], timeout=120)
    return {line.strip().lower() for line in out.splitlines() if line.strip()}


def enumerate_subdomains(domain: str) -> list:
    logger.info("Enumerating subdomains (crt.sh + any installed tools)...")
    results = set()
    results |= from_crtsh(domain)
    results |= from_subfinder(domain)
    results |= from_amass(domain)
    results |= from_assetfinder(domain)
    results.add(domain.lower())  # always include the root
    logger.ok(f"{len(results)} unique subdomains found")
    return sorted(results)
