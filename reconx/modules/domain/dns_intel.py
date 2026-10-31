"""
DNS record gathering + email security posture (SPF/DMARC) — pure
Python via dnspython, no `dig` binary required.
"""

from reconx.utils import logger

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


def _query(domain: str, rtype: str) -> list:
    if not HAS_DNSPYTHON:
        return []
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


def get_dns_records(domain: str) -> dict:
    if not HAS_DNSPYTHON:
        logger.warn("dnspython not installed — install with: pip install dnspython")
        return {}
    logger.info("Querying DNS records (A/AAAA/MX/NS/SOA)...")
    records = {}
    for rtype in ("A", "AAAA", "MX", "NS", "SOA", "TXT"):
        records[rtype] = _query(domain, rtype)
    logger.ok("DNS record query complete")
    return records


def get_email_security(domain: str) -> dict:
    """Checks SPF (in root TXT) and DMARC (_dmarc. subdomain) — key
    intel for whether email spoofing is viable for a phishing pretext."""
    logger.info("Checking SPF/DMARC (email spoofability)...")
    txt_records = _query(domain, "TXT")
    spf = next((r for r in txt_records if "v=spf1" in r.lower()), "")

    dmarc_records = _query(f"_dmarc.{domain}", "TXT")
    dmarc = next((r for r in dmarc_records if "v=dmarc1" in r.lower()), "")

    result = {"spf": spf, "dmarc": dmarc}
    if not dmarc:
        logger.warn("No DMARC record found — spoofing may be viable.")
    if spf and "~all" in spf:
        logger.warn("SPF uses softfail (~all) — not a hard block.")
    return result
