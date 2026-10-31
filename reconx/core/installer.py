"""Tooling readiness checker: validates Python packages, external binaries, and API configurations."""
from __future__ import annotations
import importlib.util
import shutil
from typing import Any
from reconx.core.config import load_config
from reconx.utils import logger

EXTERNAL_TOOLS = {
    "subfinder": ("go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "passive subdomain enumeration"),
    "httpx": ("go install github.com/projectdiscovery/httpx/cmd/httpx@latest", "live host probing + tech detection"),
    "amass": ("go install github.com/owasp-amass/amass/v4/...@latest", "deep passive subdomain enumeration"),
    "sherlock": ("pip install sherlock-project", "username enumeration across platforms"),
    "maigret": ("pip install maigret", "extended username profiling"),
    "trufflehog": ("curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh", "git secret scanning"),
    "gitleaks": ("go install github.com/zricethezav/gitleaks/v8@latest", "git secret scanning"),
    "exiftool": ("sudo apt install libimage-exiftool-perl", "document metadata extraction"),
}

PYTHON_PACKAGES = {
    "httpx": "HTTP client & async requests",
    "dns": "DNS queries & record parsing (dnspython)",
    "mmh3": "Favicon MurmurHash3 calculation",
    "websockets": "CertStream live stream monitoring",
    "socksio": "SOCKS5 proxy / Tor routing support",
}

def which(binary: str) -> bool:
    return shutil.which(binary) is not None

def check_python_packages() -> dict[str, bool]:
    return {pkg: importlib.util.find_spec(pkg) is not None for pkg in PYTHON_PACKAGES}

def check_external_binaries() -> dict[str, bool]:
    return {tool: which(tool) for tool in EXTERNAL_TOOLS}

def check_api_providers(cfg: dict[str, Any] | None = None) -> dict[str, bool]:
    config = cfg or load_config()
    return {
        "Brave Search": bool(config.get("brave_api_key")),
        "Bing Search": bool(config.get("bing_api_key")),
        "Google Custom Search": bool(config.get("google_api_key") and config.get("google_cse_id")),
        "Serper (Google Search)": bool(config.get("serper_api_key")),
        "GitHub API": bool(config.get("github_token")),
        "Shodan": bool(config.get("shodan_api_key")),
        "Censys": bool(config.get("censys_token") or (config.get("censys_api_id") and config.get("censys_api_secret"))),
        "HIBP (HaveIBeenPwned)": bool(config.get("hibp_api_key")),
        "DeHashed": bool(config.get("dehashed_api_key") and config.get("dehashed_email")),
    }

def print_status_report(cfg: dict[str, Any] | None = None) -> None:
    config = cfg or load_config()
    print("ReconX 0.3.3 — provider readiness")
    print("\n[Python Libraries]")
    for pkg, desc in PYTHON_PACKAGES.items():
        avail = importlib.util.find_spec(pkg) is not None
        status = "available" if avail else "missing"
        print(f"  {pkg:<14}: {status:<10} — {desc}")

    print("\n[External Binaries]")
    for tool, (hint, purpose) in EXTERNAL_TOOLS.items():
        avail = which(tool)
        status = "available" if avail else "optional / not installed"
        print(f"  {tool:<14}: {status:<24} — {purpose}")

    print("\n[API Providers]")
    apis = check_api_providers(config)
    for name, configured in apis.items():
        status = "configured" if configured else "not configured"
        print(f"  {name:<22}: {status}")

    print("\n[OPSEC & Routing]")
    proxy = config.get("proxy")
    if proxy:
        print(f"  Proxy configured       : {proxy}")
    else:
        print("  Proxy configured       : none (direct connection)")
    cache_status = "enabled (TTL: %ss)" % int(config.get("cache_ttl", 86400)) if config.get("cache_enabled") else "disabled"
    print(f"  Request cache          : {cache_status}")
    print("\nAPI secrets are read only from environment variables and never written to reports.")
