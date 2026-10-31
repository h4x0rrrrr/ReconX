"""Provider configuration from environment; secrets are never written to reports."""
from __future__ import annotations
import os

def _load_dotenv_file(paths: tuple[str, ...] | None = None) -> None:
    if paths is None:
        project_root_env = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env")
        paths = (
            ".env",
            "../.env",
            project_root_env,
            os.path.expanduser("~/.env"),
            os.path.expanduser("~/.config/reconx/.env"),
        )
    for p in paths:
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if k and k not in os.environ:
                            os.environ[k] = v
            except Exception:
                pass

def load_config() -> dict:
    _load_dotenv_file()
    proxy = (
        os.getenv("RECONX_PROXY", "")
        or os.getenv("ALL_PROXY", "")
        or os.getenv("HTTPS_PROXY", "")
        or os.getenv("HTTP_PROXY", "")
    ).strip()

    return {
        "brave_api_key": os.getenv("BRAVE_API_KEY", "").strip(),
        "bing_api_key": os.getenv("BING_API_KEY", "").strip(),
        "google_api_key": os.getenv("GOOGLE_API_KEY", "").strip(),
        "google_cse_id": (os.getenv("GOOGLE_CSE_ID", "") or os.getenv("GOOGLE_CX", "")).strip(),
        "serper_api_key": os.getenv("SERPER_API_KEY", "").strip(),
        "github_token": os.getenv("GITHUB_TOKEN", "").strip(),
        "shodan_api_key": os.getenv("SHODAN_API_KEY", "").strip(),
        "censys_api_id": os.getenv("CENSYS_API_ID", "").strip(),
        "censys_api_secret": os.getenv("CENSYS_API_SECRET", "").strip(),
        "censys_token": (os.getenv("CENSYS_TOKEN", "") or os.getenv("CENSYS_API_TOKEN", "") or os.getenv("CENSYS_API_KEY", "")).strip(),
        "hibp_api_key": os.getenv("HIBP_API_KEY", "").strip(),
        "dehashed_api_key": os.getenv("DEHASHED_API_KEY", "").strip(),
        "dehashed_email": os.getenv("DEHASHED_EMAIL", "").strip(),
        "concurrency": int(os.getenv("RECONX_CONCURRENCY", "6")),
        "request_timeout": float(os.getenv("RECONX_TIMEOUT", "12")),
        "rate_seconds": float(os.getenv("RECONX_RATE_SECONDS", "0.25")),
        "user_agent": os.getenv("RECONX_USER_AGENT", "ReconX-OSINT/0.3 (+authorized security research)"),
        "proxy": proxy,
        "cache_enabled": os.getenv("RECONX_CACHE", "1").lower() not in ("0", "false", "no"),
        "cache_ttl": float(os.getenv("RECONX_CACHE_TTL", "86400")),
    }
